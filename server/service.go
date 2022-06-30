// Package server contains the webserver serving the proposer and block-builder APIs
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	errInvalidSlot      = errors.New("invalid slot")
	errInvalidHash      = errors.New("invalid hash")
	errInvalidPubkey    = errors.New("invalid pubkey")
	errInvalidSignature = errors.New("invalid signature")

	// Builder-specs APIs
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"

	// Block builder APIs
	pathGetValidatorsForEpoch = "/relay/v1/builder/validators"
	pathSubmitNewBlock        = "/relay/v1/builder/blocks"
)

var nilResponse = struct{}{}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RelayService TODO
type RelayService struct {
	log                  *logrus.Entry
	listenAddr           string
	validatorService     ValidatorService
	builders             []*common.BuilderEntry
	srv                  *http.Server
	datastore            Datastore
	builderSigningDomain types.Domain
}

// NewRelayService creates a new service. if builders is nil, allow any builder
func NewRelayService(listenAddr string, validatorService ValidatorService, log *logrus.Entry, genesisForkVersionHex string, datastore Datastore) (*RelayService, error) {
	builderSigningDomain, err := common.ComputeDomain(types.DomainTypeAppBuilder, genesisForkVersionHex, types.Root{}.String())
	if err != nil {
		return nil, err
	}

	return &RelayService{
		log:                  log.WithField("module", "relay"),
		listenAddr:           listenAddr,
		validatorService:     validatorService,
		builders:             nil,
		datastore:            datastore,
		builderSigningDomain: builderSigningDomain,
	}, nil
}

func (m *RelayService) respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := httpErrorResp{code, message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		m.log.WithField("response", resp).WithError(err).Error("Couldn't write error response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (m *RelayService) respondOK(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		m.log.WithField("response", response).WithError(err).Error("Couldn't write OK response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (m *RelayService) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", m.handleRoot)
	r.HandleFunc(pathStatus, m.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathRegisterValidator, m.handleRegisterValidator).Methods(http.MethodPost)
	r.HandleFunc(pathGetHeader, m.handleGetHeader).Methods(http.MethodGet)
	r.HandleFunc(pathGetPayload, m.handleGetPayload).Methods(http.MethodPost)

	r.HandleFunc(pathGetValidatorsForEpoch, m.handleGetValidatorsForEpoch).Methods(http.MethodGet)
	r.HandleFunc(pathSubmitNewBlock, m.handleSubmitNewBlock).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(m.log, r)
	return loggedRouter
}

// StartServer starts the HTTP server for this instance
func (m *RelayService) StartServer() error {
	if m.srv != nil {
		return common.ErrServerAlreadyRunning
	}

	if m.validatorService == nil {
		err := errors.New("no validator service")
		m.log.WithError(err).Error("cannot run without validator service")
		return err
	}

	// start regular
	go m.startBeaconNodeValidatorUpdates()

	m.srv = &http.Server{
		Addr:    m.listenAddr,
		Handler: m.getRouter(),
	}

	err := m.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (m *RelayService) startBeaconNodeValidatorUpdates() {
	for {
		// Wait for one epoch (at the beginning, because initially the validators have already been queried)
		time.Sleep(common.DurationPerEpoch)

		// Load validators from BN
		m.log.Info("Querying validators from beacon node... (this may")
		err := m.validatorService.FetchValidators()
		if err != nil {
			m.log.WithError(err).Fatal("failed to fetch validators from beacon node")
		}
		m.log.Infof("Got %d validators from BN", m.validatorService.NumValidators())
	}
}

func (m *RelayService) handleRoot(w http.ResponseWriter, req *http.Request) {
	m.respondOK(w, nilResponse)
}

// ---------------
//  Proposer APIs
// ---------------
func (m *RelayService) handleStatus(w http.ResponseWriter, req *http.Request) {
	m.respondOK(w, nilResponse)
}

func (m *RelayService) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "registerValidator")
	log.Info("registerValidator")

	payload := []types.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		m.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// TODO: maybe parallelize this
	for _, registration := range payload {
		if len(registration.Message.Pubkey) != 48 {
			continue
		}

		if len(registration.Signature) != 96 {
			continue
		}

		// Check if actually a real validator
		if !m.validatorService.IsValidator(NewPubkeyHex(registration.Message.Pubkey.String())) {
			log.WithField("registration", registration).Warn("not a known validator")
			continue
		}

		// Verify the signature
		ok, err := types.VerifySignature(registration.Message, m.builderSigningDomain, registration.Message.Pubkey[:], registration.Signature[:])
		if err != nil {
			log.WithError(err).WithField("registration", registration).Warn("error verifying registerValidator signature")
			continue
		}
		if !ok {
			log.WithError(err).WithField("registration", registration).Warn("failed to verify registerValidator signature")
			continue
		}

		// Save if first time or if newer timestamp than last registration
		lastEntry, err := m.datastore.GetValidatorRegistration(registration.Message.Pubkey)
		if err != nil {
			log.WithError(err).WithField("registration", registration).Error("error getting validator registration")
			continue
		}
		
		if lastEntry == nil || lastEntry.Message.Timestamp > registration.Message.Timestamp {
			m.datastore.SaveValidatorRegistration(registration)
		}
	}

	m.respondOK(w, nilResponse)
}

func (m *RelayService) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slot := vars["slot"]
	parentHashHex := vars["parent_hash"]
	pubkey := vars["pubkey"]
	log := m.log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slot,
		"parentHash": parentHashHex,
		"pubkey":     pubkey,
	})
	log.Info("getHeader")

	if _, err := strconv.ParseUint(slot, 10, 64); err != nil {
		m.respondError(w, http.StatusBadRequest, errInvalidSlot.Error())
		return
	}

	if len(pubkey) != 98 {
		m.respondError(w, http.StatusBadRequest, errInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		m.respondError(w, http.StatusBadRequest, errInvalidHash.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
	if err := json.NewEncoder(w).Encode(nilResponse); err != nil {
		m.log.WithError(err).Error("Couldn't write getHeader response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (m *RelayService) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getPayload")
	log.Info("getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		m.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(payload.Signature) != 96 {
		m.respondError(w, http.StatusBadRequest, errInvalidSignature.Error())
		return
	}

	result := new(types.GetPayloadResponse)
	m.respondOK(w, result)
}

// --------------------
//  Block Builder APIs
// --------------------
func (m *RelayService) handleGetValidatorsForEpoch(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getValidatorsForEpoch")
	log.Info("request")
	m.respondOK(w, nilResponse)
}

func (m *RelayService) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "submitNewBlock")
	log.Info("request")
	m.respondOK(w, nilResponse)
}
