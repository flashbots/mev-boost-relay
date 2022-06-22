// Package server contains the webserver serving the proposer and block-builder APIs
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

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

// RelayService TODO
type RelayService struct {
	log              *logrus.Entry
	listenAddr       string
	validatorService ValidatorService
	builders         []*common.BuilderEntry
	srv              *http.Server
}

// NewRelayService creates a new service. if builders is nil, allow any builder
func NewRelayService(listenAddr string, validatorService ValidatorService, log *logrus.Entry) (*RelayService, error) {
	return &RelayService{
		log:              log.WithField("module", "relay"),
		listenAddr:       listenAddr,
		validatorService: validatorService,
		builders:         nil,
	}, nil
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

// StartHTTPServer starts the HTTP server for this boost service instance
func (m *RelayService) StartHTTPServer() error {
	if m.srv != nil {
		return common.ErrServerAlreadyRunning
	}

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

func (m *RelayService) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

// ---------------
//  Proposer APIs
// ---------------
func (m *RelayService) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (m *RelayService) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "registerValidator")
	log.Info("registerValidator")
	// s.validatorService.IsValidator(...)
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
		http.Error(w, errInvalidSlot.Error(), http.StatusBadRequest)
		return
	}

	if len(pubkey) != 98 {
		http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
		return
	}

	if len(parentHashHex) != 66 {
		http.Error(w, errInvalidHash.Error(), http.StatusBadRequest)
		return
	}

	result := new(types.GetHeaderResponse)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (m *RelayService) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getPayload")
	log.Info("getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Signature) != 96 {
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	result := new(types.GetPayloadResponse)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// --------------------
//  Block Builder APIs
// --------------------
func (m *RelayService) handleGetValidatorsForEpoch(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getValidatorsForEpoch")
	log.Info("request")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (m *RelayService) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "submitNewBlock")
	log.Info("request")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}
