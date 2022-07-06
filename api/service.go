// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	// Proposer API (builder-specs)
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	// pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	// pathGetPayload        = "/eth/v1/builder/blinded_blocks"

	// Block builder API
	pathGetValidatorsForEpoch = "/relay/v1/builder/validators"
	// pathSubmitNewBlock        = "/relay/v1/builder/blocks"
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr   string
	BeaconClient beaconclient.BeaconNodeClient
	Datastore    datastore.ProposerDatastore

	// // Whitelisted Builders
	// builders []*common.BuilderEntry

	// GenesisForkVersion for validating signatures
	GenesisForkVersionHex string

	// Which APIs and services to spin up
	ProposerAPI bool
	BuilderAPI  bool
}

// RelayAPI represents a single Relay instance
type RelayAPI struct {
	log *logrus.Entry

	opts RelayAPIOpts
	srv  *http.Server

	datastore    datastore.ProposerDatastore
	beaconClient beaconclient.BeaconNodeClient

	builderSigningDomain types.Domain
	currentSlot          uint64
}

// NewRelayAPI creates a new service. if builders is nil, allow any builder
func NewRelayAPI(opts RelayAPIOpts) (*RelayAPI, error) {
	var err error
	if opts.Log == nil {
		return nil, errors.New("log parameter is nil")
	}

	if opts.BeaconClient == nil {
		return nil, errors.New("beacon-client is nil")
	}

	if opts.Datastore == nil {
		return nil, errors.New("proposer datastore is nil")
	}

	rs := RelayAPI{
		opts:         opts,
		datastore:    opts.Datastore,
		beaconClient: opts.BeaconClient,
	}

	rs.log = opts.Log.WithField("module", "relay")
	rs.builderSigningDomain, err = common.ComputerBuilderSigningDomain(opts.GenesisForkVersionHex)
	if err != nil {
		return nil, err
	}

	return &rs, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)

	if api.opts.ProposerAPI {
		r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
		r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
		// r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
		// r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)
	}

	if api.opts.BuilderAPI {
		r.HandleFunc(pathGetValidatorsForEpoch, api.handleGetValidatorsForEpoch).Methods(http.MethodPost)
		// r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodGet)
	}

	// r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(api.log, r)
	return loggedRouter
}

// StartServer starts the HTTP server for this instance
func (api *RelayAPI) StartServer() (err error) {
	if api.srv != nil {
		return common.ErrServerAlreadyRunning
	}

	// Check beacon-node sync status, set current slot and start update loop
	syncStatus, err := api.beaconClient.SyncStatus()
	if err != nil {
		return err
	}
	if syncStatus.IsSyncing {
		return errors.New("beacon node is syncing")
	}
	api.currentSlot = syncStatus.HeadSlot
	api.log.WithField("slot", api.currentSlot).Info("updated current slot")
	go api.startSlotUpdates()

	// Update list of known validators, and start refresh loop
	cnt, err := api.datastore.RefreshKnownValidators()
	if err != nil {
		return err
	} else if cnt == 0 {
		api.log.WithField("cnt", cnt).Warn("updated known validators, but have not received any")
	} else {
		api.log.WithField("cnt", cnt).Info("updated known validators")
	}
	go api.startKnownValidatorUpdates()

	api.srv = &http.Server{
		Addr:    api.opts.ListenAddr,
		Handler: api.getRouter(),
	}

	err = api.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (api *RelayAPI) startSlotUpdates() {
	c := make(chan uint64)
	go api.beaconClient.SubscribeToHeadEvents(c)
	for {
		api.currentSlot = <-c
		api.log.WithField("slot", api.currentSlot).Info("updated current slot")
	}
}

func (api *RelayAPI) startKnownValidatorUpdates() {
	for {
		// Wait for one epoch (at the beginning, because initially the validators have already been queried)
		time.Sleep(common.DurationPerEpoch)

		// Refresh known validators
		cnt, err := api.datastore.RefreshKnownValidators()
		if err != nil {
			api.log.WithError(err).Error("error getting known validators")
		} else {
			if cnt == 0 {
				api.log.WithField("cnt", cnt).Warn("updated known validators, but have not received any")
			} else {
				api.log.WithField("cnt", cnt).Info("updated known validators")
			}
		}
	}
}

func (api *RelayAPI) RespondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := HTTPErrorResp{code, message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		api.log.WithField("response", resp).WithError(err).Error("Couldn't write error response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *RelayAPI) RespondOK(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		api.log.WithField("response", response).WithError(err).Error("Couldn't write OK response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *RelayAPI) RespondOKEmpty(w http.ResponseWriter) {
	api.RespondOK(w, NilResponse)
}

func (api *RelayAPI) handleRoot(w http.ResponseWriter, req *http.Request) {
	api.RespondOKEmpty(w)
}

func (api *RelayAPI) handleStatus(w http.ResponseWriter, req *http.Request) {
	api.RespondOKEmpty(w)
}

func (api *RelayAPI) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "registerValidator")
	log.Info("registerValidator")

	payload := []types.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	for _, registration := range payload {
		if len(registration.Message.Pubkey) != 48 {
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn("invalid pubkey length")
			continue
		}

		if len(registration.Signature) != 96 {
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn("invalid signature length")
			continue
		}

		// Check if actually a real validator
		isKnownValidator := api.datastore.IsKnownValidator(types.NewPubkeyHex(registration.Message.Pubkey.String()))
		if !isKnownValidator {
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn("not a known validator")
			continue
		}

		// Verify the signature
		ok, err := types.VerifySignature(registration.Message, api.builderSigningDomain, registration.Message.Pubkey[:], registration.Signature[:])
		if err != nil || !ok {
			log.WithError(err).WithField("registration", fmt.Sprintf("%+v", registration)).Warn("failed to verify registerValidator signature")
			continue
		}

		// Save or update (if newer timestamp than previous registration)
		err = api.datastore.UpdateValidatorRegistration(registration)
		if err != nil {
			log.WithError(err).WithField("registration", fmt.Sprintf("%+v", registration)).Error("error updating validator registration")
			continue
		}
	}

	api.RespondOK(w, NilResponse)
}

// func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
// 	vars := mux.Vars(req)
// 	slot := vars["slot"]
// 	parentHashHex := vars["parent_hash"]
// 	pubkey := vars["pubkey"]
// 	log := api.log.WithFields(logrus.Fields{
// 		"method":     "getHeader",
// 		"slot":       slot,
// 		"parentHash": parentHashHex,
// 		"pubkey":     pubkey,
// 	})
// 	log.Info("getHeader")

// 	if _, err := strconv.ParseUint(slot, 10, 64); err != nil {
// 		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSlot.Error())
// 		return
// 	}

// 	if len(pubkey) != 98 {
// 		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidPubkey.Error())
// 		return
// 	}

// 	if len(parentHashHex) != 66 {
// 		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidHash.Error())
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusNoContent)
// 	if err := json.NewEncoder(w).Encode(NilResponse); err != nil {
// 		api.log.WithError(err).Error("Couldn't write getHeader response")
// 		http.Error(w, "", http.StatusInternalServerError)
// 	}
// }

// func (api *RelayAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
// 	log := api.log.WithField("method", "getPayload")
// 	log.Info("getPayload")

// 	payload := new(types.SignedBlindedBeaconBlock)
// 	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
// 		api.RespondError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	if len(payload.Signature) != 96 {
// 		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSignature.Error())
// 		return
// 	}

// 	api.RespondOKEmpty(w)
// }

func (api *RelayAPI) handleGetValidatorsForEpoch(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "getValidatorsForEpoch")
	log.Info("request")
	api.RespondOKEmpty(w)
}

// func (m *ProposerAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
// 	log := m.Log.WithField("method", "submitNewBlock")
// 	log.Info("request")
// 	m.RespondOKEmpty(w)
// }
