// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"

	_ "net/http/pprof"
)

var (
	// Proposer API (builder-specs)
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	// pathGetPayload        = "/eth/v1/builder/blinded_blocks"

	// Block builder API
	pathBuilderGetValidators = "/relay/v1/builder/validators"
	pathSubmitNewBlock       = "/relay/v1/builder/blocks"
)

type bidKey struct {
	slot           uint64
	parentHash     string
	proposerPubkey string
}

type blockKey struct {
	slot      uint64
	blockHash string
}

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr    string
	RegValWorkers int // number of workers for validator registration processing
	BeaconClient  beaconclient.BeaconNodeClient
	Datastore     datastore.ProposerDatastore

	// GenesisForkVersion for validating signatures
	GenesisForkVersionHex string

	// Which APIs and services to spin up
	ProposerAPI bool
	BuilderAPI  bool
	PprofAPI    bool
}

// RelayAPI represents a single Relay instance
type RelayAPI struct {
	opts RelayAPIOpts
	log  *logrus.Entry

	sk *bls.SecretKey

	srv        *http.Server
	srvStarted atomic.Bool

	regValEntriesC       chan types.SignedValidatorRegistration
	regValWorkersStarted atomic.Bool

	datastore            datastore.ProposerDatastore
	beaconClient         beaconclient.BeaconNodeClient
	builderSigningDomain types.Domain

	proposerDutiesLock     sync.RWMutex
	proposerDutiesEpoch    uint64 // used to update duties only once per epoch
	proposerDutiesResponse []BuilderGetValidatorsResponseEntry

	bidLock sync.RWMutex // lock for both bids and blocks
	bids    map[bidKey]*types.GetHeaderResponse
	blocks  map[blockKey]*types.GetPayloadResponse

	// debugDisableValidatorRegistrationChecks bool
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

	sk, _, err := bls.GenerateNewKeypair()
	if err != nil {
		return nil, err
	}

	api := RelayAPI{
		opts:                   opts,
		log:                    opts.Log.WithField("module", "api"),
		sk:                     sk,
		datastore:              opts.Datastore,
		beaconClient:           opts.BeaconClient,
		proposerDutiesResponse: []BuilderGetValidatorsResponseEntry{},
		regValEntriesC:         make(chan types.SignedValidatorRegistration, 5000),

		bids:   make(map[bidKey]*types.GetHeaderResponse),
		blocks: make(map[blockKey]*types.GetPayloadResponse),
	}

	// if os.Getenv("DEBUG_ENABLE_ANY_VALREG") != "" {
	// 	api.log.Warn("DEBUG: validator registration checks are disabled")
	// 	api.debugDisableValidatorRegistrationChecks = true
	// }

	api.builderSigningDomain, err = common.ComputerBuilderSigningDomain(opts.GenesisForkVersionHex)
	if err != nil {
		return nil, err
	}

	return &api, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)

	if api.opts.ProposerAPI {
		r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
		r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
		r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
		// r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)
	}

	if api.opts.BuilderAPI {
		r.HandleFunc(pathBuilderGetValidators, api.handleBuilderGetValidators).Methods(http.MethodGet)
		r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodPost)
	}

	if api.opts.PprofAPI {
		r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	}

	// r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(api.log, r)
	return loggedRouter
}

// startValidatorRegistrationWorkers starts a number of worker goroutines to handle the expensive part
// of (already sanity-checked) validator registrations: the signature verification and updating in Redis.
func (api *RelayAPI) startValidatorRegistrationWorkers() error {
	if api.regValWorkersStarted.Swap(true) {
		return errors.New("validator registration workers already started")
	}

	numWorkers := api.opts.RegValWorkers
	if numWorkers == 0 {
		numWorkers = runtime.NumCPU()
	}

	api.log.Infof("Starting %d registerValidator workers", numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func() {
			for {
				registration := <-api.regValEntriesC

				// Verify the signature
				ok, err := types.VerifySignature(registration.Message, api.builderSigningDomain, registration.Message.Pubkey[:], registration.Signature[:])
				if err != nil || !ok {
					api.log.WithError(err).WithField("registration", fmt.Sprintf("%+v", registration)).Warn("failed to verify registerValidator signature")
					continue
				}

				// Save the registration
				go func() {
					err = api.datastore.SetValidatorRegistration(registration)
					if err != nil {
						api.log.WithError(err).WithField("registration", fmt.Sprintf("%+v", registration)).Error("error updating validator registration")
					}
				}()
			}
		}()
	}
	return nil
}

// StartServer starts the HTTP server for this instance
func (api *RelayAPI) StartServer() (err error) {
	if api.srvStarted.Swap(true) {
		return errors.New("server was already started")
	}

	// Check beacon-node sync status, set current slot and start update loop
	syncStatus, err := api.beaconClient.SyncStatus()
	if err != nil {
		return err
	}
	if syncStatus.IsSyncing {
		return errors.New("beacon node is syncing")
	}
	currentSlot := syncStatus.HeadSlot
	currentEpoch := currentSlot / uint64(common.SlotsPerEpoch)
	api.log.WithField("slot", currentSlot).WithField("epoch", currentEpoch).Info("updated current slot")

	// Start worker pool for validator registration processing
	api.startValidatorRegistrationWorkers()

	// Get proposer duties for current and next epoch
	err = api.updateProposerDuties(currentEpoch)
	if err != nil {
		return err
	}

	// Start regular slot updates
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

// Stop: TODO: use context everywhere to quit background tasks as well
// func (api *RelayAPI) Stop() error {
// 	if !api.srvStarted.Load() {
// 		return nil
// 	}
// 	defer api.srvStarted.Store(false)
// 	return api.srv.Close()
// }

func (api *RelayAPI) startSlotUpdates() {
	c := make(chan uint64)
	go api.beaconClient.SubscribeToHeadEvents(c)
	for {
		currentSlot := <-c
		currentEpoch := currentSlot / uint64(common.SlotsPerEpoch)
		api.log.WithFields(logrus.Fields{
			"slot":            currentSlot,
			"epoch":           currentEpoch,
			"slotLastInEpoch": (currentEpoch+1)*32 - 1,
		}).Info("updated current slot")

		// Update proposer duties in the background
		go func() {
			err := api.updateProposerDuties(currentEpoch)
			if err != nil {
				api.log.WithError(err).WithField("epoch", currentEpoch).Error("failed to update proposer duties")
			}
		}()
	}
}

func (api *RelayAPI) updateProposerDuties(epoch uint64) error {
	// Do nothing if already checked this epoch
	if epoch == api.proposerDutiesEpoch {
		return nil
	}

	// Get the proposers with duty in this epoch (TODO: and next, but Prysm doesn't support it yet, Terence is on it)
	api.log.WithField("epoch", epoch).Debug("updating proposer duties...")
	r, err := api.beaconClient.GetProposerDuties(epoch)
	if err != nil {
		return err
	}

	// Result for parallel Redis requests
	type result struct {
		val BuilderGetValidatorsResponseEntry
		err error
	}

	// Scatter requests to Redis to get registrations
	c := make(chan result, len(r.Data))
	for i := 0; i < cap(c); i++ {
		go func(duty beaconclient.ProposerDutiesResponseData) {
			reg, err := api.datastore.GetValidatorRegistration(types.NewPubkeyHex(duty.Pubkey))
			c <- result{BuilderGetValidatorsResponseEntry{
				Slot:  duty.Slot,
				Entry: reg,
			}, err}
		}(r.Data[i])
	}

	// Gather results
	proposerDutiesResponse := make([]BuilderGetValidatorsResponseEntry, 0)
	for i := 0; i < cap(c); i++ {
		res := <-c
		if res.err != nil {
			return res.err
		} else if res.val.Entry != nil {
			proposerDutiesResponse = append(proposerDutiesResponse, res.val)
		}
	}

	api.proposerDutiesLock.Lock()
	api.proposerDutiesEpoch = epoch
	api.proposerDutiesResponse = proposerDutiesResponse
	api.proposerDutiesLock.Unlock()
	// api.log.WithField("epoch", epoch).Infof("proposer duties updated for slots %d-%d", proposerDutiesResponse[0].Slot, proposerDutiesResponse[len(proposerDutiesResponse)-1].Slot)
	api.log.WithField("epoch", epoch).Info("proposer duties updated")
	return nil
}

func (api *RelayAPI) startKnownValidatorUpdates() {
	for {
		// Wait for one epoch (at the beginning, because initially the validators have already been queried)
		time.Sleep(common.DurationPerEpoch / 2)

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
	// log.Info("registerValidator")

	start := time.Now()
	startTimestamp := start.Unix()

	payload := []types.SignedValidatorRegistration{}
	lastChangedPubkey := ""
	errorResp := ""
	numSentToC := 0

	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Possible optimisations:
	// - GetValidatorRegistrationTimestamp could keep a cache in memory for some time and check memory first before going to Redis
	// - Do multiple loops and filter down set of registrations, and batch checks for all registrations instead of locking for each individually:
	//   (1) sanity checks, (2) IsKnownValidator, (3) CheckTimestamp, (4) Batch SetValidatorRegistration
	for _, registration := range payload {
		if registration.Message == nil {
			log.Warn("registration without message")
			continue
		}

		if len(registration.Message.Pubkey) != 48 {
			errorResp = "invalid pubkey length"
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			continue
		}

		if len(registration.Signature) != 96 {
			errorResp = "invalid signature length"
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			continue
		}

		td := int64(registration.Message.Timestamp) - startTimestamp
		if td > 10 {
			errorResp = "timestamp too far in the future"
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			continue
		}

		// Check if actually a real validator
		isKnownValidator := api.datastore.IsKnownValidator(registration.Message.Pubkey.PubkeyHex())
		if !isKnownValidator {
			errorResp = fmt.Sprintf("not a known validator: %s", registration.Message.Pubkey.PubkeyHex())
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			continue
		}

		// Check for a previous registration timestamp
		prevTimestamp, err := api.datastore.GetValidatorRegistrationTimestamp(registration.Message.Pubkey.PubkeyHex())
		if err != nil {
			log.WithError(err).Infof("error getting last registration timestamp for %s", registration.Message.Pubkey.PubkeyHex())
		}

		// Do nothing if the registration is already the latest
		if prevTimestamp >= registration.Message.Timestamp {
			continue
		}

		// Send to workers for signature verification and saving
		api.regValEntriesC <- registration
		numSentToC++
		lastChangedPubkey = registration.Message.Pubkey.String()
	}

	log.WithFields(logrus.Fields{
		"numRegistrations": len(payload),
		"numSentToC":       numSentToC,
		"lastChanged":      lastChangedPubkey,
		"timeNeededSec":    time.Since(start).Seconds(),
		"error":            errorResp,
		"IP":               common.GetIPXForwardedFor(req),
	}).Info("validator registrations done")

	if errorResp != "" {
		api.RespondError(w, http.StatusBadRequest, errorResp)
	} else {
		api.RespondOKEmpty(w)
	}
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slotStr := vars["slot"]
	parentHashHex := vars["parent_hash"]
	pubkey := vars["pubkey"]
	log := api.log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slotStr,
		"parentHash": parentHashHex,
		"pubkey":     pubkey,
	})
	log.Info("getHeader")

	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSlot.Error())
		return
	}

	if len(pubkey) != 98 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidHash.Error())
		return
	}

	api.bidLock.RLock()
	bid := api.bids[bidKey{
		slot:           slot,
		parentHash:     parentHashHex,
		proposerPubkey: pubkey,
	}]
	api.bidLock.RUnlock()

	if bid == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	} else {
		api.RespondOK(w, bid)
		return
	}
}

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

func (api *RelayAPI) handleBuilderGetValidators(w http.ResponseWriter, req *http.Request) {
	// log := api.log.WithField("method", "getValidatorsForEpoch")
	api.proposerDutiesLock.RLock()
	defer api.proposerDutiesLock.RUnlock()
	api.RespondOK(w, api.proposerDutiesResponse)
}

func (api *RelayAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "submitNewBlock")
	log.Info("request")

	payload := new(BuilderSubmitBlockRequest)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		log.WithError(err).Error("could not decode payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, api.sk, api.builderSigningDomain)
	if err != nil {
		log.WithError(err).Error("could not sign builder bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	getHeaderResponse := types.GetHeaderResponse{
		Version: "bellatrix",
		Data:    signedBuilderBid,
	}

	getPayloadResponse := types.GetPayloadResponse{
		Version: "bellatrix",
		Data:    &payload.ExecutionPayload,
	}

	// TODO:
	// - accept new block only if greater valur
	// - save to Redis
	// - expire
	api.bidLock.Lock()
	api.bids[bidKey{
		slot:           payload.Message.Slot,
		parentHash:     payload.Message.ParentHash.String(),
		proposerPubkey: payload.Message.ProposerPubkey.String(),
	}] = &getHeaderResponse
	api.blocks[blockKey{
		slot:      payload.Message.Slot,
		blockHash: payload.Message.BlockHash.String(),
	}] = &getPayloadResponse
	api.bidLock.Unlock()

	log.WithFields(logrus.Fields{
		"slot":           payload.Message.Slot,
		"parentHash":     payload.Message.ParentHash,
		"proposerPubkey": payload.Message.ProposerPubkey,
		"blockHash":      payload.Message.BlockHash,
		"value":          payload.Message.Value,
	}).Info("Got a new block!")

	api.RespondError(w, http.StatusNotImplemented, "not yet implemented")
}
