// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
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
	uberatomic "go.uber.org/atomic"

	_ "net/http/pprof"
)

var (
	// Proposer API (builder-specs)
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"

	// Block builder API
	pathBuilderGetValidators = "/relay/v1/builder/validators"
	pathSubmitNewBlock       = "/relay/v1/builder/blocks"

	// JSON-RPC builder proxy
	// pathSendBundle = "/jsonrpc_sendbundle"
)

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr    string
	RegValWorkers int // number of workers for validator registration processing
	BeaconClient  beaconclient.BeaconNodeClient
	Datastore     datastore.Datastore
	SecretKey     *bls.SecretKey // used to sign bids (getHeader responses)

	// Network specific variables
	EthNetDetails common.EthNetworkDetails

	// Whether to enable Pprof
	PprofAPI bool

	// Delay on getHeader calls before checking memory for blocks and returning (not used anymore)
	GetHeaderWaitTime time.Duration
}

// RelayAPI represents a single Relay instance
type RelayAPI struct {
	opts RelayAPIOpts
	log  *logrus.Entry

	blsSk     *bls.SecretKey
	publicKey *types.PublicKey

	srv        *http.Server
	srvStarted uberatomic.Bool

	regValEntriesC       chan types.SignedValidatorRegistration
	regValWorkersStarted uberatomic.Bool

	datastore    datastore.Datastore
	beaconClient beaconclient.BeaconNodeClient

	proposerDutiesLock     sync.RWMutex
	proposerDutiesEpoch    uint64 // used to update duties only once per epoch
	proposerDutiesResponse []types.BuilderGetValidatorsResponseEntry

	headSlot     uint64
	currentEpoch uint64

	// feature flag options
	allowZeroValueBlocks                  bool
	enableQueryProposerDutiesForNextEpoch bool
	// disableGetPayloadVerifications        bool
}

// NewRelayAPI creates a new service. if builders is nil, allow any builder
func NewRelayAPI(opts RelayAPIOpts) (*RelayAPI, error) {
	if opts.Log == nil {
		return nil, errors.New("log parameter is nil")
	}

	if opts.BeaconClient == nil {
		return nil, errors.New("beacon-client is nil")
	}

	if opts.Datastore == nil {
		return nil, errors.New("proposer datastore is nil")
	}

	publicKey := types.BlsPublicKeyToPublicKey(bls.PublicKeyFromSecretKey(opts.SecretKey))

	api := RelayAPI{
		opts:                   opts,
		log:                    opts.Log.WithField("module", "api"),
		blsSk:                  opts.SecretKey,
		publicKey:              &publicKey,
		datastore:              opts.Datastore,
		beaconClient:           opts.BeaconClient,
		proposerDutiesResponse: []types.BuilderGetValidatorsResponseEntry{},
		regValEntriesC:         make(chan types.SignedValidatorRegistration, 5000),
	}

	api.log.Infof("Using BLS key: %s", publicKey.String())

	if opts.GetHeaderWaitTime > 0 {
		api.log.Infof("GetHeaderWaitTime: %s", opts.GetHeaderWaitTime.String())
	}

	if os.Getenv("ENABLE_ZERO_VALUE_BLOCKS") != "" {
		api.log.Warn("env: ENABLE_ZERO_VALUE_BLOCKS: sending blocks with zero value")
		api.allowZeroValueBlocks = true
	}

	if os.Getenv("ENABLE_QUERY_PROPOSER_DUTIES_NEXT_EPOCH") != "" {
		api.log.Warn("env: ENABLE_QUERY_PROPOSER_DUTIES_NEXT_EPOCH - querying proposer duties for current + next epoch")
		api.enableQueryProposerDutiesForNextEpoch = true
	}

	// if os.Getenv("DISABLE_SIGNATURE_VERIFICATIONS") != "" {
	// 	api.log.Warn("env: DISABLE_SIGNATURE_VERIFICATIONS - signature verifications disabled for registraterValidator and getPayload calls")
	// 	api.disableGetPayloadVerifications = true
	// }

	return &api, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()
	// r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)

	// Proposer API
	r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
	r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
	r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)

	// Builder API
	r.HandleFunc(pathBuilderGetValidators, api.handleBuilderGetValidators).Methods(http.MethodGet)
	r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodPost)

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
				ok, err := types.VerifySignature(registration.Message, api.opts.EthNetDetails.DomainBuilder, registration.Message.Pubkey[:], registration.Signature[:])
				if err != nil || !ok {
					api.log.WithError(err).WithField("registration", fmt.Sprintf("%+v", registration)).Warn("failed to verify registerValidator signature")
					continue
				}

				go api.datastore.IncEpochSummaryVal(api.currentEpoch, "validator_registrations_saved", 1)

				// Save the registration
				go func() {
					err := api.datastore.SetValidatorRegistration(registration)
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

	// Check beacon-node sync status, process current slot and start slot updates
	syncStatus, err := api.beaconClient.SyncStatus()
	if err != nil {
		return err
	}
	if syncStatus.IsSyncing {
		return errors.New("beacon node is syncing")
	}

	// Start worker pool for validator registration processing
	api.startValidatorRegistrationWorkers()

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

	// Process current slot
	headSlot := syncStatus.HeadSlot
	api.processNewSlot(headSlot)

	// Start regular slot updates
	go func() {
		c := make(chan uint64)
		go api.beaconClient.SubscribeToHeadEvents(c)
		for {
			headSlot := <-c
			api.processNewSlot(headSlot)
		}
	}()

	// Update HTML data before starting server
	// api.updateStatusHTMLData()

	api.srv = &http.Server{
		Addr:    api.opts.ListenAddr,
		Handler: api.getRouter(),

		ReadTimeout:       600 * time.Millisecond,
		ReadHeaderTimeout: 400 * time.Millisecond,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       3 * time.Second,
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

func (api *RelayAPI) processNewSlot(headSlot uint64) {
	if headSlot <= api.headSlot {
		return
	}

	if api.headSlot > 0 {
		for s := api.headSlot + 1; s < headSlot; s++ {
			api.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	api.headSlot = headSlot
	currentEpoch := headSlot / uint64(common.SlotsPerEpoch)
	api.log.WithFields(logrus.Fields{
		"epoch":              currentEpoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (currentEpoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot to %d", headSlot)

	go api.datastore.SetNXEpochSummaryVal(api.currentEpoch, "slot_first_processed", int64(headSlot))
	go api.datastore.SetEpochSummaryVal(api.currentEpoch, "slot_last_processed", int64(headSlot))
	api.currentEpoch = currentEpoch

	if headSlot%10 == 0 {
		// Remove expired headers
		numRemoved, numRemaining := api.datastore.CleanupOldBidsAndBlocks(headSlot)
		api.log.Infof("Removed %d old bids and blocks. Remaining: %d", numRemoved, numRemaining)
	}

	// Update proposer duties in the background
	go func() {
		err := api.updateProposerDuties(currentEpoch)
		if err != nil {
			api.log.WithError(err).WithField("epoch", currentEpoch).Error("failed to update proposer duties")
		}
	}()
}

func (api *RelayAPI) updateProposerDuties(epoch uint64) error {
	// Do nothing if already checked this epoch
	if epoch <= api.proposerDutiesEpoch {
		return nil
	}

	// Get the proposers with duty in this epoch (TODO: and next, but Prysm doesn't support it yet, Terence is on it)
	epochFrom := epoch
	epochTo := epoch
	if api.enableQueryProposerDutiesForNextEpoch {
		epochTo = epoch + 1
	}

	log := api.log.WithFields(logrus.Fields{
		"epochFrom": epochFrom,
		"epochTo":   epochTo,
	})
	log.Debug("updating proposer duties...")

	r, err := api.beaconClient.GetProposerDuties(epoch)
	if err != nil {
		return err
	}

	entries := r.Data

	if api.enableQueryProposerDutiesForNextEpoch {
		r2, err := api.beaconClient.GetProposerDuties(epoch + 1)
		if err != nil {
			return err
		}
		entries = append(entries, r2.Data...)
	}

	// Result for parallel Redis requests
	type result struct {
		val types.BuilderGetValidatorsResponseEntry
		err error
	}

	// Scatter requests to Redis to get registrations
	c := make(chan result, len(entries))
	for i := 0; i < cap(c); i++ {
		go func(duty beaconclient.ProposerDutiesResponseData) {
			reg, err := api.datastore.GetValidatorRegistration(types.NewPubkeyHex(duty.Pubkey))
			c <- result{types.BuilderGetValidatorsResponseEntry{
				Slot:  duty.Slot,
				Entry: reg,
			}, err}
		}(entries[i])
	}

	// Gather results
	proposerDutiesResponse := make([]types.BuilderGetValidatorsResponseEntry, 0)
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
	log.WithField("duties", len(proposerDutiesResponse)).Info("proposer duties updated")
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
				go api.datastore.SetEpochSummaryVal(api.currentEpoch, "validators_known_total", int64(cnt))
			}
		}

		_numRegistered, err := api.datastore.NumRegisteredValidators()
		if err != nil {
			api.log.WithError(err).Error("error getting number of registered validators")
		} else {
			go api.datastore.SetEpochSummaryVal(api.currentEpoch, "validator_registrations_total", int64(_numRegistered))
		}

		// api.updateStatusHTMLData()
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

func (api *RelayAPI) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// ---------------
//  PROPOSER APIS
// ---------------

func (api *RelayAPI) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "registerValidator")
	go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_register_validator_requests", 1)

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

		go api.datastore.IncEpochSummaryVal(api.currentEpoch, "validator_registrations_received_unverified", 1)

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
		"ip":               common.GetIPXForwardedFor(req),
	}).Info("validator registrations done")

	if errorResp != "" {
		api.RespondError(w, http.StatusBadRequest, errorResp)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_get_header_requests", 1)

	vars := mux.Vars(req)
	slotStr := vars["slot"]
	parentHashHex := vars["parent_hash"]
	proposerPubkeyHex := vars["pubkey"]
	log := api.log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slotStr,
		"parentHash": parentHashHex,
		"pubkey":     proposerPubkeyHex,
	})

	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSlot.Error())
		return
	}

	if len(proposerPubkeyHex) != 98 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidHash.Error())
		return
	}

	// Give builders some time...
	if api.opts.GetHeaderWaitTime > 0 {
		time.Sleep(api.opts.GetHeaderWaitTime)
	}

	bid, err := api.datastore.GetBid(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		log.WithError(err).Error("could not get bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if bid == nil || bid.Data == nil || bid.Data.Message == nil {
		go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_header_sent_204", 1)
		w.WriteHeader(http.StatusNoContent)
		return
	} else {
		// If 0-value bid, only return if explicitly allowed
		if bid.Data.Message.Value.Cmp(&ZeroU256) == 0 && !api.allowZeroValueBlocks {
			go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_header_sent_204", 1)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		log.WithFields(logrus.Fields{
			"value":     bid.Data.Message.Value.String(),
			"blockHash": bid.Data.Message.Header.BlockHash.String(),
		}).Info("bid delivered")

		go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_header_sent_ok", 1)
		api.RespondOK(w, bid)
		return
	}
}

func (api *RelayAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "getPayload")
	go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_get_payload_requests", 1)

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log = log.WithFields(logrus.Fields{
		"slot":      payload.Message.Slot,
		"blockHash": strings.ToLower(payload.Message.Body.ExecutionPayloadHeader.BlockHash.String()),
	})

	if len(payload.Signature) != 96 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSignature.Error())
		return
	}

	pubkeyFromIndex, found := api.datastore.GetKnownValidatorPubkeyByIndex(payload.Message.ProposerIndex)
	if !found {
		log.Warnf("could not find proposer pubkey for index %d", payload.Message.ProposerIndex)
		// api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	log = log.WithField("pubkeyFromIndex", pubkeyFromIndex)

	// Get the proposer pubkey based on the validator index from the payload
	pk, err := types.HexToPubkey(pubkeyFromIndex.String())
	if err != nil {
		log.WithError(err).Warn("could not convert pubkey to types.PublicKey")
		api.RespondError(w, http.StatusBadRequest, "could not convert pubkey to types.PublicKey")
		return
	}

	// Verify the signature
	ok, err := types.VerifySignature(payload.Message, api.opts.EthNetDetails.DomainBeaconProposer, pk[:], payload.Signature[:])
	if !ok || err != nil {
		log.WithError(err).Warn("could not verify payload signature")
		api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	// Get the block
	block, err := api.datastore.GetBlock(payload.Message.Slot, pubkeyFromIndex.String(), payload.Message.Body.ExecutionPayloadHeader.BlockHash.String())
	if err != nil {
		log.WithError(err).Error("could not get block")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if block == nil {
		log.Error("requested execution payload was not found")
		api.RespondError(w, http.StatusBadRequest, "no execution payload for this request")
		return
	}

	api.RespondOK(w, block)
	go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_payload_sent", 1)
	go api.datastore.SetSlotPayloadDelivered(payload.Message.Slot, pubkeyFromIndex.String(), payload.Message.Body.ExecutionPayloadHeader.BlockHash.String())
	log.WithField("tx", len(block.Data.Transactions)).Info("execution payload delivered")
}

// --------------------
//  BLOCK BUILDER APIS
// --------------------

func (api *RelayAPI) handleBuilderGetValidators(w http.ResponseWriter, req *http.Request) {
	api.proposerDutiesLock.RLock()
	defer api.proposerDutiesLock.RUnlock()
	api.RespondOK(w, api.proposerDutiesResponse)
}

func (api *RelayAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "submitNewBlock")

	payload := new(types.BuilderSubmitBlockRequest)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		log.WithError(err).Error("could not decode payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// By default, don't accept blocks with 0 value
	if !api.allowZeroValueBlocks {
		if payload.Message.Value.Cmp(&ZeroU256) == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Sanity check the submission
	err := VerifyBuilderBlockSubmission(payload)
	if err != nil {
		log.WithError(err).Warn("block submission verification failed")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_builder_bid_received", 1)

	// Check if there's already a bid
	prevBid, err := api.datastore.GetBid(payload.Message.Slot, payload.Message.ParentHash.String(), payload.Message.ProposerPubkey.String())
	if err != nil {
		log.WithError(err).Error("could not get best bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// If existing bid has same or higher value, do nothing
	if prevBid != nil {
		if payload.Message.Value.Cmp(&prevBid.Data.Message.Value) < 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Prepare the response data
	signedBuilderBid, err := BuilderSubmitBlockRequestToSignedBuilderBid(payload, api.blsSk, api.publicKey, api.opts.EthNetDetails.DomainBuilder)
	if err != nil {
		log.WithError(err).Error("could not sign builder bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	getHeaderResponse := types.GetHeaderResponse{
		Version: VersionBellatrix,
		Data:    signedBuilderBid,
	}

	getPayloadResponse := types.GetPayloadResponse{
		Version: VersionBellatrix,
		Data:    payload.ExecutionPayload,
	}

	err = api.datastore.SaveBidAndBlock(payload.Message.Slot, payload.Message.ProposerPubkey.String(), &getHeaderResponse, &getPayloadResponse)
	if err != nil {
		log.WithError(err).Error("could not save bid and block")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log.WithFields(logrus.Fields{
		"slot":           payload.Message.Slot,
		"blockHash":      payload.Message.BlockHash.String(),
		"parentHash":     payload.Message.ParentHash.String(),
		"builderPubkey":  payload.Message.BuilderPubkey.String(),
		"proposerPubkey": payload.Message.ProposerPubkey.String(),
		"value":          payload.Message.Value.String(),
		"tx":             len(payload.ExecutionPayload.Transactions),
	}).Info("received block from builder")

	// Update HTML data
	// go api.updateStatusHTMLData()

	// Respond with OK (TODO: proper response format)
	w.WriteHeader(http.StatusOK)
}
