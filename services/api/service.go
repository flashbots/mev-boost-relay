// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
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

	// Data API
	pathDataProposerPayloadDelivered = "/relay/v1/data/bidtraces/proposer_payload_delivered"
)

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr    string
	RegValWorkers int // number of workers for validator registration processing
	BeaconClient  beaconclient.BeaconNodeClient
	Datastore     datastore.Datastore
	Redis         *datastore.RedisCache

	SecretKey *bls.SecretKey // used to sign bids (getHeader responses)

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

	beaconClient beaconclient.BeaconNodeClient
	datastore    datastore.Datastore
	redis        *datastore.RedisCache

	headSlot     uint64
	currentEpoch uint64

	proposerDutiesLock       sync.RWMutex
	proposerDutiesResponse   []types.BuilderGetValidatorsResponseEntry
	proposerDutiesSlot       uint64
	isUpdatingProposerDuties uberatomic.Bool

	// feature flags
	ffAllowZeroValueBlocks       bool
	ffSyncValidatorRegistrations bool
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
		redis:                  opts.Redis,
		proposerDutiesResponse: []types.BuilderGetValidatorsResponseEntry{},
		regValEntriesC:         make(chan types.SignedValidatorRegistration, 5000),
	}

	api.log.Infof("Using BLS key: %s", publicKey.String())

	// ensure pubkey is same across all relay instances
	_pubkey, err := api.redis.GetRelayConfig(datastore.FieldPubkey)
	if err != nil {
		return nil, err
	} else if _pubkey == "" {
		api.redis.SetRelayConfig(datastore.FieldPubkey, publicKey.String())
	} else if _pubkey != publicKey.String() {
		return nil, fmt.Errorf("relay pubkey %s does not match already existing one %s", publicKey.String(), _pubkey)
	}

	if opts.GetHeaderWaitTime > 0 {
		api.log.Warnf("GetHeaderWaitTime: %s", opts.GetHeaderWaitTime.String())
	}

	if os.Getenv("ENABLE_ZERO_VALUE_BLOCKS") != "" {
		api.log.Warn("env: ENABLE_ZERO_VALUE_BLOCKS: sending blocks with zero value")
		api.ffAllowZeroValueBlocks = true
	}

	if os.Getenv("SYNC_VALIDATOR_REGISTRATIONS") != "" {
		api.log.Warn("env: SYNC_VALIDATOR_REGISTRATIONS: enabling sync validator registrations")
		api.ffSyncValidatorRegistrations = true
	}

	return &api, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()

	// Proposer API
	r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
	r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
	r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)

	// Builder API
	r.HandleFunc(pathBuilderGetValidators, api.handleBuilderGetValidators).Methods(http.MethodGet)
	r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodPost)

	// Data API
	r.HandleFunc(pathDataProposerPayloadDelivered, api.handleDataProposerPayloadDelivers).Methods(http.MethodGet)

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
					api.log.WithError(err).WithField("pubkey", registration.Message.Pubkey.String()).Warn("failed to verify registerValidator signature")
					continue
				}

				// Save the registration and increment counter
				go api.datastore.SetValidatorRegistration(registration)
				// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "validator_registrations_saved", 1)
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

	// Get current proposer duties
	api.updateProposerDuties(syncStatus.HeadSlot)

	// Update list of known validators, and start refresh loop
	go api.startKnownValidatorUpdates()

	// Process current slot
	api.processNewSlot(syncStatus.HeadSlot)

	// Start regular slot updates
	go func() {
		c := make(chan uint64)
		go api.beaconClient.SubscribeToHeadEvents(c)
		for {
			headSlot := <-c
			api.processNewSlot(headSlot)
		}
	}()

	// Periodically remove expired headers
	go func() {
		for {
			time.Sleep(2 * time.Minute)
			numRemoved, numRemaining := api.datastore.CleanupOldBidsAndBlocks(api.headSlot)
			api.log.Infof("Removed %d old bids and blocks. Remaining: %d", numRemoved, numRemaining)
		}
	}()

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
	api.currentEpoch = headSlot / uint64(common.SlotsPerEpoch)
	api.log.WithFields(logrus.Fields{
		"epoch":              api.currentEpoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (api.currentEpoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot to %d", headSlot)

	// go api.datastore.SetNXEpochSummaryVal(api.currentEpoch, "slot_first_processed", int64(headSlot))
	// go api.datastore.SetEpochSummaryVal(api.currentEpoch, "slot_last_processed", int64(headSlot))

	// Regularly update proposer duties in the background
	go api.updateProposerDuties(headSlot)
}

func (api *RelayAPI) updateProposerDuties(headSlot uint64) {
	// Ensure only one updating is running at a time
	if api.isUpdatingProposerDuties.Swap(true) {
		return
	}
	defer api.isUpdatingProposerDuties.Store(false)

	// Update once every 8 slots (or more, if a slot was missed)
	if headSlot%8 != 0 && headSlot-api.proposerDutiesSlot < 8 {
		return
	}

	// Until epoch+1 is enabled, we need to delay here, because at start of epoch at the same time the housekeeper is updating, and we might get an old update otherwise
	// time.Sleep(1 * time.Second)

	// Get duties from mem
	duties, err := api.redis.GetProposerDuties()

	if err == nil {
		api.proposerDutiesLock.Lock()
		api.proposerDutiesResponse = duties
		api.proposerDutiesSlot = headSlot
		api.proposerDutiesLock.Unlock()

		// pretty-print
		_duties := make([]string, len(duties))
		for i, duty := range duties {
			_duties[i] = fmt.Sprint(duty.Slot)
		}
		sort.Strings(_duties)
		api.log.Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
	} else {
		api.log.WithError(err).Error("failed to update proposer duties")
	}
}

func (api *RelayAPI) startKnownValidatorUpdates() {
	for {
		// Refresh known validators
		cnt, err := api.datastore.RefreshKnownValidators()
		if err != nil {
			api.log.WithError(err).Error("error getting known validators")
		} else {
			api.log.WithField("cnt", cnt).Info("updated known validators")
		}

		// Wait for one epoch (at the beginning, because initially the validators have already been queried)
		time.Sleep(common.DurationPerEpoch / 2)
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
	// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_register_validator_requests", 1)

	start := time.Now()
	startTimestamp := start.Unix()

	payload := []types.SignedValidatorRegistration{}
	errorResp := ""
	numRegNew := 0
	numRegErr := 0

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
			numRegErr += 1
			continue
		}

		if len(registration.Message.Pubkey) != 48 {
			errorResp = "invalid pubkey length"
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			numRegErr += 1
			continue
		}

		if len(registration.Signature) != 96 {
			errorResp = "invalid signature length"
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			numRegErr += 1
			continue
		}

		td := int64(registration.Message.Timestamp) - startTimestamp
		if td > 10 {
			errorResp = "timestamp too far in the future"
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			numRegErr += 1
			continue
		}

		// Check if actually a real validator
		isKnownValidator := api.datastore.IsKnownValidator(registration.Message.Pubkey.PubkeyHex())
		if !isKnownValidator {
			errorResp = fmt.Sprintf("not a known validator: %s", registration.Message.Pubkey.PubkeyHex())
			log.WithField("registration", fmt.Sprintf("%+v", registration)).Warn(errorResp)
			numRegErr += 1
			continue
		}

		// Check for a previous registration timestamp
		prevTimestamp, err := api.datastore.GetValidatorRegistrationTimestamp(registration.Message.Pubkey.PubkeyHex())
		if err != nil {
			log.WithError(err).Infof("error getting last registration timestamp for %s", registration.Message.Pubkey.PubkeyHex())
		}

		// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "validator_registrations_received_unverified", 1)

		// Do nothing if the registration is already the latest
		if prevTimestamp >= registration.Message.Timestamp {
			continue
		}

		// Send to workers for signature verification and saving
		numRegNew++
		if api.ffSyncValidatorRegistrations {
			// Verify the signature
			ok, err := types.VerifySignature(registration.Message, api.opts.EthNetDetails.DomainBuilder, registration.Message.Pubkey[:], registration.Signature[:])
			if err != nil || !ok {
				if err != nil {
					api.log.WithError(err).WithField("pubkey", registration.Message.Pubkey.String()).Error("error verifying registerValidator signature")
				}
				numRegErr += 1
				errorResp = fmt.Sprintf("failed to verify validator signature of %d registrations. latest: %s", numRegErr, registration.Message.Pubkey)
			} else {
				// Save and increment counter
				go api.datastore.SetValidatorRegistration(registration)
				// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "validator_registrations_saved", 1)
			}

		} else {
			// Send to channel for async processing
			api.regValEntriesC <- registration
		}
	}

	log = log.WithFields(logrus.Fields{
		"numRegistrations":    len(payload),
		"numRegistrationsNew": numRegNew,
		"numRegistrationsErr": numRegErr,
		"timeNeededSec":       time.Since(start).Seconds(),
		"ip":                  common.GetIPXForwardedFor(req),
	})
	if errorResp != "" {
		log = log.WithField("error", errorResp)
	}
	log.Info("validator registrations processed")

	if errorResp != "" {
		api.RespondError(w, http.StatusBadRequest, errorResp)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_get_header_requests", 1)

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
		// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_header_sent_204", 1)
		w.WriteHeader(http.StatusNoContent)
		return
	} else {
		// If 0-value bid, only return if explicitly allowed
		if bid.Data.Message.Value.Cmp(&ZeroU256) == 0 && !api.ffAllowZeroValueBlocks {
			// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_header_sent_204", 1)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		log.WithFields(logrus.Fields{
			"value":     bid.Data.Message.Value.String(),
			"blockHash": bid.Data.Message.Header.BlockHash.String(),
		}).Info("bid delivered")

		// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_header_sent_ok", 1)
		api.RespondOK(w, bid)
		return
	}
}

func (api *RelayAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "getPayload")
	// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_get_payload_requests", 1)

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

	proposerPubkey, found := api.datastore.GetKnownValidatorPubkeyByIndex(payload.Message.ProposerIndex)
	if !found {
		log.Errorf("could not find proposer pubkey for index %d", payload.Message.ProposerIndex)
		api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	log = log.WithField("pubkeyFromIndex", proposerPubkey)

	// Get the proposer pubkey based on the validator index from the payload
	pk, err := types.HexToPubkey(proposerPubkey.String())
	if err != nil {
		log.WithError(err).Warn("could not convert pubkey to types.PublicKey")
		api.RespondError(w, http.StatusBadRequest, "could not convert pubkey to types.PublicKey")
		return
	}

	// Verify the signature
	ok, err := types.VerifySignature(payload.Message, api.opts.EthNetDetails.DomainBeaconProposer, pk[:], payload.Signature[:])
	if !ok || err != nil {
		log.WithError(err).Warn("could not verify payload signature")
		api.RespondError(w, http.StatusBadRequest, "could not verify payload signature")
		return
	}

	// Get the block
	blockBidAndTrace, err := api.datastore.GetBlockBidAndTrace(payload.Message.Slot, proposerPubkey.String(), payload.Message.Body.ExecutionPayloadHeader.BlockHash.String())
	if err != nil {
		log.WithError(err).Error("failed getting execution payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if blockBidAndTrace == nil {
		log.Error("requested execution payload was not found")
		api.RespondError(w, http.StatusBadRequest, "no execution payload for this request")
		return
	}

	api.RespondOK(w, blockBidAndTrace.Payload)
	log.WithFields(logrus.Fields{
		"numTx":       len(blockBidAndTrace.Payload.Data.Transactions),
		"blockNumber": payload.Message.Body.ExecutionPayloadHeader.BlockNumber,
	}).Info("execution payload delivered")

	// Save payload and increment counter
	go api.datastore.SaveDeliveredPayload(payload, blockBidAndTrace.Bid, blockBidAndTrace.Payload, blockBidAndTrace.Trace)
	// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_payload_sent", 1)
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
	if !api.ffAllowZeroValueBlocks {
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

	// go api.datastore.IncEpochSummaryVal(api.currentEpoch, "num_builder_bid_received", 1)

	// Verify the signature
	ok, err := types.VerifySignature(payload.Message, api.opts.EthNetDetails.DomainBuilder, payload.Message.BuilderPubkey[:], payload.Signature[:])
	if !ok || err != nil {
		log.WithError(err).Warn("could not verify builder bid payload signature")
		// continue for now, as long as we're the only builder
		// api.RespondError(w, http.StatusBadRequest, "invalid signature")
		// return
	}

	// Save to database
	go func() {
		err := api.datastore.SaveBuilderBlockSubmission(payload)
		if err != nil {
			log.WithError(err).Error("saving builder block submission to database failed")
		}
	}()

	// Check if there's already a bid
	prevBid, err := api.datastore.GetBid(payload.Message.Slot, payload.Message.ParentHash.String(), payload.Message.ProposerPubkey.String())
	if err != nil {
		log.WithError(err).Error("could not get best bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// If existing bid has same or higher value, do nothing
	if prevBid != nil && payload.Message.Value.Cmp(&prevBid.Data.Message.Value) < 1 {
		w.WriteHeader(http.StatusOK)
		return
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

	signedBidTrace := types.SignedBidTrace{
		Message:   payload.Message,
		Signature: payload.Signature,
	}

	err = api.datastore.SaveBidAndBlock(payload.Message.Slot, payload.Message.ProposerPubkey.String(), &signedBidTrace, &getHeaderResponse, &getPayloadResponse)
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

func (api *RelayAPI) handleDataProposerPayloadDelivers(w http.ResponseWriter, req *http.Request) {
	var err error

	args := req.URL.Query()

	filters := database.GetPayloadsFilters{
		IncludeBidTrace: true,
		Limit:           10,
		BlockHash:       args.Get("block_hash"),
	}

	if args.Get("slot") != "" {
		filters.Slot, err = strconv.ParseUint(args.Get("slot"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
	}

	if args.Get("limit") != "" {
		_limit, err := strconv.ParseUint(args.Get("limit"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
		if _limit < filters.Limit {
			filters.Limit = _limit
		}
	}

	// fmt.Println(req.URL.Query(), _slot, _blockhash)
	// fmt.Printf("%+#v \n", filters)
	payloads, err := api.datastore.GetRecentDeliveredPayloads(filters)
	if err != nil {
		api.log.WithError(err).Error("error getting recent payloads")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := []types.BidTrace{}
	for _, payload := range payloads {
		trace := types.BidTrace{}
		err = json.Unmarshal([]byte(payload.BidTrace), &trace)
		if err != nil {
			api.log.WithError(err).Error("failed to unmarshal bidtrace")
		} else {
			response = append(response, trace)
		}
	}

	api.RespondOK(w, response)
}
