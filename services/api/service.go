// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

var (
	ErrMissingLogOpt                     = errors.New("log parameter is nil")
	ErrMissingBeaconClientOpt            = errors.New("beacon-client is nil")
	ErrMissingDatastoreOpt               = errors.New("proposer datastore is nil")
	ErrRelayPubkeyMismatch               = errors.New("relay pubkey does not match existing one")
	ErrRegistrationWorkersAlreadyStarted = errors.New("validator registration workers already started")
	ErrServerAlreadyStarted              = errors.New("server was already started")
	ErrBeaconNodeSyncing                 = errors.New("beacon node is syncing")
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
	BlockSimURL   string
	RegValWorkers int // number of workers for validator registration processing

	BeaconClients []beaconclient.BeaconNodeClient
	Datastore     *datastore.Datastore
	Redis         *datastore.RedisCache
	DB            database.IDatabaseService

	SecretKey *bls.SecretKey // used to sign bids (getHeader responses)

	// Network specific variables
	EthNetDetails common.EthNetworkDetails

	// Whether to enable Pprof
	PprofAPI bool
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

	beaconClients []beaconclient.BeaconNodeClient
	datastore     *datastore.Datastore
	redis         *datastore.RedisCache
	db            database.IDatabaseService

	headSlot     uint64
	currentEpoch uint64

	proposerDutiesLock       sync.RWMutex
	proposerDutiesResponse   []types.BuilderGetValidatorsResponseEntry
	proposerDutiesSlot       uint64
	isUpdatingProposerDuties uberatomic.Bool

	blockSimRateLimiter *BlockSimulationRateLimiter

	// feature flags
	ffAllowSyncingBeaconNode     bool
	ffAllowZeroValueBlocks       bool
	ffSyncValidatorRegistrations bool
	ffAllowBlockVerificationFail bool
}

// NewRelayAPI creates a new service. if builders is nil, allow any builder
func NewRelayAPI(opts RelayAPIOpts) (*RelayAPI, error) {
	if opts.Log == nil {
		return nil, ErrMissingLogOpt
	}

	if len(opts.BeaconClients) == 0 {
		return nil, ErrMissingBeaconClientOpt
	}

	if opts.Datastore == nil {
		return nil, ErrMissingDatastoreOpt
	}

	publicKey := types.BlsPublicKeyToPublicKey(bls.PublicKeyFromSecretKey(opts.SecretKey))

	api := RelayAPI{
		opts:                   opts,
		log:                    opts.Log.WithField("module", "api"),
		blsSk:                  opts.SecretKey,
		publicKey:              &publicKey,
		datastore:              opts.Datastore,
		beaconClients:          opts.BeaconClients,
		redis:                  opts.Redis,
		db:                     opts.DB,
		proposerDutiesResponse: []types.BuilderGetValidatorsResponseEntry{},
		regValEntriesC:         make(chan types.SignedValidatorRegistration, 5000),
		blockSimRateLimiter:    NewBlockSimulationRateLimiter(opts.BlockSimURL),
	}

	api.log.Infof("Using BLS key: %s", publicKey.String())

	// ensure pubkey is same across all relay instances
	_pubkey, err := api.redis.GetRelayConfig(datastore.RedisConfigFieldPubkey)
	if err != nil {
		return nil, err
	} else if _pubkey == "" {
		err := api.redis.SetRelayConfig(datastore.RedisConfigFieldPubkey, publicKey.String())
		if err != nil {
			return nil, err
		}
	} else if _pubkey != publicKey.String() {
		return nil, fmt.Errorf("%w: new=%s old=%s", ErrRelayPubkeyMismatch, publicKey.String(), _pubkey)
	}

	// Feature Flags
	if os.Getenv("ENABLE_ZERO_VALUE_BLOCKS") != "" {
		api.log.Warn("env: ENABLE_ZERO_VALUE_BLOCKS: sending blocks with zero value")
		api.ffAllowZeroValueBlocks = true
	}

	if os.Getenv("SYNC_VALIDATOR_REGISTRATIONS") != "" {
		api.log.Warn("env: SYNC_VALIDATOR_REGISTRATIONS: enabling sync validator registrations")
		api.ffSyncValidatorRegistrations = true
	}

	if os.Getenv("ALLOW_BLOCK_VERIFICATION_FAIL") != "" {
		api.log.Warn("env: ALLOW_BLOCK_VERIFICATION_FAIL: allow failing block verification")
		api.ffAllowBlockVerificationFail = true
	}

	if os.Getenv("ALLOW_SYNCING_BEACON_NODE") != "" {
		api.log.Warn("env: ALLOW_SYNCING_BEACON_NODE: allow syncing beacon node")
		api.ffAllowSyncingBeaconNode = true
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
	r.HandleFunc(pathDataProposerPayloadDelivered, api.handleDataProposerPayloadDelivered).Methods(http.MethodGet)

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
		return ErrRegistrationWorkersAlreadyStarted
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
				log := api.log.WithFields(logrus.Fields{
					"pubkey": registration.Message.Pubkey.PubkeyHex(),
				})

				// Verify the signature
				ok, err := types.VerifySignature(registration.Message, api.opts.EthNetDetails.DomainBuilder, registration.Message.Pubkey[:], registration.Signature[:])
				if err != nil || !ok {
					log.WithError(err).Warn("failed to verify registerValidator signature")
					continue
				}

				// Save the registration and increment counter
				go func() {
					err := api.datastore.SetValidatorRegistration(registration)
					if err != nil {
						log.WithError(err).Error("Failed to set validator registration")
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
		return ErrServerAlreadyStarted
	}

	// Get best beacon-node status by head slot, process current slot and start slot updates
	bestSyncStatus, err := api.getBestSyncStatus()
	if err != nil {
		return err
	}

	// Start worker pool for validator registration processing
	err = api.startValidatorRegistrationWorkers()
	if err != nil {
		return err
	}

	// Get current proposer duties
	api.updateProposerDuties(bestSyncStatus.HeadSlot)

	// Update list of known validators, and start refresh loop
	go api.startKnownValidatorUpdates()

	// Process current slot
	api.processNewSlot(bestSyncStatus.HeadSlot)

	// Start regular slot updates
	go func() {
		c := make(chan beaconclient.HeadEventData)
		for _, client := range api.beaconClients {
			go client.SubscribeToHeadEvents(c)
		}
		for {
			headEvent := <-c
			api.processNewSlot(headEvent.Slot)
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
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (api *RelayAPI) getBestSyncStatus() (*beaconclient.SyncStatusPayloadData, error) {
	var bestSyncStatus *beaconclient.SyncStatusPayloadData
	var mu sync.Mutex
	var numSyncedNodes uint32

	// Check each beacon-node sync status
	var wg sync.WaitGroup
	for _, client := range api.beaconClients {
		wg.Add(1)
		go func(client beaconclient.BeaconNodeClient) {
			defer wg.Done()
			log := api.log.WithField("uri", client.GetURI())
			log.Debug("getting sync status")

			syncStatus, err := client.SyncStatus()
			if err != nil {
				log.WithError(err).Error("failed to get sync status")
				return
			}

			mu.Lock()
			defer mu.Unlock()

			if bestSyncStatus == nil || syncStatus.HeadSlot > bestSyncStatus.HeadSlot {
				bestSyncStatus = syncStatus
			}

			if !syncStatus.IsSyncing {
				atomic.AddUint32(&numSyncedNodes, 1)
			}
		}(client)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if numSyncedNodes == 0 && !api.ffAllowSyncingBeaconNode {
		return nil, ErrBeaconNodeSyncing
	}
	return bestSyncStatus, nil
}

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
	log := api.log.WithFields(logrus.Fields{
		"method": "registerValidator",
		"ip":     common.GetIPXForwardedFor(req),
	})

	respondError := func(code int, msg string) {
		log.Warn("bad request: ", msg)
		api.RespondError(w, code, msg)
	}

	start := time.Now()
	registrationTimeUpperBound := start.Add(10 * time.Second)

	registrations := []types.SignedValidatorRegistration{}
	numRegNew := 0

	if err := json.NewDecoder(req.Body).Decode(&registrations); err != nil {
		respondError(http.StatusBadRequest, "failed to decode payload")
		return
	}

	// Possible optimisations:
	// - GetValidatorRegistrationTimestamp could keep a cache in memory for some time and check memory first before going to Redis
	// - Do multiple loops and filter down set of registrations, and batch checks for all registrations instead of locking for each individually:
	//   (1) sanity checks, (2) IsKnownValidator, (3) CheckTimestamp, (4) Batch SetValidatorRegistration
	for _, registration := range registrations {
		if registration.Message == nil {
			respondError(http.StatusBadRequest, "registration without message")
			return
		}

		pubkey := registration.Message.Pubkey.PubkeyHex()
		regLog := api.log.WithFields(logrus.Fields{
			"pubkey": pubkey,
		})

		registrationTime := time.Unix(int64(registration.Message.Timestamp), 0)
		if registrationTime.After(registrationTimeUpperBound) {
			respondError(http.StatusBadRequest, "timestamp too far in the future")
			return
		}

		// Check if actually a real validator
		isKnownValidator := api.datastore.IsKnownValidator(pubkey)
		if !isKnownValidator {
			respondError(http.StatusBadRequest, fmt.Sprintf("not a known validator: %s", pubkey))
			return
		}

		// Check for a previous registration timestamp
		prevTimestamp, err := api.datastore.GetValidatorRegistrationTimestamp(pubkey)
		if err != nil {
			regLog.WithError(err).Infof("error getting last registration timestamp")
		}

		// Do nothing if the registration is already the latest
		if prevTimestamp >= registration.Message.Timestamp {
			continue
		}

		// Send to workers for signature verification and saving
		numRegNew++
		if api.ffSyncValidatorRegistrations {
			// Verify the signature
			ok, err := types.VerifySignature(registration.Message, api.opts.EthNetDetails.DomainBuilder, registration.Message.Pubkey[:], registration.Signature[:])
			if err != nil {
				regLog.WithError(err).Error("error verifying registerValidator signature")
				continue
			} else if !ok {
				api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("failed to verify validator signature for %s", registration.Message.Pubkey.String()))
				return
			} else {
				// Save and increment counter
				go func(reg types.SignedValidatorRegistration) {
					err := api.datastore.SetValidatorRegistration(reg)
					if err != nil {
						regLog.WithError(err).Error("Failed to set validator registration")
					}
				}(registration)
			}
		} else {
			// Send to channel for async processing
			api.regValEntriesC <- registration
		}
	}

	log = log.WithFields(logrus.Fields{
		"numRegistrations":    len(registrations),
		"numRegistrationsNew": numRegNew,
		"timeNeededSec":       time.Since(start).Seconds(),
	})
	log.Info("validator registrations call processed")
	w.WriteHeader(http.StatusOK)
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
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

	bid, err := api.datastore.GetBid(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		log.WithError(err).Error("could not get bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if bid == nil || bid.Data == nil || bid.Data.Message == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// If 0-value bid, only return if explicitly allowed
	if bid.Data.Message.Value.Cmp(&ZeroU256) == 0 && !api.ffAllowZeroValueBlocks {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.WithFields(logrus.Fields{
		"value":     bid.Data.Message.Value.String(),
		"blockHash": bid.Data.Message.Header.BlockHash.String(),
	}).Info("bid delivered")
	api.RespondOK(w, bid)
}

func (api *RelayAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := api.log.WithField("method", "getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log = log.WithFields(logrus.Fields{
		"slot":      payload.Message.Slot,
		"blockHash": strings.ToLower(payload.Message.Body.ExecutionPayloadHeader.BlockHash.String()),
		"idArg":     req.URL.Query().Get("id"),
		"ua":        req.UserAgent(),
	})

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
	log = log.WithFields(logrus.Fields{
		"numTx":       len(blockBidAndTrace.Payload.Data.Transactions),
		"blockNumber": payload.Message.Body.ExecutionPayloadHeader.BlockNumber,
	})
	log.Info("execution payload delivered")

	// Save payload and increment counter
	go func() {
		err := api.datastore.SaveDeliveredPayload(payload, blockBidAndTrace.Bid, blockBidAndTrace.Payload, blockBidAndTrace.Trace)
		if err != nil {
			log.WithError(err).Error("Failed to save delivered payload")
		}
	}()
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

	log = log.WithFields(logrus.Fields{
		"slot":      payload.Message.Slot,
		"builder":   payload.Message.BuilderPubkey.String(),
		"blockHash": payload.Message.BlockHash.String(),
	})

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
		log.WithError(err).Warn("block submission sanity checks failed")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify the signature
	ok, err := types.VerifySignature(payload.Message, api.opts.EthNetDetails.DomainBuilder, payload.Message.BuilderPubkey[:], payload.Signature[:])
	if !ok || err != nil {
		log.WithError(err).Warnf("could not verify builder signature")
		api.RespondError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	// Prepare entry for saving to database
	dbEntry, err := database.NewBuilderBlockEntry(payload)
	if err != nil {
		log.WithError(err).Error("failed creating BuilderBlockEntry")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Simulate the block submission and save to db
	simErr := api.blockSimRateLimiter.send(req.Context(), payload)
	if simErr != nil {
		log.WithError(simErr).Error("failed block simulation for block")
		dbEntry.SimError = simErr.Error()
	} else {
		dbEntry.SimSuccess = true
	}

	// Save builder submission to database (in the background)
	go func() {
		err = api.db.SaveBuilderBlockSubmission(dbEntry)
		if err != nil {
			log.WithError(err).Error("saving builder block submission to database failed")
		}
	}()

	// Return error if block verification failed
	if simErr != nil && !api.ffAllowBlockVerificationFail {
		api.RespondError(w, http.StatusBadRequest, simErr.Error())
		return
	}

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

	// Respond with OK (TODO: proper response format)
	w.WriteHeader(http.StatusOK)
}

// -----------
//  DATA APIS
// -----------

func (api *RelayAPI) handleDataProposerPayloadDelivered(w http.ResponseWriter, req *http.Request) {
	var err error
	args := req.URL.Query()

	filters := database.GetPayloadsFilters{
		IncludeBidTrace: true,
		Limit:           100,
	}

	if args.Get("slot") != "" {
		filters.Slot, err = strconv.ParseUint(args.Get("slot"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
	} else if args.Get("cursor") != "" {
		filters.Cursor, err = strconv.ParseUint(args.Get("cursor"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid cursor argument")
			return
		}
	}

	if args.Get("block_hash") != "" {
		var hash types.Hash
		err = hash.UnmarshalText([]byte(args.Get("block_hash")))
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_hash argument")
			return
		}
		filters.BlockHash = args.Get("block_hash")
	}

	if args.Get("block_number") != "" {
		filters.BlockNumber, err = strconv.ParseUint(args.Get("block_number"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_number argument")
			return
		}
	}

	if args.Get("limit") != "" {
		_limit, err := strconv.ParseUint(args.Get("limit"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid limit argument")
			return
		}
		if _limit > filters.Limit {
			api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("maximum limit is %d", filters.Limit))
			return
		}
		filters.Limit = _limit
	}

	payloads, err := api.db.GetRecentDeliveredPayloads(filters)
	if err != nil {
		api.log.WithError(err).Error("error getting recent payloads")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := []types.BidTrace{}
	for _, payload := range payloads {
		var trace types.BidTrace
		err = json.Unmarshal([]byte(payload.BidTrace), &trace)
		if err != nil {
			api.log.WithError(err).Error("failed to unmarshal bidtrace")
		} else {
			response = append(response, trace)
		}
	}

	api.RespondOK(w, response)
}
