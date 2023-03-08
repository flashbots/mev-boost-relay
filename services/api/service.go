// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/buger/jsonparser"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/go-redis/redis/v9"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

const ErrBlockAlreadyKnown = "simulation failed: block already known"

var (
	ErrMissingLogOpt              = errors.New("log parameter is nil")
	ErrMissingBeaconClientOpt     = errors.New("beacon-client is nil")
	ErrMissingDatastoreOpt        = errors.New("proposer datastore is nil")
	ErrRelayPubkeyMismatch        = errors.New("relay pubkey does not match existing one")
	ErrServerAlreadyStarted       = errors.New("server was already started")
	ErrBuilderAPIWithoutSecretKey = errors.New("cannot start builder API without secret key")
	ErrMismatchedForkVersions     = errors.New("can not find matching fork versions as retrieved from beacon node")
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
	pathDataBuilderBidsReceived      = "/relay/v1/data/bidtraces/builder_blocks_received"
	pathDataValidatorRegistration    = "/relay/v1/data/validator_registration"

	// Internal API
	pathInternalBuilderStatus     = "/internal/v1/builder/{pubkey:0x[a-fA-F0-9]+}"
	pathInternalBuilderCollateral = "/internal/v1/builder/collateral/{pubkey:0x[a-fA-F0-9]+}"

	// number of goroutines to save active validator
	numActiveValidatorProcessors = cli.GetEnvInt("NUM_ACTIVE_VALIDATOR_PROCESSORS", 10)
	numValidatorRegProcessors    = cli.GetEnvInt("NUM_VALIDATOR_REG_PROCESSORS", 10)
	timeoutGetPayloadRetryMs     = cli.GetEnvInt("GETPAYLOAD_RETRY_TIMEOUT_MS", 100)

	apiReadTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_READ_MS", 1500)
	apiReadHeaderTimeoutMs = cli.GetEnvInt("API_TIMEOUT_READHEADER_MS", 600)
	apiWriteTimeoutMs      = cli.GetEnvInt("API_TIMEOUT_WRITE_MS", 10000)
	apiIdleTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_IDLE_MS", 3000)
)

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr  string
	BlockSimURL string

	BeaconClient beaconclient.IMultiBeaconClient
	Datastore    *datastore.Datastore
	Redis        *datastore.RedisCache
	DB           database.IDatabaseService

	SecretKey *bls.SecretKey // used to sign bids (getHeader responses)

	// Network specific variables
	EthNetDetails common.EthNetworkDetails

	// APIs to enable
	ProposerAPI     bool
	BlockBuilderAPI bool
	DataAPI         bool
	PprofAPI        bool
	InternalAPI     bool
}

type randaoHelper struct {
	slot       uint64
	prevRandao string
}

type withdrawalsHelper struct {
	slot uint64
	root phase0.Root
}

// Data needed to issue a block validation request.
type blockSimOptions struct {
	isHighPrio bool
	log        *logrus.Entry
	req        *BuilderBlockValidationRequest
}

type blockBuilderCacheEntry struct {
	status     common.BuilderStatus
	collateral *big.Int
}

// RelayAPI represents a single Relay instance
type RelayAPI struct {
	opts RelayAPIOpts
	log  *logrus.Entry

	blsSk     *bls.SecretKey
	publicKey *boostTypes.PublicKey

	srv        *http.Server
	srvStarted uberatomic.Bool

	beaconClient beaconclient.IMultiBeaconClient
	datastore    *datastore.Datastore
	redis        *datastore.RedisCache
	db           database.IDatabaseService

	headSlot       uberatomic.Uint64
	genesisInfo    *beaconclient.GetGenesisResponse
	bellatrixEpoch uint64
	capellaEpoch   uint64

	proposerDutiesLock       sync.RWMutex
	proposerDutiesResponse   []boostTypes.BuilderGetValidatorsResponseEntry
	proposerDutiesMap        map[uint64]*boostTypes.RegisterValidatorRequestMessage
	proposerDutiesSlot       uint64
	isUpdatingProposerDuties uberatomic.Bool

	blockSimRateLimiter IBlockSimRateLimiter

	activeValidatorC chan boostTypes.PubkeyHex
	validatorRegC    chan boostTypes.SignedValidatorRegistration

	// used to wait on any active getPayload calls on shutdown
	getPayloadCallsInFlight sync.WaitGroup

	// Feature flags
	ffForceGetHeader204      bool
	ffDisableBlockPublishing bool
	ffDisableLowPrioBuilders bool

	expectedPrevRandao         randaoHelper
	expectedPrevRandaoLock     sync.RWMutex
	expectedPrevRandaoUpdating uint64

	expectedWithdrawalsRoot     withdrawalsHelper
	expectedWithdrawalsLock     sync.RWMutex
	expectedWithdrawalsUpdating uint64

	// The slot we are currently optimistically simulating.
	optimisticSlot uint64
	// The number of optimistic blocks being processed (only used for logging).
	optimisticBlocksInFlight uint64
	// Wait group used to monitor status of per-slot optimistic processing.
	optimisticBlocks sync.WaitGroup
	// Cache for builder statuses and collaterals.
	blockBuildersCache map[string]*blockBuilderCacheEntry
}

// NewRelayAPI creates a new service. if builders is nil, allow any builder
func NewRelayAPI(opts RelayAPIOpts) (api *RelayAPI, err error) {
	if opts.Log == nil {
		return nil, ErrMissingLogOpt
	}

	if opts.BeaconClient == nil {
		return nil, ErrMissingBeaconClientOpt
	}

	if opts.Datastore == nil {
		return nil, ErrMissingDatastoreOpt
	}

	// If block-builder API is enabled, then ensure secret key is all set
	var publicKey boostTypes.PublicKey
	if opts.BlockBuilderAPI {
		if opts.SecretKey == nil {
			return nil, ErrBuilderAPIWithoutSecretKey
		}

		// If using a secret key, ensure it's the correct one
		publicKey, err = boostTypes.BlsPublicKeyToPublicKey(bls.PublicKeyFromSecretKey(opts.SecretKey))
		if err != nil {
			return nil, err
		}
		opts.Log.Infof("Using BLS key: %s", publicKey.String())

		// ensure pubkey is same across all relay instances
		_pubkey, err := opts.Redis.GetRelayConfig(datastore.RedisConfigFieldPubkey)
		if err != nil {
			return nil, err
		} else if _pubkey == "" {
			err := opts.Redis.SetRelayConfig(datastore.RedisConfigFieldPubkey, publicKey.String())
			if err != nil {
				return nil, err
			}
		} else if _pubkey != publicKey.String() {
			return nil, fmt.Errorf("%w: new=%s old=%s", ErrRelayPubkeyMismatch, publicKey.String(), _pubkey)
		}
	}

	api = &RelayAPI{
		opts:                   opts,
		log:                    opts.Log,
		blsSk:                  opts.SecretKey,
		publicKey:              &publicKey,
		datastore:              opts.Datastore,
		beaconClient:           opts.BeaconClient,
		redis:                  opts.Redis,
		db:                     opts.DB,
		proposerDutiesResponse: []boostTypes.BuilderGetValidatorsResponseEntry{},
		blockSimRateLimiter:    NewBlockSimulationRateLimiter(opts.BlockSimURL),

		activeValidatorC: make(chan boostTypes.PubkeyHex, 450_000),
		validatorRegC:    make(chan boostTypes.SignedValidatorRegistration, 450_000),
	}

	if os.Getenv("FORCE_GET_HEADER_204") == "1" {
		api.log.Warn("env: FORCE_GET_HEADER_204 - forcing getHeader to always return 204")
		api.ffForceGetHeader204 = true
	}

	if os.Getenv("DISABLE_BLOCK_PUBLISHING") == "1" {
		api.log.Warn("env: DISABLE_BLOCK_PUBLISHING - disabling publishing blocks on getPayload")
		api.ffDisableBlockPublishing = true
	}

	if os.Getenv("DISABLE_LOWPRIO_BUILDERS") == "1" {
		api.log.Warn("env: DISABLE_LOWPRIO_BUILDERS - allowing only high-level builders")
		api.ffDisableLowPrioBuilders = true
	}

	return api, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)

	// Proposer API
	if api.opts.ProposerAPI {
		api.log.Info("proposer API enabled")
		r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
		r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
		r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
		r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)
	}

	// Builder API
	if api.opts.BlockBuilderAPI {
		api.log.Info("block builder API enabled")
		r.HandleFunc(pathBuilderGetValidators, api.handleBuilderGetValidators).Methods(http.MethodGet)
		r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodPost)
	}

	// Data API
	if api.opts.DataAPI {
		api.log.Info("data API enabled")
		r.HandleFunc(pathDataProposerPayloadDelivered, api.handleDataProposerPayloadDelivered).Methods(http.MethodGet)
		r.HandleFunc(pathDataBuilderBidsReceived, api.handleDataBuilderBidsReceived).Methods(http.MethodGet)
		r.HandleFunc(pathDataValidatorRegistration, api.handleDataValidatorRegistration).Methods(http.MethodGet)
	}

	// Pprof
	if api.opts.PprofAPI {
		api.log.Info("pprof API enabled")
		r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	}

	// /internal/...
	if api.opts.InternalAPI {
		api.log.Info("internal API enabled")
		r.HandleFunc(pathInternalBuilderStatus, api.handleInternalBuilderStatus).Methods(http.MethodGet, http.MethodPost, http.MethodPut)
		r.HandleFunc(pathInternalBuilderCollateral, api.handleInternalBuilderCollateral).Methods(http.MethodPost, http.MethodPut)
	}

	// r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(api.log, r)
	withGz := gziphandler.GzipHandler(loggedRouter)
	return withGz
}

func (api *RelayAPI) isCapella(slot uint64) bool {
	epoch := slot / uint64(common.SlotsPerEpoch)
	return epoch >= api.capellaEpoch
}

func (api *RelayAPI) isBellatrix(slot uint64) bool {
	epoch := slot / uint64(common.SlotsPerEpoch)
	return epoch >= api.bellatrixEpoch && epoch < api.capellaEpoch
}

// StartServer starts the HTTP server for this instance
func (api *RelayAPI) StartServer() (err error) {
	if api.srvStarted.Swap(true) {
		return ErrServerAlreadyStarted
	}

	// Get best beacon-node status by head slot, process current slot and start slot updates
	bestSyncStatus, err := api.beaconClient.BestSyncStatus()
	if err != nil {
		return err
	}

	// Initialize block builder cache.
	api.blockBuildersCache = make(map[string]*blockBuilderCacheEntry)

	api.genesisInfo, err = api.beaconClient.GetGenesis()
	if err != nil {
		return err
	}
	api.log.Infof("genesis info: %d", api.genesisInfo.Data.GenesisTime)

	forkSchedule, err := api.beaconClient.GetForkSchedule()
	if err != nil {
		return err
	}

	for _, fork := range forkSchedule.Data {
		switch fork.CurrentVersion {
		case api.opts.EthNetDetails.BellatrixForkVersionHex:
			api.bellatrixEpoch = fork.Epoch
		case api.opts.EthNetDetails.CapellaForkVersionHex:
			api.capellaEpoch = fork.Epoch
		}
	}

	currentSlot := bestSyncStatus.HeadSlot
	currentEpoch := currentSlot / uint64(common.SlotsPerEpoch)
	if api.isCapella(currentSlot) {
		api.log.Infof("capella fork detected, startEpoch: %d / currentEpoch: %d", api.capellaEpoch, currentEpoch)
	} else if api.isBellatrix(currentSlot) {
		api.log.Infof("bellatrix fork detected. capellaStartEpoch: %d / currentEpoch: %d", api.capellaEpoch, currentEpoch)
	} else {
		return ErrMismatchedForkVersions
	}

	// start things for the block-builder API
	if api.opts.BlockBuilderAPI {
		// Get current proposer duties blocking before starting, to have them ready
		api.updateProposerDuties(bestSyncStatus.HeadSlot)
	}

	// start things specific for the proposer API
	if api.opts.ProposerAPI {
		// Update list of known validators, and start refresh loop
		go api.startKnownValidatorUpdates()

		// Start the worker pool to process active validators
		api.log.Infof("starting %d active validator processors", numActiveValidatorProcessors)
		for i := 0; i < numActiveValidatorProcessors; i++ {
			go api.startActiveValidatorProcessor()
		}

		// Start the validator registration db-save processor
		api.log.Infof("starting %d validator registration processors", numValidatorRegProcessors)
		for i := 0; i < numValidatorRegProcessors; i++ {
			go api.startValidatorRegistrationDBProcessor()
		}
	}

	// Process current slot
	api.processNewSlot(bestSyncStatus.HeadSlot)

	// Start regular slot updates
	go func() {
		c := make(chan beaconclient.HeadEventData)
		api.beaconClient.SubscribeToHeadEvents(c)
		for {
			headEvent := <-c
			api.processNewSlot(headEvent.Slot)
		}
	}()

	api.srv = &http.Server{
		Addr:    api.opts.ListenAddr,
		Handler: api.getRouter(),

		ReadTimeout:       time.Duration(apiReadTimeoutMs) * time.Millisecond,
		ReadHeaderTimeout: time.Duration(apiReadHeaderTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(apiWriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       time.Duration(apiIdleTimeoutMs) * time.Millisecond,
	}

	err = api.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// StopServer disables sending any bids on getHeader calls, waits a few seconds to catch any remaining getPayload call, and then shuts down the webserver
func (api *RelayAPI) StopServer() (err error) {
	api.log.Info("Stopping server...")

	if api.opts.ProposerAPI {
		// stop sending bids
		api.ffForceGetHeader204 = true
		api.log.Info("Disabled sending bids, waiting a few seconds...")

		// wait a few seconds, for any pending getPayload call to complete
		time.Sleep(5 * time.Second)

		// wait for any active getPayload call to finish
		api.getPayloadCallsInFlight.Wait()
	}

	// shutdown
	return api.srv.Shutdown(context.Background())
}

// startActiveValidatorProcessor keeps listening on the channel and saving active validators to redis
func (api *RelayAPI) startActiveValidatorProcessor() {
	for pubkey := range api.activeValidatorC {
		err := api.redis.SetActiveValidator(pubkey)
		if err != nil {
			api.log.WithError(err).Infof("error setting active validator")
		}
	}
}

// startActiveValidatorProcessor keeps listening on the channel and saving active validators to redis
func (api *RelayAPI) startValidatorRegistrationDBProcessor() {
	for valReg := range api.validatorRegC {
		err := api.datastore.SaveValidatorRegistration(valReg)
		if err != nil {
			api.log.WithError(err).WithFields(logrus.Fields{
				"reg_pubkey":       valReg.Message.Pubkey,
				"reg_feeRecipient": valReg.Message.FeeRecipient,
				"reg_gasLimit":     valReg.Message.GasLimit,
				"reg_timestamp":    valReg.Message.Timestamp,
			}).Error("error saving validator registration")
		}
	}
}

// simulateBlock sends a request for a block simulation to blockSimRateLimiter.
func (api *RelayAPI) simulateBlock(ctx context.Context, opts blockSimOptions) error {
	t := time.Now()
	simErr := api.blockSimRateLimiter.send(ctx, opts.req, opts.isHighPrio)
	log := opts.log.WithFields(logrus.Fields{
		"duration":   time.Since(t).Seconds(),
		"numWaiting": api.blockSimRateLimiter.currentCounter(),
	})
	if simErr != nil && simErr.Error() != ErrBlockAlreadyKnown {
		log.WithError(simErr).Error("block validation failed")
		return simErr
	}
	log.Info("block validation successful")
	return nil
}

func (api *RelayAPI) demoteBuilder(pubkey string, req *common.BuilderSubmitBlockRequest, simError error) {
	builderEntry, ok := api.blockBuildersCache[pubkey]
	if !ok {
		api.log.Warnf("builder %v not in the builder cache", pubkey)
		builderEntry = &blockBuilderCacheEntry{}
	}
	newStatus := common.BuilderStatus{
		IsHighPrio:    builderEntry.status.IsHighPrio,
		IsBlacklisted: builderEntry.status.IsBlacklisted,
		IsOptimistic:  false,
	}
	api.log.Infof("demoted builder, new status: %v", newStatus)
	if err := api.db.SetBlockBuilderStatus(pubkey, newStatus); err != nil {
		api.log.Error(fmt.Errorf("error setting builder: %v status: %v", pubkey, err))
	}
	// Write to demotions table.
	api.log.WithFields(logrus.Fields{"builder_pubkey": pubkey}).Info("demoting builder")
	if err := api.db.InsertBuilderDemotion(req, simError); err != nil {
		api.log.WithError(err).WithFields(logrus.Fields{
			"errorWritingDemotionToDB": true,
			"bidTrace":                 req.Message,
			"simError":                 simError,
		}).Error("failed to save demotion to database")
	}
}

// processOptimisticBlock is called on a new goroutine when a optimistic block
// needs to be simulated.
func (api *RelayAPI) processOptimisticBlock(ctx context.Context, opts blockSimOptions) {
	api.optimisticBlocksInFlight += 1
	defer func() { api.optimisticBlocksInFlight -= 1 }()
	api.optimisticBlocks.Add(1)
	defer api.optimisticBlocks.Done()

	builderPubkey := opts.req.BuilderPubkey().String()
	opts.log.WithFields(logrus.Fields{
		"builderPubkey": builderPubkey,
		// NOTE: this value is just an estimate because many goroutines could be
		// updating api.optimisticBlocksInFlight concurrently. Since we just use
		// it for logging, it is not atomic to avoid the performance impact.
		"optBlocksInFlight": api.optimisticBlocksInFlight,
	}).Infof("simulating optimistic block with hash: %v", opts.req.BuilderSubmitBlockRequest.BlockHash())

	if simErr := api.simulateBlock(ctx, opts); simErr != nil {
		api.log.WithError(simErr).Error("block simulation failed in processOptimisticBlock, demoting builder")

		// Demote the builder.
		api.demoteBuilder(builderPubkey, &opts.req.BuilderSubmitBlockRequest, simErr)
	}
}

func (api *RelayAPI) processNewSlot(headSlot uint64) {
	_apiHeadSlot := api.headSlot.Load()
	if headSlot <= _apiHeadSlot {
		return
	}

	if _apiHeadSlot > 0 {
		for s := _apiHeadSlot + 1; s < headSlot; s++ {
			api.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	// store the head slot
	api.headSlot.Store(headSlot)

	// only for builder-api
	if api.opts.BlockBuilderAPI {
		// query the expected prev_randao field
		go api.updatedExpectedRandao(headSlot)

		// query expected withdrawals root
		go api.updatedExpectedWithdrawals(headSlot)

		// update proposer duties in the background
		go api.updateProposerDuties(headSlot)

		// update the optimistic slot
		go api.updateOptimisticSlot(headSlot)
	}

	// log
	epoch := headSlot / uint64(common.SlotsPerEpoch)
	api.log.WithFields(logrus.Fields{
		"epoch":              epoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (epoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot to %d", headSlot)
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
	dutiesMap := make(map[uint64]*boostTypes.RegisterValidatorRequestMessage)
	for _, duty := range duties {
		dutiesMap[duty.Slot] = duty.Entry.Message
	}

	if err == nil {
		api.proposerDutiesLock.Lock()
		api.proposerDutiesResponse = duties
		api.proposerDutiesMap = dutiesMap
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

func (api *RelayAPI) updateOptimisticSlot(headSlot uint64) {
	// Wait until there are no optimistic blocks being processed. Then we can
	// safely update the slot.
	api.optimisticBlocks.Wait()
	api.optimisticSlot = headSlot + 1

	builders, err := api.db.GetBlockBuilders()
	if err != nil {
		api.log.WithError(err).Error("unable to read block builders from db, not updating builder cache")
		return
	}
	for _, v := range builders {
		collStr := v.Collateral

		// Try to parse builder collateral string to big int.
		var builderCollateral big.Int
		err = builderCollateral.UnmarshalText([]byte(collStr))
		if err != nil {
			api.log.WithError(err).Error("could not parse builder collateral string")
			builderCollateral.SetInt64(0)
		}
		api.blockBuildersCache[v.BuilderPubkey] = &blockBuilderCacheEntry{
			status: common.BuilderStatus{
				IsHighPrio:    v.IsHighPrio,
				IsBlacklisted: v.IsBlacklisted,
				IsOptimistic:  v.IsOptimistic,
			},
			collateral: &builderCollateral,
		}
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

func (api *RelayAPI) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "MEV-Boost Relay API")
}

func (api *RelayAPI) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":    "registerValidator",
		"ua":        ua,
		"mevBoostV": common.GetMevBoostVersionFromUserAgent(ua),
	})

	start := time.Now()
	registrationTimeUpperBound := start.Add(10 * time.Second)

	numRegTotal := 0
	numRegProcessed := 0
	numRegActive := 0
	numRegNew := 0
	processingStoppedByError := false

	respondError := func(code int, msg string) {
		processingStoppedByError = true
		log.Warnf("error: %s", msg)
		api.RespondError(w, code, msg)
	}

	if req.ContentLength == 0 {
		respondError(http.StatusBadRequest, "empty request")
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.WithError(err).WithField("contentLength", req.ContentLength).Warn("failed to read request body")
		api.RespondError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	req.Body.Close()

	parseRegistration := func(value []byte) (pkHex boostTypes.PubkeyHex, timestampInt int64, err error) {
		pubkey, err := jsonparser.GetUnsafeString(value, "message", "pubkey")
		if err != nil {
			return pkHex, timestampInt, fmt.Errorf("registration message error (pubkey): %w", err)
		}

		timestamp, err := jsonparser.GetUnsafeString(value, "message", "timestamp")
		if err != nil {
			return pkHex, timestampInt, fmt.Errorf("registration message error (timestamp): %w", err)
		}

		timestampInt, err = strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return pkHex, timestampInt, fmt.Errorf("invalid timestamp: %w", err)
		}

		return boostTypes.PubkeyHex(pubkey), timestampInt, nil
	}

	// Iterate over the registrations
	_, err = jsonparser.ArrayEach(body, func(value []byte, dataType jsonparser.ValueType, offset int, _err error) {
		numRegTotal += 1
		if processingStoppedByError {
			return
		}
		numRegProcessed += 1

		// Extract immediately necessary registration fields
		pkHex, timestampInt, err := parseRegistration(value)
		if err != nil {
			respondError(http.StatusBadRequest, err.Error())
			return
		}

		// Add validator pubkey to logs
		regLog := api.log.WithField("pubkey", pkHex.String())

		// Ensure registration is not too far in the future
		registrationTime := time.Unix(timestampInt, 0)
		if registrationTime.After(registrationTimeUpperBound) {
			respondError(http.StatusBadRequest, "timestamp too far in the future")
			return
		}

		// Check if a real validator
		isKnownValidator := api.datastore.IsKnownValidator(pkHex)
		if !isKnownValidator {
			respondError(http.StatusBadRequest, fmt.Sprintf("not a known validator: %s", pkHex.String()))
			return
		}

		// Track active validators here
		numRegActive += 1
		select {
		case api.activeValidatorC <- pkHex:
		default:
			regLog.Error("active validator channel full")
		}

		// Check for a previous registration timestamp
		prevTimestamp, err := api.redis.GetValidatorRegistrationTimestamp(pkHex)
		if err != nil {
			regLog.WithError(err).Error("error getting last registration timestamp")
		} else if prevTimestamp >= uint64(timestampInt) {
			// abort if the current registration timestamp is older or equal to the last known one
			return
		}

		// Now we have a new registration to process
		numRegNew += 1

		// JSON-decode the registration now (needed for signature verification)
		signedValidatorRegistration := new(boostTypes.SignedValidatorRegistration)
		err = json.Unmarshal(value, signedValidatorRegistration)
		if err != nil {
			regLog.WithError(err).Error("error unmarshalling signed validator registration")
			respondError(http.StatusBadRequest, fmt.Sprintf("error unmarshalling signed validator registration: %s", err.Error()))
			return
		}

		// Verify the signature
		ok, err := boostTypes.VerifySignature(signedValidatorRegistration.Message, api.opts.EthNetDetails.DomainBuilder, signedValidatorRegistration.Message.Pubkey[:], signedValidatorRegistration.Signature[:])
		if err != nil {
			regLog.WithError(err).Error("error verifying registerValidator signature")
			respondError(http.StatusBadRequest, fmt.Sprintf("error verifying registerValidator signature: %s", err.Error()))
			return
		} else if !ok {
			api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("failed to verify validator signature for %s", signedValidatorRegistration.Message.Pubkey.String()))
			return
		}

		// Save to database
		select {
		case api.validatorRegC <- *signedValidatorRegistration:
		default:
			regLog.Error("validator registration channel full")
		}
	})

	if err != nil {
		respondError(http.StatusBadRequest, "error in traversing json")
		return
	}

	log = log.WithFields(logrus.Fields{
		"timeNeededSec":             time.Since(start).Seconds(),
		"numRegistrations":          numRegTotal,
		"numRegistrationsActive":    numRegActive,
		"numRegistrationsProcessed": numRegProcessed,
		"numRegistrationsNew":       numRegNew,
		"processingStoppedByError":  processingStoppedByError,
	})
	log.Info("validator registrations call processed")
	w.WriteHeader(http.StatusOK)
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slotStr := vars["slot"]
	parentHashHex := vars["parent_hash"]
	proposerPubkeyHex := vars["pubkey"]
	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slotStr,
		"parentHash": parentHashHex,
		"pubkey":     proposerPubkeyHex,
		"ua":         ua,
		"mevBoostV":  common.GetMevBoostVersionFromUserAgent(ua),
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

	if slot < api.headSlot.Load() {
		api.RespondError(w, http.StatusBadRequest, "slot is too old")
		return
	}

	log.Debug("getHeader request received")

	if api.ffForceGetHeader204 {
		log.Info("forced getHeader 204 response")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	bid, err := api.redis.GetBestBid(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		log.WithError(err).Error("could not get bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if bid.Empty() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Error on bid without value
	if bid.Value().Cmp(big.NewInt(0)) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.WithFields(logrus.Fields{
		"value":     bid.Value().String(),
		"blockHash": bid.BlockHash().String(),
	}).Info("bid delivered")
	api.RespondOK(w, bid)
}

func (api *RelayAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	signedAt := time.Now().UTC()
	api.getPayloadCallsInFlight.Add(1)
	defer api.getPayloadCallsInFlight.Done()

	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":        "getPayload",
		"ua":            ua,
		"mevBoostV":     common.GetMevBoostVersionFromUserAgent(ua),
		"contentLength": req.ContentLength,
		"headSlot":      api.headSlot.Load(),
	})

	// Read the body first, so we can decode it later
	body, err := io.ReadAll(req.Body)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			log.WithError(err).Error("getPayload request failed to decode (i/o timeout)")
			api.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		log.WithError(err).Error("could not read body of request from the beacon node")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload := new(common.SignedBlindedBeaconBlock)
	capellaPayload := new(capella.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(capellaPayload); err != nil {
		log.WithError(err).Debug("capella getPayload request failed to decode")
		bellatrixPayload := new(boostTypes.SignedBlindedBeaconBlock)
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(bellatrixPayload); err != nil {
			log.WithError(err).Warn("bellatrix getPayload request failed to decode")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		payload.Bellatrix = bellatrixPayload
	} else {
		payload.Capella = capellaPayload
	}

	log = log.WithFields(logrus.Fields{
		"slot":      payload.Slot(),
		"blockHash": payload.BlockHash(),
		"idArg":     req.URL.Query().Get("id"),
	})

	log.Debug("getPayload request received")

	proposerPubkey, found := api.datastore.GetKnownValidatorPubkeyByIndex(payload.ProposerIndex())
	if !found {
		log.Errorf("could not find proposer pubkey for index %d", payload.ProposerIndex())
		api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	log = log.WithField("pubkeyFromIndex", proposerPubkey)

	// Get the proposer pubkey based on the validator index from the payload
	pk, err := boostTypes.HexToPubkey(proposerPubkey.String())
	if err != nil {
		log.WithError(err).Warn("could not convert pubkey to types.PublicKey")
		api.RespondError(w, http.StatusBadRequest, "could not convert pubkey to types.PublicKey")
		return
	}

	// Attempt verifying the signature for capella
	ok, err := boostTypes.VerifySignature(payload.Message(), api.opts.EthNetDetails.DomainBeaconProposerCapella, pk[:], payload.Signature())
	if !ok || err != nil {
		log.WithError(err).Debug("could not verify capella payload signature, attempting to verify signature for bellatrix")
		// Attempt verifying the signature for bellatrix
		ok, err := boostTypes.VerifySignature(payload.Message(), api.opts.EthNetDetails.DomainBeaconProposerBellatrix, pk[:], payload.Signature())
		if !ok || err != nil {
			log.WithError(err).Warn("could not verify payload signature")
			api.RespondError(w, http.StatusBadRequest, "could not verify payload signature")
			return
		}
	}

	// Get the response - from memory, Redis or DB
	// note that mev-boost might send getPayload for bids of other relays, thus this code wouldn't find anything
	getPayloadResp, err := api.datastore.GetGetPayloadResponse(payload.Slot(), proposerPubkey.String(), payload.BlockHash())
	if err != nil || getPayloadResp == nil {
		log.WithError(err).Warn("failed getting execution payload (1/2)")
		time.Sleep(time.Duration(timeoutGetPayloadRetryMs) * time.Millisecond)

		// Try again
		getPayloadResp, err = api.datastore.GetGetPayloadResponse(payload.Slot(), proposerPubkey.String(), payload.BlockHash())
		if err != nil {
			log.WithError(err).Error("failed getting execution payload (2/2) - due to error")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		} else if getPayloadResp == nil {
			log.Warn("failed getting execution payload (2/2)")
			api.RespondError(w, http.StatusBadRequest, "no execution payload for this request")
			return
		}
	}

	api.RespondOK(w, getPayloadResp)
	log = log.WithFields(logrus.Fields{
		"numTx":       getPayloadResp.NumTx(),
		"blockNumber": payload.BlockNumber(),
	})
	log.Info("execution payload delivered")

	// Save information about delivered payload
	go func() {
		err = api.redis.SetStats(datastore.RedisStatsFieldSlotLastPayloadDelivered, payload.Slot())
		if err != nil {
			log.WithError(err).Error("failed to save delivered payload slot to redis")
		}

		bidTrace, err := api.redis.GetBidTrace(payload.Slot(), proposerPubkey.String(), payload.BlockHash())
		if err != nil {
			log.WithError(err).Error("failed to get bidTrace for delivered payload from redis")
		}

		err = api.db.SaveDeliveredPayload(bidTrace, payload, signedAt)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"bidTrace": bidTrace,
				"payload":  payload,
			}).Error("failed to save delivered payload")
		}

		// Increment builder stats
		err = api.db.IncBlockBuilderStatsAfterGetPayload(bidTrace.BuilderPubkey.String())
		if err != nil {
			log.WithError(err).Error("failed to increment builder-stats after getPayload")
		}

		// Wait until optimistic blocks are complete.
		api.optimisticBlocks.Wait()

		// Check if there is a demotion for the winning block.
		_, err = api.db.GetBuilderDemotion(bidTrace)
		// If demotion not found, we are done!
		if errors.Is(err, sql.ErrNoRows) {
			log.Info("no demotion in getPayload, successful block proposal")
			return
		}
		if err != nil {
			log.WithError(err).Error("failed to read demotion table in getPayload")
			return
		}
		// Demotion found, update the demotion table with refund data.
		builderPubkey := bidTrace.BuilderPubkey.String()
		log = log.WithFields(logrus.Fields{
			"builderPubkey": builderPubkey,
			"slot":          bidTrace.Slot,
			"blockHash":     bidTrace.BlockHash,
		})
		log.Error("demotion found in getPayload, inserting refund justification")

		// Prepare refund data.
		signedBeaconBlock := SignedBlindedBeaconBlockToBeaconBlock(payload, getPayloadResp)

		// Get registration entry from the DB.
		registrationEntry, err := api.db.GetValidatorRegistration(proposerPubkey.String())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.WithError(err).Error("no registration found for validator " + proposerPubkey.String())
			} else {
				log.WithError(err).Error("error reading validator registration")
			}
		}
		var signedRegistration *boostTypes.SignedValidatorRegistration
		if registrationEntry != nil {
			signedRegistration, err = registrationEntry.ToSignedValidatorRegistration()
			if err != nil {
				log.WithError(err).Error("error converting registration to signed registration")
			}
		}

		err = api.db.UpdateBuilderDemotion(bidTrace, signedBeaconBlock, signedRegistration)
		if err != nil {
			log.WithFields(logrus.Fields{
				"errorWritingRefundToDB": true,
				"bidTrace":               bidTrace,
				"signedBeaconBlock":      signedBeaconBlock,
				"signedRegistration":     signedRegistration,
			}).WithError(err).Error("unable to update builder demotion with refund justification")
		}
	}()

	// Publish the signed beacon block via beacon-node
	go func() {
		if api.ffDisableBlockPublishing {
			log.Info("publishing the block is disabled")
			return
		}
		signedBeaconBlock := SignedBlindedBeaconBlockToBeaconBlock(payload, getPayloadResp)
		_, _ = api.beaconClient.PublishBlock(signedBeaconBlock) // errors are logged inside
	}()
}

// --------------------
//  BLOCK BUILDER APIS
// --------------------

// updatedExpectedRandao updates the prev_randao field we expect from builder block submissions
func (api *RelayAPI) updatedExpectedRandao(slot uint64) {
	log := api.log.WithField("slot", slot)
	log.Infof("updating randao...")
	api.expectedPrevRandaoLock.Lock()
	latestKnownSlot := api.expectedPrevRandao.slot
	if slot < latestKnownSlot || slot <= api.expectedPrevRandaoUpdating { // do nothing slot is already known or currently being updated
		log.Debugf("- abort updating randao, latest: %d, updating: %d", latestKnownSlot, api.expectedPrevRandaoUpdating)
		api.expectedPrevRandaoLock.Unlock()
		return
	}
	api.expectedPrevRandaoUpdating = slot
	api.expectedPrevRandaoLock.Unlock()

	// get randao from BN
	log.Debugf("- querying BN for randao")
	randao, err := api.beaconClient.GetRandao(slot)
	if err != nil {
		log.WithError(err).Error("failed to get randao from beacon node")
		api.expectedPrevRandaoLock.Lock()
		api.expectedPrevRandaoUpdating = 0
		api.expectedPrevRandaoLock.Unlock()
		return
	}

	// after request, check if still the latest, then update
	api.expectedPrevRandaoLock.Lock()
	defer api.expectedPrevRandaoLock.Unlock()
	targetSlot := slot + 1
	log.Debugf("- after BN randao: targetSlot: %d latest: %d", targetSlot, api.expectedPrevRandao.slot)

	// update if still the latest
	if targetSlot >= api.expectedPrevRandao.slot {
		api.expectedPrevRandao = randaoHelper{
			slot:       targetSlot, // the retrieved prev_randao is for the next slot
			prevRandao: randao.Data.Randao,
		}
		log.Infof("updated expected prev_randao to %s for slot %d", randao.Data.Randao, targetSlot)
	}
}

// updatedExpectedWithdrawals updates the withdrawals field we expect from builder block submissions
func (api *RelayAPI) updatedExpectedWithdrawals(slot uint64) {
	if api.isBellatrix(slot) {
		return
	}

	log := api.log.WithField("slot", slot)
	log.Infof("updating withdrawals root...")
	api.expectedWithdrawalsLock.Lock()
	latestKnownSlot := api.expectedWithdrawalsRoot.slot
	if slot < latestKnownSlot || slot <= api.expectedWithdrawalsUpdating { // do nothing slot is already known or currently being updated
		log.Debugf("- abort updating withdrawals root, latest: %d, updating: %d", latestKnownSlot, api.expectedWithdrawalsUpdating)
		api.expectedWithdrawalsLock.Unlock()
		return
	}
	api.expectedWithdrawalsUpdating = slot
	api.expectedWithdrawalsLock.Unlock()

	// get withdrawals from BN
	log.Debugf("- querying BN for withdrawals for slot %d", slot)
	withdrawals, err := api.beaconClient.GetWithdrawals(slot)
	if err != nil {
		if errors.Is(err, beaconclient.ErrWithdrawalsBeforeCapella) {
			log.WithError(err).Debug("attempted to fetch withdrawals before capella")
		} else {
			log.WithError(err).Error("failed to get withdrawals from beacon node")
		}
		api.expectedWithdrawalsLock.Lock()
		api.expectedWithdrawalsUpdating = 0
		api.expectedWithdrawalsLock.Unlock()
		return
	}

	// after request, check if still the latest, then update
	api.expectedWithdrawalsLock.Lock()
	defer api.expectedWithdrawalsLock.Unlock()
	targetSlot := slot + 1
	log.Debugf("- after BN withdrawals: targetSlot: %d latest: %d", targetSlot, api.expectedWithdrawalsRoot.slot)

	// update if still the latest
	if targetSlot >= api.expectedWithdrawalsRoot.slot {
		withdrawalsRoot, err := ComputeWithdrawalsRoot(withdrawals.Data.Withdrawals)
		if err != nil {
			log.WithError(err).Warn("failed to compute withdrawals root")
			api.expectedWithdrawalsUpdating = 0
			return
		}
		api.expectedWithdrawalsRoot = withdrawalsHelper{
			slot: targetSlot, // the retrieved withdrawals is for the next slot
			root: withdrawalsRoot,
		}
		log.Infof("updated expected withdrawals root to %s for slot %d", withdrawalsRoot, targetSlot)
	}
}

func (api *RelayAPI) handleBuilderGetValidators(w http.ResponseWriter, req *http.Request) {
	api.proposerDutiesLock.RLock()
	defer api.proposerDutiesLock.RUnlock()
	api.RespondOK(w, api.proposerDutiesResponse)
}

func (api *RelayAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	var pf common.Profile
	var prevTime, nextTime time.Time

	receivedAt := time.Now().UTC()
	prevTime = receivedAt
	log := api.log.WithFields(logrus.Fields{
		"method":        "submitNewBlock",
		"contentLength": req.ContentLength,
	})

	var err error
	var r io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		r, err = gzip.NewReader(req.Body)
		if err != nil {
			log.WithError(err).Warn("could not create gzip reader")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log = log.WithField("gzip-req", true)
	}

	payload := new(common.BuilderSubmitBlockRequest)
	if err := json.NewDecoder(r).Decode(payload); err != nil {
		log.WithError(err).Warn("could not decode payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if payload.Message() == nil || !payload.HasExecutionPayload() {
		api.RespondError(w, http.StatusBadRequest, "missing parts of the payload")
		return
	}

	currentSlot := api.headSlot.Load()
	if api.isCapella(currentSlot) && payload.Capella == nil {
		log.Info("rejecting submission - non capella payload for capella fork")
		api.RespondError(w, http.StatusBadRequest, "not capella payload")
	} else if api.isBellatrix(currentSlot) && payload.Bellatrix == nil {
		log.Info("rejecting submission - non bellatrix payload for bellatrix fork")
		api.RespondError(w, http.StatusBadRequest, "not belltrix payload")
	}

	nextTime = time.Now().UTC()
	pf.Decode = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	log = log.WithFields(logrus.Fields{
		"slot":          payload.Slot(),
		"builderPubkey": payload.BuilderPubkey().String(),
		"blockHash":     payload.BlockHash(),
	})

	// Reject new submissions once the payload for this slot was delivered
	slotStr, err := api.redis.GetStats(datastore.RedisStatsFieldSlotLastPayloadDelivered)
	if err != nil && !errors.Is(err, redis.Nil) {
		log.WithError(err).Error("failed to get delivered payload slot from redis")
	} else {
		slotLastPayloadDelivered, err := strconv.ParseUint(slotStr, 10, 64)
		if err != nil {
			log.WithError(err).Errorf("failed to parse delivered payload slot from redis: %s", slotStr)
		} else if payload.Slot() <= slotLastPayloadDelivered {
			log.Info("rejecting submission because payload for this slot was already delivered")
			api.RespondError(w, http.StatusBadRequest, "payload for this slot was already delivered")
			return
		}
	}

	if payload.Slot() <= api.headSlot.Load() {
		api.log.Info("submitNewBlock failed: submission for past slot")
		api.RespondError(w, http.StatusBadRequest, "submission for past slot")
		return
	}

	if payload.Slot() > api.headSlot.Load()+1 {
		api.log.Info("submitNewBlock failed: submission for future slot")
		api.RespondError(w, http.StatusBadRequest, "submission for future slot")
		return
	}

	builderPubkey := payload.BuilderPubkey()
	builderEntry, ok := api.blockBuildersCache[builderPubkey.String()]
	if !ok {
		log.Warnf("unable to read builder: %x from the builder cache, using low-prio and no collateral", builderPubkey.String())
		builderEntry = &blockBuilderCacheEntry{
			status: common.BuilderStatus{
				IsHighPrio: false,
			},
			collateral: big.NewInt(0),
		}
	}
	log = log.WithFields(logrus.Fields{
		"builderEntry": builderEntry,
	})

	// Timestamp check
	expectedTimestamp := api.genesisInfo.Data.GenesisTime + (payload.Slot() * 12)
	if payload.Timestamp() != expectedTimestamp {
		log.Warnf("incorrect timestamp. got %d, expected %d", payload.Timestamp(), expectedTimestamp)
		api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("incorrect timestamp. got %d, expected %d", payload.Timestamp(), expectedTimestamp))
		return
	}

	// ensure correct feeRecipient is used
	api.proposerDutiesLock.RLock()
	slotDuty := api.proposerDutiesMap[payload.Slot()]
	api.proposerDutiesLock.RUnlock()
	if slotDuty == nil {
		log.Warn("could not find slot duty")
		api.RespondError(w, http.StatusBadRequest, "could not find slot duty")
		return
	} else if slotDuty.FeeRecipient.String() != payload.ProposerFeeRecipient() {
		log.Info("fee recipient does not match")
		api.RespondError(w, http.StatusBadRequest, "fee recipient does not match")
		return
	}

	if builderEntry.status.IsBlacklisted {
		log.Info("builder is blacklisted")
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		return
	}

	// In case only high-prio requests are accepted, fail others
	if api.ffDisableLowPrioBuilders && !builderEntry.status.IsHighPrio {
		log.Info("rejecting low-prio builder (ff-disable-low-prio-builders)")
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		return
	}

	log = log.WithFields(logrus.Fields{
		"proposerPubkey": payload.ProposerPubkey(),
		"parentHash":     payload.ParentHash(),
		"value":          payload.Value().String(),
		"tx":             payload.NumTx(),
	})

	// Don't accept blocks with 0 value
	if payload.Value().Cmp(ZeroU256.BigInt()) == 0 || payload.NumTx() == 0 {
		api.log.Info("submitNewBlock failed: block with 0 value or no txs")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Sanity check the submission
	err = SanityCheckBuilderBlockSubmission(payload)
	if err != nil {
		log.WithError(err).Info("block submission sanity checks failed")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// get the latest randao and check its slot
	api.expectedPrevRandaoLock.RLock()
	expectedRandao := api.expectedPrevRandao
	api.expectedPrevRandaoLock.RUnlock()
	if expectedRandao.slot != payload.Slot() {
		log.Warn("prev_randao is not known yet")
		api.RespondError(w, http.StatusInternalServerError, "prev_randao is not known yet")
		return
	} else if expectedRandao.prevRandao != payload.Random() {
		msg := fmt.Sprintf("incorrect prev_randao - got: %s, expected: %s", payload.Random(), expectedRandao.prevRandao)
		log.Info(msg)
		api.RespondError(w, http.StatusBadRequest, msg)
		return
	}

	withdrawals := payload.Withdrawals()
	if withdrawals != nil {
		// get latest withdrawals and verify the roots match
		api.expectedWithdrawalsLock.RLock()
		expectedWithdrawalsRoot := api.expectedWithdrawalsRoot
		api.expectedWithdrawalsLock.RUnlock()
		withdrawalsRoot, err := ComputeWithdrawalsRoot(payload.Withdrawals())
		if err != nil {
			log.WithError(err).Warn("could not compute withdrawals root from payload")
			api.RespondError(w, http.StatusBadRequest, "could not compute withdrawals root")
			return
		}
		if expectedWithdrawalsRoot.slot != payload.Slot() {
			log.Warn("withdrawals are not known yet")
			api.RespondError(w, http.StatusInternalServerError, "withdrawals are not known yet")
			return
		} else if expectedWithdrawalsRoot.root != withdrawalsRoot {
			msg := fmt.Sprintf("incorrect withdrawals root - got: %s, expected: %s", withdrawalsRoot.String(), expectedWithdrawalsRoot.root.String())
			log.Info(msg)
			api.RespondError(w, http.StatusBadRequest, msg)
			return
		}
	}

	// Verify the signature
	signature := payload.Signature()
	ok, err = boostTypes.VerifySignature(payload.Message(), api.opts.EthNetDetails.DomainBuilder, builderPubkey[:], signature[:])
	if !ok || err != nil {
		log.WithError(err).Warn("could not verify builder signature")
		api.RespondError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	var simErr error
	var optimisticSubmission bool
	var eligibleAt time.Time

	// At end of this function, save builder submission to database (in the background)
	defer func() {
		submissionEntry, err := api.db.SaveBuilderBlockSubmission(payload, simErr, receivedAt, eligibleAt, pf, optimisticSubmission)
		if err != nil {
			log.WithError(err).WithField("payload", payload).Error("saving builder block submission to database failed")
			return
		}

		err = api.db.UpsertBlockBuilderEntryAfterSubmission(submissionEntry, simErr != nil)
		if err != nil {
			log.WithError(err).Error("failed to upsert block-builder-entry")
		}
	}()

	nextTime = time.Now().UTC()
	pf.Prechecks = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	// Construct simulation request.
	opts := blockSimOptions{
		isHighPrio: builderEntry.status.IsHighPrio,
		log:        log,
		req: &BuilderBlockValidationRequest{
			BuilderSubmitBlockRequest: *payload,
			RegisteredGasLimit:        slotDuty.GasLimit,
		},
	}

	// With sufficient collateral, process the block optimistically.
	if builderEntry.collateral.Cmp(payload.Value()) > 0 &&
		builderEntry.status.IsOptimistic &&
		payload.Slot() == api.optimisticSlot {
		optimisticSubmission = true
		go api.processOptimisticBlock(req.Context(), opts)
	} else {
		// Simulate block (synchronously).
		simErr = api.simulateBlock(req.Context(), opts)
		if simErr != nil {
			api.RespondError(w, http.StatusBadRequest, simErr.Error())
			return
		}
	}

	nextTime = time.Now().UTC()
	pf.Simulation = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	// Ensure this request is still the latest one
	latestPayloadReceivedAt, err := api.redis.GetBuilderLatestPayloadReceivedAt(payload.Slot(), payload.BuilderPubkey().String(), payload.ParentHash(), payload.ProposerPubkey())
	if err != nil {
		log.WithError(err).Error("failed getting latest payload receivedAt from redis")
	} else if receivedAt.UnixMilli() < latestPayloadReceivedAt {
		log.Infof("already have a newer payload: now=%d / prev=%d", receivedAt.UnixMilli(), latestPayloadReceivedAt)
		api.RespondError(w, http.StatusBadRequest, "already using a newer payload")
		return
	}

	// Prepare the response data
	getHeaderResponse, err := BuildGetHeaderResponse(payload, api.blsSk, api.publicKey, api.opts.EthNetDetails.DomainBuilder)
	if err != nil {
		log.WithError(err).Error("could not sign builder bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	getPayloadResponse, err := BuildGetPayloadResponse(payload)
	if err != nil {
		log.WithError(err).Error("could not build getPayload response")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	bidTrace := common.BidTraceV2{
		BidTrace:    *payload.Message(),
		BlockNumber: payload.BlockNumber(),
		NumTx:       uint64(payload.NumTx()),
	}

	//
	// Save to Redis
	//
	// first the trace
	err = api.redis.SaveBidTrace(&bidTrace)
	if err != nil {
		log.WithError(err).Error("failed saving bidTrace in redis")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// save execution payload (getPayload response)
	err = api.redis.SaveExecutionPayload(payload.Slot(), payload.ProposerPubkey(), payload.BlockHash(), getPayloadResponse)
	if err != nil {
		log.WithError(err).Error("failed saving execution payload in redis")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// save this builder's latest bid
	err = api.redis.SaveLatestBuilderBid(payload.Slot(), payload.BuilderPubkey().String(), payload.ParentHash(), payload.ProposerPubkey(), receivedAt, getHeaderResponse)
	if err != nil {
		log.WithError(err).Error("could not save latest builder bid")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// recalculate top bid
	err = api.redis.UpdateTopBid(payload.Slot(), payload.ParentHash(), payload.ProposerPubkey())
	if err != nil {
		log.WithError(err).Error("could not compute top bid")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// this bid is now elligible to win the auction
	nextTime = time.Now().UTC()
	eligibleAt = nextTime
	pf.RedisUpdate = uint64(nextTime.Sub(prevTime).Microseconds())
	pf.Total = uint64(nextTime.Sub(receivedAt).Microseconds())

	//
	// all done
	//
	log.WithFields(logrus.Fields{
		"proposerPubkey": payload.ProposerPubkey(),
		"value":          payload.Value().String(),
		"tx":             payload.NumTx(),
		"profile":        pf.String(),
	}).Info("received block from builder")

	// Respond with OK (TODO: proper response data type https://flashbots.notion.site/Relay-API-Spec-5fb0819366954962bc02e81cb33840f5#fa719683d4ae4a57bc3bf60e138b0dc6)
	w.WriteHeader(http.StatusOK)
}

// ---------------
//  INTERNAL APIS
// ---------------

func (api *RelayAPI) handleInternalBuilderStatus(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	builderPubkey := vars["pubkey"]

	if req.Method == http.MethodGet {
		builderEntry, err := api.db.GetBlockBuilderByPubkey(builderPubkey)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				api.RespondError(w, http.StatusBadRequest, "builder not found")
				return
			}

			api.log.WithError(err).Error("could not get block builder")
			api.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		api.RespondOK(w, builderEntry)
		return
	} else if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		args := req.URL.Query()
		trueStr := "true"
		isHighPrio := args.Get("high_prio") == trueStr
		isBlacklisted := args.Get("blacklisted") == trueStr
		isOptimistic := args.Get("optimistic") == trueStr
		api.log.WithFields(logrus.Fields{
			"builderPubkey": builderPubkey,
			"isHighPrio":    isHighPrio,
			"isBlacklisted": isBlacklisted,
			"isOptimistic":  isOptimistic,
		}).Info("updating builder status")
		newStatus := common.BuilderStatus{
			IsHighPrio:    isHighPrio,
			IsBlacklisted: isBlacklisted,
			IsOptimistic:  isOptimistic,
		}
		err := api.db.SetBlockBuilderStatus(builderPubkey, newStatus)
		if err != nil {
			err := fmt.Errorf("error setting builder: %v status: %v", builderPubkey, err)
			api.log.Error(err)
			api.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		api.RespondOK(w, newStatus)
	}
}

func (api *RelayAPI) handleInternalBuilderCollateral(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	builderPubkey := vars["pubkey"]
	if req.Method == http.MethodPost || req.Method == http.MethodPut {
		args := req.URL.Query()
		collateral := args.Get("collateral")
		value := args.Get("value")
		log := api.log.WithFields(logrus.Fields{
			"pubkey":     builderPubkey,
			"collateral": collateral,
			"value":      value,
		})
		log.Infof("updating builder collateral")
		if err := api.db.SetBlockBuilderCollateral(builderPubkey, collateral, value); err != nil {
			fullErr := fmt.Errorf("unable to set collateral in db for pubkey: %v: %v", builderPubkey, err)
			log.Error(fullErr.Error())
			api.RespondError(w, http.StatusInternalServerError, fullErr.Error())
			return
		}
		api.RespondOK(w, NilResponse)
	}
}

// -----------
//  DATA APIS
// -----------

func (api *RelayAPI) handleDataProposerPayloadDelivered(w http.ResponseWriter, req *http.Request) {
	var err error
	args := req.URL.Query()

	filters := database.GetPayloadsFilters{
		Limit: 200,
	}

	if args.Get("slot") != "" && args.Get("cursor") != "" {
		api.RespondError(w, http.StatusBadRequest, "cannot specify both slot and cursor")
		return
	} else if args.Get("slot") != "" {
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
		var hash boostTypes.Hash
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

	if args.Get("proposer_pubkey") != "" {
		if err = checkBLSPublicKeyHex(args.Get("proposer_pubkey")); err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid proposer_pubkey argument")
			return
		}
		filters.ProposerPubkey = args.Get("proposer_pubkey")
	}

	if args.Get("builder_pubkey") != "" {
		if err = checkBLSPublicKeyHex(args.Get("builder_pubkey")); err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid builder_pubkey argument")
			return
		}
		filters.BuilderPubkey = args.Get("builder_pubkey")
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

	if args.Get("order_by") == "value" {
		filters.OrderByValue = 1
	} else if args.Get("order_by") == "-value" {
		filters.OrderByValue = -1
	}

	deliveredPayloads, err := api.db.GetRecentDeliveredPayloads(filters)
	if err != nil {
		api.log.WithError(err).Error("error getting recent payloads")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]common.BidTraceV2JSON, len(deliveredPayloads))
	for i, payload := range deliveredPayloads {
		response[i] = database.DeliveredPayloadEntryToBidTraceV2JSON(payload)
	}

	api.RespondOK(w, response)
}

func (api *RelayAPI) handleDataBuilderBidsReceived(w http.ResponseWriter, req *http.Request) {
	var err error
	args := req.URL.Query()

	filters := database.GetBuilderSubmissionsFilters{
		Limit:         500,
		Slot:          0,
		BlockHash:     "",
		BlockNumber:   0,
		BuilderPubkey: "",
	}

	if args.Get("cursor") != "" {
		api.RespondError(w, http.StatusBadRequest, "cursor argument not supported")
		return
	}

	if args.Get("slot") != "" {
		filters.Slot, err = strconv.ParseUint(args.Get("slot"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
	}

	if args.Get("block_hash") != "" {
		var hash boostTypes.Hash
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

	if args.Get("builder_pubkey") != "" {
		if err = checkBLSPublicKeyHex(args.Get("builder_pubkey")); err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid builder_pubkey argument")
			return
		}
		filters.BuilderPubkey = args.Get("builder_pubkey")
	}

	// at least one query arguments is required
	if filters.Slot == 0 && filters.BlockHash == "" && filters.BlockNumber == 0 && filters.BuilderPubkey == "" {
		api.RespondError(w, http.StatusBadRequest, "need to query for specific slot or block_hash or block_number or builder_pubkey")
		return
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

	blockSubmissions, err := api.db.GetBuilderSubmissions(filters)
	if err != nil {
		api.log.WithError(err).Error("error getting recent payloads")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]common.BidTraceV2WithTimestampJSON, len(blockSubmissions))
	for i, payload := range blockSubmissions {
		response[i] = database.BuilderSubmissionEntryToBidTraceV2WithTimestampJSON(payload)
	}

	api.RespondOK(w, response)
}

func (api *RelayAPI) handleDataValidatorRegistration(w http.ResponseWriter, req *http.Request) {
	pkStr := req.URL.Query().Get("pubkey")
	if pkStr == "" {
		api.RespondError(w, http.StatusBadRequest, "missing pubkey argument")
		return
	}

	var pk boostTypes.PublicKey
	err := pk.UnmarshalText([]byte(pkStr))
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, "invalid pubkey")
		return
	}

	registrationEntry, err := api.db.GetValidatorRegistration(pkStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			api.RespondError(w, http.StatusBadRequest, "no registration found for validator "+pkStr)
			return
		}
		api.log.WithError(err).Error("error getting validator registration")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	signedRegistration, err := registrationEntry.ToSignedValidatorRegistration()
	if err != nil {
		api.log.WithError(err).Error("error converting registration entry to signed validator registration")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	api.RespondOK(w, signedRegistration)
}
