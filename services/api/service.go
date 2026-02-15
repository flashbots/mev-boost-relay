// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	_ "net/http/pprof"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/aohorodnyk/mimeheader"
	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/buger/jsonparser"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/flashbots/mev-boost-relay/metrics"
	"github.com/goccy/go-json"
	"github.com/gorilla/mux"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	otelapi "go.opentelemetry.io/otel/metric"
	uberatomic "go.uber.org/atomic"
)

type HandleGetPayloadVersion string

const (
	ErrBlockAlreadyKnown  = "simulation failed: block already known"
	ErrBlockRequiresReorg = "simulation failed: block requires a reorg"
	ErrMissingTrieNode    = "missing trie node"

	HeaderAccept              = "Accept"
	HeaderContentType         = "Content-Type"
	HeaderEthConsensusVersion = "Eth-Consensus-Version"

	HandleGetPayloadVersionV1 HandleGetPayloadVersion = "V1"
	HandleGetPayloadVersionV2 HandleGetPayloadVersion = "V2"
)

var (
	ErrMissingLogOpt              = errors.New("log parameter is nil")
	ErrMissingBeaconClientOpt     = errors.New("beacon-client is nil")
	ErrMissingDatastoreOpt        = errors.New("proposer datastore is nil")
	ErrRelayPubkeyMismatch        = errors.New("relay pubkey does not match existing one")
	ErrServerAlreadyStarted       = errors.New("server was already started")
	ErrBuilderAPIWithoutSecretKey = errors.New("cannot start builder API without secret key")
	ErrInvalidForkVersion         = errors.New("invalid fork version")
)

var (
	// Proposer API (builder-specs)
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayloadV1      = "/eth/v1/builder/blinded_blocks"
	pathGetPayloadV2      = "/eth/v2/builder/blinded_blocks"

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
	numValidatorRegProcessors = cli.GetEnvInt("NUM_VALIDATOR_REG_PROCESSORS", 10)

	// various timings
	timeoutGetPayloadRetryMs  = cli.GetEnvInt("GETPAYLOAD_RETRY_TIMEOUT_MS", 100)
	getHeaderRequestCutoffMs  = cli.GetEnvInt("GETHEADER_REQUEST_CUTOFF_MS", 3000)
	getPayloadRequestCutoffMs = cli.GetEnvInt("GETPAYLOAD_REQUEST_CUTOFF_MS", 4000)
	getPayloadResponseDelayMs = cli.GetEnvInt("GETPAYLOAD_RESPONSE_DELAY_MS", 1000)

	// api settings
	apiReadTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_READ_MS", 1500)
	apiReadHeaderTimeoutMs = cli.GetEnvInt("API_TIMEOUT_READHEADER_MS", 600)
	apiIdleTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_IDLE_MS", 3_000)
	apiWriteTimeoutMs      = cli.GetEnvInt("API_TIMEOUT_WRITE_MS", 10_000)
	apiMaxHeaderBytes      = cli.GetEnvInt("API_MAX_HEADER_BYTES", 60_000)
	apiMaxPayloadBytes     = cli.GetEnvInt("API_MAX_PAYLOAD_BYTES", 15*1024*1024) // 15 MiB

	// api shutdown: wait time (to allow removal from load balancer before stopping http server)
	apiShutdownWaitDuration = common.GetEnvDurationSec("API_SHUTDOWN_WAIT_SEC", 30)

	// api shutdown: whether to stop sending bids during shutdown phase (only useful if running a single-instance testnet setup)
	apiShutdownStopSendingBids = os.Getenv("API_SHUTDOWN_STOP_SENDING_BIDS") == "1"

	// maximum payload bytes for a block submission to be fast-tracked (large payloads slow down other fast-tracked requests!)
	fastTrackPayloadSizeLimit = cli.GetEnvInt("FAST_TRACK_PAYLOAD_SIZE_LIMIT", 230_000)

	// user-agents which shouldn't receive bids
	apiNoHeaderUserAgents = common.GetEnvStrSlice("NO_HEADER_USERAGENTS", []string{
		"mev-boost/v1.5.0 Go-http-client/1.1", // Prysm v4.0.1 (Shapella signing issue)
	})
)

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr  string
	BlockSimURL string

	BeaconClient beaconclient.IMultiBeaconClient
	Datastore    *datastore.Datastore
	Redis        *datastore.RedisCache
	Memcached    *datastore.Memcached
	DB           database.IDatabaseService

	SecretKey *bls.SecretKey // used to sign bids (getHeader responses)

	// Network specific variables
	EthNetDetails common.EthNetworkDetails

	PprofListenAddr string

	// APIs to enable
	ProposerAPI     bool
	BlockBuilderAPI bool
	DataAPI         bool
	InternalAPI     bool
}

type payloadAttributesHelper struct {
	slot              uint64
	parentHash        string
	withdrawalsRoot   phase0.Root
	parentBeaconRoot  *phase0.Root
	payloadAttributes beaconclient.PayloadAttributes
}

// Data needed to issue a block validation request.
type blockSimOptions struct {
	isHighPrio bool
	fastTrack  bool
	log        *logrus.Entry
	builder    *blockBuilderCacheEntry
	req        *common.BuilderBlockValidationRequest
}

type blockBuilderCacheEntry struct {
	status     common.BuilderStatus
	collateral *big.Int
}

type blockSimResult struct {
	wasSimulated         bool
	blockValue           *uint256.Int
	optimisticSubmission bool
	requestErr           error
	validationErr        error
}

// RelayAPI represents a single Relay instance
type RelayAPI struct {
	opts RelayAPIOpts
	log  *logrus.Entry

	blsSk     *bls.SecretKey
	publicKey *phase0.BLSPubKey

	srv         *http.Server
	srvStarted  uberatomic.Bool
	srvShutdown uberatomic.Bool

	beaconClient beaconclient.IMultiBeaconClient
	datastore    *datastore.Datastore
	redis        *datastore.RedisCache
	memcached    *datastore.Memcached
	db           database.IDatabaseService

	headSlot     uberatomic.Uint64
	genesisInfo  *beaconclient.GetGenesisResponse
	capellaEpoch int64
	denebEpoch   int64
	electraEpoch int64
	fuluEpoch    int64

	proposerDutiesLock       sync.RWMutex
	proposerDutiesResponse   *[]byte // raw http response
	proposerDutiesMap        map[uint64]*common.BuilderGetValidatorsResponseEntry
	proposerDutiesSlot       uint64
	isUpdatingProposerDuties uberatomic.Bool

	blockSimRateLimiter IBlockSimRateLimiter

	validatorRegC chan builderApiV1.SignedValidatorRegistration

	// used to notify when a new validator has been registered
	validatorUpdateCh chan struct{}

	// used to wait on any active getPayload calls on shutdown
	getPayloadCallsInFlight sync.WaitGroup

	// Feature flags
	ffForceGetHeader204          bool
	ffDisableLowPrioBuilders     bool
	ffDisablePayloadDBStorage    bool // disable storing the execution payloads in the database
	ffLogInvalidSignaturePayload bool // log payload if getPayload signature validation fails
	ffEnableCancellations        bool // whether to enable block builder cancellations
	ffRegValContinueOnInvalidSig bool // whether to continue processing further validators if one fails
	ffIgnorableValidationErrors  bool // whether to enable ignorable validation errors

	payloadAttributes     map[string]payloadAttributesHelper // key:parentBlockHash
	payloadAttributesLock sync.RWMutex

	// The slot we are currently optimistically simulating.
	optimisticSlot uberatomic.Uint64
	// The number of optimistic blocks being processed (only used for logging).
	optimisticBlocksInFlight uberatomic.Uint64
	// Wait group used to monitor status of per-slot optimistic processing.
	optimisticBlocksWG sync.WaitGroup
	// Cache for builder statuses and collaterals.
	blockBuildersCache map[string]*blockBuilderCacheEntry
}

// NewRelayAPI creates a new service. if builders is nil, allow any builder
func NewRelayAPI(opts RelayAPIOpts) (api *RelayAPI, err error) {
	if err := metrics.Setup(context.Background()); err != nil {
		return nil, err
	}

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
	var publicKey phase0.BLSPubKey
	if opts.BlockBuilderAPI {
		if opts.SecretKey == nil {
			return nil, ErrBuilderAPIWithoutSecretKey
		}

		// If using a secret key, ensure it's the correct one
		blsPubkey, err := bls.PublicKeyFromSecretKey(opts.SecretKey)
		if err != nil {
			return nil, err
		}
		publicKey, err = utils.BlsPublicKeyToPublicKey(blsPubkey)
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

	var blockSim IBlockSimRateLimiter
	if opts.BlockSimURL != "" {
		blockSim = NewBlockSimulationRateLimiter(opts.BlockSimURL)
	} else {
		log.Warn("Running without block simulator")
		blockSim = newNoopBlockSim()
	}

	api = &RelayAPI{
		opts:         opts,
		log:          opts.Log,
		blsSk:        opts.SecretKey,
		publicKey:    &publicKey,
		datastore:    opts.Datastore,
		beaconClient: opts.BeaconClient,
		redis:        opts.Redis,
		memcached:    opts.Memcached,
		db:           opts.DB,

		payloadAttributes: make(map[string]payloadAttributesHelper),

		proposerDutiesResponse: &[]byte{},
		blockSimRateLimiter:    blockSim,

		validatorRegC:     make(chan builderApiV1.SignedValidatorRegistration, 450_000),
		validatorUpdateCh: make(chan struct{}),
	}

	if os.Getenv("FORCE_GET_HEADER_204") == "1" {
		api.log.Warn("env: FORCE_GET_HEADER_204 - forcing getHeader to always return 204")
		api.ffForceGetHeader204 = true
	}

	if os.Getenv("DISABLE_LOWPRIO_BUILDERS") == "1" {
		api.log.Warn("env: DISABLE_LOWPRIO_BUILDERS - allowing only high-level builders")
		api.ffDisableLowPrioBuilders = true
	}

	if os.Getenv("DISABLE_PAYLOAD_DATABASE_STORAGE") == "1" {
		api.log.Warn("env: DISABLE_PAYLOAD_DATABASE_STORAGE - disabling storing payloads in the database")
		api.ffDisablePayloadDBStorage = true
	}

	if os.Getenv("LOG_INVALID_GETPAYLOAD_SIGNATURE") == "1" {
		api.log.Warn("env: LOG_INVALID_GETPAYLOAD_SIGNATURE - getPayload payloads with invalid proposer signature will be logged")
		api.ffLogInvalidSignaturePayload = true
	}

	if os.Getenv("ENABLE_BUILDER_CANCELLATIONS") == "1" {
		api.log.Warn("env: ENABLE_BUILDER_CANCELLATIONS - builders are allowed to cancel submissions when using ?cancellation=1")
		api.ffEnableCancellations = true
	}

	if os.Getenv("REGISTER_VALIDATOR_CONTINUE_ON_INVALID_SIG") == "1" {
		api.log.Warn("env: REGISTER_VALIDATOR_CONTINUE_ON_INVALID_SIG - validator registration will continue processing even if one validator has an invalid signature")
		api.ffRegValContinueOnInvalidSig = true
	}

	if os.Getenv("ENABLE_IGNORABLE_VALIDATION_ERRORS") == "1" {
		api.log.Warn("env: ENABLE_IGNORABLE_VALIDATION_ERRORS - some validation errors will be ignored")
		api.ffIgnorableValidationErrors = true
	}

	return api, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)
	r.HandleFunc("/livez", api.handleLivez).Methods(http.MethodGet)
	r.HandleFunc("/readyz", api.handleReadyz).Methods(http.MethodGet)
	r.Handle("/metrics", promhttp.Handler()).Methods(http.MethodGet)

	// Proposer API
	if api.opts.ProposerAPI {
		api.log.Info("proposer API enabled")
		r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
		r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
		r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
		r.HandleFunc(pathGetPayloadV1, api.handleGetPayloadV1).Methods(http.MethodPost)
		r.HandleFunc(pathGetPayloadV2, api.handleGetPayloadV2).Methods(http.MethodPost)
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

	// /internal/...
	if api.opts.InternalAPI {
		api.log.Info("internal API enabled")
		r.HandleFunc(pathInternalBuilderStatus, api.handleInternalBuilderStatus).Methods(http.MethodGet, http.MethodPost, http.MethodPut)
		r.HandleFunc(pathInternalBuilderCollateral, api.handleInternalBuilderCollateral).Methods(http.MethodPost, http.MethodPut)
	}

	mresp := common.MustB64Gunzip("H4sICAtOkWQAA2EudHh0AKWVPW+DMBCGd36Fe9fIi5Mt8uqqs4dIlZiCEqosKKhVO2Txj699GBtDcEl4JwTnh/t4dS7YWom2FcVaiETSDEmIC+pWLGRVgKrD3UY0iwnSj6THofQJDomiR13BnPgjvJDqNWX+OtzH7inWEGvr76GOCGtg3Kp7Ak+lus3zxLNtmXaMUncjcj1cwbOH3xBZtJCYG6/w+hdpB6ErpnqzFPZxO4FdXB3SAEgpscoDqWeULKmJA4qyfYFg0QV+p7hD8GGDd6C8+mElGDKab1CWeUQMVVvVDTJVj6nngHmNOmSoe6yH1BM3KZIKpuRaHKrOFd/3ksQwzdK+ejdM4VTzSDfjJsY1STeVTWb0T9JWZbJs8DvsNvwaddKdUy4gzVIzWWaWk3IF8D35kyUDf3FfKipwk/DYUee2nYyWQD0xEKDHeprzeXYwVmZD/lXt1OOg8EYhFfitsmQVcwmbUutpdt3PoqWdMyd2DYHKbgcmPlEYMxPjR6HhxOfuNG52xZr7TtzpygJJKNtWS14Uf0T6XSmzBwAA")
	r.HandleFunc("/miladyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK); w.Write(mresp) }).Methods(http.MethodGet) //nolint:errcheck

	// r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(api.log, r)
	withGz := gziphandler.GzipHandler(loggedRouter)
	return withGz
}

// StartServer starts up this API instance and HTTP server
// - First it initializes the cache and updates local information
// - Once that is done, the HTTP server is started
func (api *RelayAPI) StartServer() (err error) {
	if api.srvStarted.Swap(true) {
		return ErrServerAlreadyStarted
	}

	log := api.log.WithField("method", "StartServer")

	// Get best beacon-node status by head slot, process current slot and start slot updates
	syncStatus, err := api.beaconClient.BestSyncStatus()
	if err != nil {
		return err
	}
	currentSlot := syncStatus.HeadSlot

	// Initialize block builder cache.
	api.blockBuildersCache = make(map[string]*blockBuilderCacheEntry)

	// Get genesis info
	api.genesisInfo, err = api.beaconClient.GetGenesis()
	if err != nil {
		return err
	}
	log.Infof("genesis info: %d", api.genesisInfo.Data.GenesisTime)

	// Get and prepare fork schedule
	forkSchedule, err := api.beaconClient.GetForkSchedule()
	if err != nil {
		return err
	}

	api.capellaEpoch = -1
	api.denebEpoch = -1
	api.electraEpoch = -1
	api.fuluEpoch = -1
	for _, fork := range forkSchedule.Data {
		log.Infof("forkSchedule: version=%s / epoch=%d", fork.CurrentVersion, fork.Epoch)
		switch fork.CurrentVersion {
		case api.opts.EthNetDetails.CapellaForkVersionHex:
			api.capellaEpoch = int64(fork.Epoch) //nolint:gosec
		case api.opts.EthNetDetails.DenebForkVersionHex:
			api.denebEpoch = int64(fork.Epoch) //nolint:gosec
		case api.opts.EthNetDetails.ElectraForkVersionHex:
			api.electraEpoch = int64(fork.Epoch) //nolint:gosec
		case api.opts.EthNetDetails.FuluForkVersionHex:
			api.fuluEpoch = int64(fork.Epoch) //nolint:gosec
		}
	}

	if api.denebEpoch == -1 {
		// log warning that deneb epoch was not found in CL fork schedule, suggest CL upgrade
		log.Info("Deneb epoch not found in fork schedule")
	}
	if api.electraEpoch == -1 {
		// log warning that electra epoch was not found in CL fork schedule, suggest CL upgrade
		log.Info("Electra epoch not found in fork schedule")
	}
	if api.fuluEpoch == -1 {
		// log warning that fulu epoch was not found in CL fork schedule, suggest CL upgrade
		log.Info("Fulu epoch not found in fork schedule")
	}

	// Print fork version information
	if hasReachedFork(currentSlot, api.fuluEpoch) {
		log.Infof("fulu fork detected (currentEpoch: %d / fuluEpoch: %d)", common.SlotToEpoch(currentSlot), api.fuluEpoch)
	} else if hasReachedFork(currentSlot, api.electraEpoch) {
		log.Infof("electra fork detected (currentEpoch: %d / electraEpoch: %d)", common.SlotToEpoch(currentSlot), api.electraEpoch)
	} else if hasReachedFork(currentSlot, api.denebEpoch) {
		log.Infof("deneb fork detected (currentEpoch: %d / denebEpoch: %d)", common.SlotToEpoch(currentSlot), api.denebEpoch)
	} else if hasReachedFork(currentSlot, api.capellaEpoch) {
		log.Infof("capella fork detected (currentEpoch: %d / capellaEpoch: %d)", common.SlotToEpoch(currentSlot), api.capellaEpoch)
	}

	// start proposer API specific things
	if api.opts.ProposerAPI {
		// Update known validators (which can take 10-30 sec). This is a requirement for service readiness, because without them,
		// getPayload() doesn't have the information it needs (known validators), which could lead to missed slots.
		go api.datastore.RefreshKnownValidators(api.log, api.beaconClient, currentSlot)

		// Start the validator registration db-save processor
		api.log.Infof("starting %d validator registration processors", numValidatorRegProcessors)
		for range numValidatorRegProcessors {
			go api.startValidatorRegistrationDBProcessor()
		}
	}

	// start block-builder API specific things
	if api.opts.BlockBuilderAPI {
		// Initialize metrics
		metrics.BuilderDemotionCount.Add(context.Background(), 0)

		// Get current proposer duties blocking before starting, to have them ready
		api.updateProposerDuties(syncStatus.HeadSlot)

		// Subscribe to payload attributes events (only for builder-api)
		go func() {
			c := make(chan beaconclient.PayloadAttributesEvent)
			api.beaconClient.SubscribeToPayloadAttributesEvents(c)
			for {
				payloadAttributes := <-c
				api.processPayloadAttributes(payloadAttributes)
			}
		}()
	}

	// Process current slot
	api.processNewSlot(currentSlot)

	// Start regular slot updates
	go func() {
		c := make(chan beaconclient.HeadEventData)
		api.beaconClient.SubscribeToHeadEvents(c)
		for {
			headEvent := <-c
			api.processNewSlot(headEvent.Slot)
		}
	}()

	if api.opts.PprofListenAddr != "" {
		api.log.Info("pprof API is listening on", api.opts.PprofListenAddr)
		go func() {
			//nolint:gosec // we should not expose pprof externally anyway
			err := http.ListenAndServe(api.opts.PprofListenAddr, http.DefaultServeMux)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				api.log.WithError(err).Fatal("failed to start pprof API")
			}
		}()
	}

	// create and start HTTP server
	api.srv = &http.Server{
		Addr:    api.opts.ListenAddr,
		Handler: api.getRouter(),

		ReadTimeout:       time.Duration(apiReadTimeoutMs) * time.Millisecond,
		ReadHeaderTimeout: time.Duration(apiReadHeaderTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(apiWriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       time.Duration(apiIdleTimeoutMs) * time.Millisecond,
		MaxHeaderBytes:    apiMaxHeaderBytes,
	}
	err = api.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (api *RelayAPI) IsReady() bool {
	// If server is shutting down, return false
	if api.srvShutdown.Load() {
		return false
	}

	// Proposer API readiness checks
	if api.opts.ProposerAPI {
		knownValidatorsUpdated := api.datastore.KnownValidatorsWasUpdated.Load()
		return knownValidatorsUpdated
	}

	// Block-builder API readiness checks
	return true
}

// StopServer gracefully shuts down the HTTP server:
// - Stop returning bids
// - Set ready /readyz to negative status
// - Wait a bit to allow removal of service from load balancer and draining of requests
func (api *RelayAPI) StopServer() (err error) {
	// avoid running this twice. setting srvShutdown to true makes /readyz switch to negative status
	if wasStopping := api.srvShutdown.Swap(true); wasStopping {
		return nil
	}

	// start server shutdown
	api.log.Info("Stopping server...")

	// stop returning bids on getHeader calls (should only be used when running a single instance)
	if api.opts.ProposerAPI && apiShutdownStopSendingBids {
		api.ffForceGetHeader204 = true
		api.log.Info("Disabled returning bids on getHeader")
	}

	// wait some time to get service removed from load balancer
	api.log.Infof("Waiting %.2f seconds before shutdown...", apiShutdownWaitDuration.Seconds())
	time.Sleep(apiShutdownWaitDuration)

	// wait for any active getPayload call to finish
	api.getPayloadCallsInFlight.Wait()

	// shutdown
	return api.srv.Shutdown(context.Background())
}

func (api *RelayAPI) ValidatorUpdateCh() chan struct{} {
	return api.validatorUpdateCh
}

func (api *RelayAPI) isCapella(slot uint64) bool {
	return hasReachedFork(slot, api.capellaEpoch) && !hasReachedFork(slot, api.denebEpoch)
}

func (api *RelayAPI) isDeneb(slot uint64) bool {
	return hasReachedFork(slot, api.denebEpoch) && !hasReachedFork(slot, api.electraEpoch)
}

func (api *RelayAPI) isElectra(slot uint64) bool {
	return hasReachedFork(slot, api.electraEpoch) && !hasReachedFork(slot, api.fuluEpoch)
}

func (api *RelayAPI) isFulu(slot uint64) bool {
	return hasReachedFork(slot, api.fuluEpoch)
}

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
func (api *RelayAPI) simulateBlock(ctx context.Context, opts blockSimOptions) (blockValue *uint256.Int, requestErr, validationErr error) {
	t := time.Now()
	response, requestErr, validationErr := api.blockSimRateLimiter.Send(ctx, opts.req, opts.isHighPrio, opts.fastTrack)
	log := opts.log.WithFields(logrus.Fields{
		"durationMs": time.Since(t).Milliseconds(),
		"numWaiting": api.blockSimRateLimiter.CurrentCounter(),
	})
	if validationErr != nil {
		if api.ffIgnorableValidationErrors {
			// Operators chooses to ignore certain validation errors
			ignoreError := validationErr.Error() == ErrBlockAlreadyKnown || validationErr.Error() == ErrBlockRequiresReorg || strings.Contains(validationErr.Error(), ErrMissingTrieNode)
			if ignoreError {
				log.WithError(validationErr).Warn("block validation failed with ignorable error")
				return nil, nil, nil
			}
		}
		log.WithError(validationErr).Warn("block validation failed")
		return nil, nil, validationErr
	}
	if requestErr != nil {
		log.WithError(requestErr).Warn("block validation failed: request error")
		return nil, requestErr, nil
	}

	log.Info("block validation successful")
	if response == nil {
		log.Warn("block validation response is nil")
		return nil, nil, nil
	}
	return response.BlockValue, nil, nil
}

func (api *RelayAPI) demoteBuilder(pubkey string, req *common.VersionedSubmitBlockRequest, simError error) {
	metrics.BuilderDemotionCount.Add(
		context.Background(),
		1,
	)

	builderEntry, ok := api.blockBuildersCache[pubkey]
	if !ok {
		api.log.Warnf("builder %v not in the builder cache", pubkey)
		builderEntry = &blockBuilderCacheEntry{} //nolint:exhaustruct
	}
	newStatus := common.BuilderStatus{
		IsHighPrio:    builderEntry.status.IsHighPrio,
		IsBlacklisted: builderEntry.status.IsBlacklisted,
		IsOptimistic:  false,
	}
	api.log.Infof("demoted builder, new status: %v", newStatus)
	if err := api.db.SetBlockBuilderIDStatusIsOptimistic(pubkey, false); err != nil {
		api.log.Error(fmt.Errorf("error setting builder: %v status: %w", pubkey, err))
	}
	// Write to demotions table.
	api.log.WithFields(logrus.Fields{
		"builderPubkey": pubkey,
		"slot":          req.Slot,
		"blockHash":     req.BlockHash,
		"demotionErr":   simError.Error(),
	}).Info("demoting builder")
	bidTrace, err := req.BidTrace()
	if err != nil {
		api.log.WithError(err).Warn("failed to get bid trace from submit block request")
	}
	if err := api.db.InsertBuilderDemotion(req, simError); err != nil {
		api.log.WithError(err).WithFields(logrus.Fields{
			"errorWritingDemotionToDB": true,
			"bidTrace":                 bidTrace,
			"simError":                 simError,
		}).Error("failed to save demotion to database")
	}
}

// processOptimisticBlock is called on a new goroutine when a optimistic block
// needs to be simulated.
func (api *RelayAPI) processOptimisticBlock(opts blockSimOptions, simResultC chan *blockSimResult) {
	api.optimisticBlocksInFlight.Add(1)
	defer func() { api.optimisticBlocksInFlight.Sub(1) }()
	api.optimisticBlocksWG.Add(1)
	defer api.optimisticBlocksWG.Done()

	ctx := context.Background()
	submission, err := common.GetBlockSubmissionInfo(opts.req.VersionedSubmitBlockRequest)
	if err != nil {
		opts.log.WithError(err).Error("error getting block submission info")
		return
	}
	builderPubkey := submission.BidTrace.BuilderPubkey.String()
	opts.log.WithFields(logrus.Fields{
		"builderPubkey": builderPubkey,
		// NOTE: this value is just an estimate because many goroutines could be
		// updating api.optimisticBlocksInFlight concurrently. Since we just use
		// it for logging, it is not atomic to avoid the performance impact.
		"optBlocksInFlight": api.optimisticBlocksInFlight,
	}).Infof("simulating optimistic block with hash: %v", submission.BidTrace.BlockHash.String())
	blockValue, reqErr, simErr := api.simulateBlock(ctx, opts)
	simResultC <- &blockSimResult{reqErr == nil, blockValue, true, reqErr, simErr}
	if reqErr != nil || simErr != nil {
		// Mark builder as non-optimistic.
		opts.builder.status.IsOptimistic = false
		api.log.WithError(simErr).Warn("block simulation failed in processOptimisticBlock, demoting builder")

		var demotionErr error
		if reqErr != nil {
			demotionErr = reqErr
		} else {
			demotionErr = simErr
		}

		// Demote the builder.
		api.demoteBuilder(builderPubkey, opts.req.VersionedSubmitBlockRequest, demotionErr)
	}
}

func (api *RelayAPI) processPayloadAttributes(payloadAttributes beaconclient.PayloadAttributesEvent) {
	apiHeadSlot := api.headSlot.Load()
	payloadAttrSlot := payloadAttributes.Data.ProposalSlot

	// require proposal slot in the future
	if payloadAttrSlot <= apiHeadSlot {
		return
	}
	log := api.log.WithFields(logrus.Fields{
		"headSlot":          apiHeadSlot,
		"payloadAttrSlot":   payloadAttrSlot,
		"payloadAttrParent": payloadAttributes.Data.ParentBlockHash,
	})

	// discard payload attributes if already known
	api.payloadAttributesLock.RLock()
	_, ok := api.payloadAttributes[getPayloadAttributesKey(payloadAttributes.Data.ParentBlockHash, payloadAttrSlot)]
	api.payloadAttributesLock.RUnlock()

	if ok {
		return
	}

	var withdrawalsRoot phase0.Root
	var err error
	if hasReachedFork(payloadAttrSlot, api.capellaEpoch) {
		withdrawalsRoot, err = ComputeWithdrawalsRoot(payloadAttributes.Data.PayloadAttributes.Withdrawals)
		log = log.WithField("withdrawalsRoot", withdrawalsRoot.String())
		if err != nil {
			log.WithError(err).Error("error computing withdrawals root")
			return
		}
	}

	var parentBeaconRoot *phase0.Root
	if hasReachedFork(payloadAttrSlot, api.denebEpoch) {
		if payloadAttributes.Data.PayloadAttributes.ParentBeaconBlockRoot == "" {
			log.Error("parent beacon block root in payload attributes is empty")
			return
		}
		// TODO: (deneb) HexToRoot util function
		hash, err := utils.HexToHash(payloadAttributes.Data.PayloadAttributes.ParentBeaconBlockRoot)
		if err != nil {
			log.WithError(err).Error("error parsing parent beacon block root from payload attributes")
			return
		}
		root := phase0.Root(hash)
		parentBeaconRoot = &root
	}

	api.payloadAttributesLock.Lock()
	defer api.payloadAttributesLock.Unlock()

	// Step 1: clean up old ones
	for parentBlockHash, attr := range api.payloadAttributes {
		if attr.slot < apiHeadSlot {
			delete(api.payloadAttributes, getPayloadAttributesKey(parentBlockHash, attr.slot))
		}
	}

	// Step 2: save new one
	api.payloadAttributes[getPayloadAttributesKey(payloadAttributes.Data.ParentBlockHash, payloadAttrSlot)] = payloadAttributesHelper{
		slot:              payloadAttrSlot,
		parentHash:        payloadAttributes.Data.ParentBlockHash,
		withdrawalsRoot:   withdrawalsRoot,
		parentBeaconRoot:  parentBeaconRoot,
		payloadAttributes: payloadAttributes.Data.PayloadAttributes,
	}

	log.WithFields(logrus.Fields{
		"randao":    payloadAttributes.Data.PayloadAttributes.PrevRandao,
		"timestamp": payloadAttributes.Data.PayloadAttributes.Timestamp,
	}).Info("updated payload attributes")
}

func (api *RelayAPI) processNewSlot(headSlot uint64) {
	prevHeadSlot := api.headSlot.Load()
	if headSlot <= prevHeadSlot {
		return
	}

	// If there's gaps between previous and new headslot, print the missed slots
	if prevHeadSlot > 0 {
		for s := prevHeadSlot + 1; s < headSlot; s++ {
			api.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
			metrics.MissedSlotCount.Add(context.Background(), 1)
		}
	}

	// store the head slot
	api.headSlot.Store(headSlot)
	metrics.CurrentHeadSlotGauge.Record(context.Background(), int64(headSlot)) //nolint:gosec

	// only for builder-api
	if api.opts.BlockBuilderAPI || api.opts.ProposerAPI {
		// update proposer duties in the background
		go api.updateProposerDuties(headSlot)

		// update the optimistic slot
		go api.prepareBuildersForSlot(headSlot)
	}

	if api.opts.ProposerAPI {
		go api.datastore.RefreshKnownValidators(api.log, api.beaconClient, headSlot)
	}

	// log
	epoch := headSlot / common.SlotsPerEpoch
	api.log.WithFields(logrus.Fields{
		"epoch":              epoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (epoch + 1) * common.SlotsPerEpoch,
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

	api.UpdateProposerDutiesWithoutChecks(headSlot)
}

func (api *RelayAPI) UpdateProposerDutiesWithoutChecks(headSlot uint64) {
	// Load upcoming proposer duties from Redis
	duties, err := api.redis.GetProposerDuties()
	if err != nil {
		api.log.WithError(err).Error("failed getting proposer duties from redis")
		return
	}

	// Prepare raw bytes for HTTP response
	respBytes, err := json.Marshal(duties)
	if err != nil {
		api.log.WithError(err).Error("error marshalling duties")
	}

	// Prepare the map for lookup by slot
	dutiesMap := make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	for index, duty := range duties {
		dutiesMap[duty.Slot] = &duties[index]
	}

	// Update
	api.proposerDutiesLock.Lock()
	if len(respBytes) > 0 {
		api.proposerDutiesResponse = &respBytes
	}
	api.proposerDutiesMap = dutiesMap
	api.proposerDutiesSlot = headSlot
	api.proposerDutiesLock.Unlock()

	// pretty-print
	_duties := make([]string, len(duties))
	for i, duty := range duties {
		_duties[i] = strconv.FormatUint(duty.Slot, 10)
	}
	sort.Strings(_duties)
	api.log.Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
}

func (api *RelayAPI) prepareBuildersForSlot(headSlot uint64) {
	// Wait until there are no optimistic blocks being processed. Then we can
	// safely update the slot.
	api.optimisticBlocksWG.Wait()
	api.optimisticSlot.Store(headSlot + 1)

	builders, err := api.db.GetBlockBuilders()
	if err != nil {
		api.log.WithError(err).Error("unable to read block builders from db, not updating builder cache")
		return
	}
	api.log.Debugf("Updating builder cache with %d builders from database", len(builders))

	newCache := make(map[string]*blockBuilderCacheEntry)
	for _, v := range builders {
		entry := &blockBuilderCacheEntry{ //nolint:exhaustruct
			status: common.BuilderStatus{
				IsHighPrio:    v.IsHighPrio,
				IsBlacklisted: v.IsBlacklisted,
				IsOptimistic:  v.IsOptimistic,
			},
		}
		// Try to parse builder collateral string to big int.
		builderCollateral, ok := big.NewInt(0).SetString(v.Collateral, 10)
		if !ok {
			api.log.WithError(err).Errorf("could not parse builder collateral string %s", v.Collateral)
			entry.collateral = big.NewInt(0)
		} else {
			entry.collateral = builderCollateral
		}
		newCache[v.BuilderPubkey] = entry
	}
	api.blockBuildersCache = newCache
}

func (api *RelayAPI) RespondError(w http.ResponseWriter, code int, message string) {
	api.Respond(w, code, HTTPErrorResp{code, message})
}

func (api *RelayAPI) RespondOK(w http.ResponseWriter, response any) {
	api.Respond(w, http.StatusOK, response)
}

func (api *RelayAPI) RespondMsg(w http.ResponseWriter, code int, msg string) {
	api.Respond(w, code, HTTPMessageResp{msg})
}

func (api *RelayAPI) Respond(w http.ResponseWriter, code int, response any) {
	w.Header().Set(HeaderContentType, common.ApplicationJSON)
	w.WriteHeader(code)
	if response == nil {
		return
	}

	// write the json response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		api.log.WithField("response", response).WithError(err).Error("Couldn't write response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *RelayAPI) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// NegotiateRequestResponseType returns whether the request accepts
// JSON (application/json) or SSZ (application/octet-stream) responses.
// If accepted is false, no mime type could be negotiated and the server
// should respond with http.StatusNotAcceptable.
func NegotiateRequestResponseType(req *http.Request) (mimeType string, err error) {
	ah := req.Header.Get(HeaderAccept)
	if ah == "" {
		return common.ApplicationJSON, nil
	}
	mh := mimeheader.ParseAcceptHeader(ah)
	_, mimeType, matched := mh.Negotiate(
		[]string{common.ApplicationJSON, common.ApplicationOctetStream},
		common.ApplicationJSON,
	)
	if !matched {
		return "", ErrNotAcceptable
	}
	return mimeType, nil
}

// ---------------
//  PROPOSER APIS
// ---------------

func (api *RelayAPI) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "MEV-Boost Relay API")
}

func (api *RelayAPI) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	var err, userErr error

	start := time.Now().UTC()
	numRegProcessed := 0
	numRegNew := 0

	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":        "registerValidator",
		"ua":            ua,
		"mevBoostV":     common.GetMevBoostVersionFromUserAgent(ua),
		"headSlot":      api.headSlot.Load(),
		"contentLength": req.ContentLength,
	})

	registerSuccess := false
	defer func() {
		status := "error"
		if registerSuccess {
			status = "success"
		}
		metrics.RegisterValidatorCount.Add(req.Context(), 1,
			otelapi.WithAttributes(attribute.String("status", status)),
		)
	}()

	// Setup error handling
	logAndReturnError := func(_log *logrus.Entry, code int, userMsg string, err error) {
		_log.WithError(err).Warnf("error: %s", userMsg)
		api.RespondError(w, code, userMsg)
	}

	// Start processing
	if req.ContentLength == 0 {
		log.Info("empty request")
		api.RespondError(w, http.StatusBadRequest, "empty request")
		return
	}

	// Get the request content type
	proposerContentType, _, err := getHeaderContentType(req.Header)
	if err != nil {
		api.log.WithError(err).Error("failed to parse proposer content type")
		api.RespondError(w, http.StatusUnsupportedMediaType, err.Error())
		return
	}
	log = log.WithField("proposerContentType", proposerContentType)

	// Read the encoded validator registrations
	limitReader := io.LimitReader(req.Body, int64(apiMaxPayloadBytes))
	regBytes, err := io.ReadAll(limitReader)
	if err != nil {
		log.WithError(err).Warn("failed to read request body")
		api.RespondError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	_ = req.Body.Close()

	//
	// Parse the registrations request body, and check for cached entries
	//
	numTotalRegistrations := 0
	var signedValidatorRegistrations []*builderApiV1.SignedValidatorRegistration

	if proposerContentType == common.ApplicationOctetStream {
		// Registrations in SSZ
		log = log.WithField("is_ssz", true)
		log.Debug("Parsing registrations as SSZ")

		resp := new(builderApiV1.SignedValidatorRegistrations)
		err = resp.UnmarshalSSZ(regBytes)
		if err != nil {
			logAndReturnError(log, http.StatusBadRequest, err.Error(), err)
			return
		}

		numTotalRegistrations = len(resp.Registrations)
		signedValidatorRegistrations, userErr, err = api.processValidatorRegistrationsSSZ(resp.Registrations)
	} else {
		// Registrations in JSON
		log = log.WithField("is_ssz", false)
		api.log.Debug("Parsing registrations as JSON")

		var signedValidatorRegistrationsJSON []*common.SimpleValidatorRegistration
		signedValidatorRegistrationsJSON, err = api.parseValidatorRegistrationsJSON(regBytes)
		if err != nil {
			logAndReturnError(log, http.StatusBadRequest, err.Error(), err)
			return
		}

		numTotalRegistrations = len(signedValidatorRegistrationsJSON)
		signedValidatorRegistrations, userErr, err = api.processValidatorRegistrationJSON(signedValidatorRegistrationsJSON)
	}

	log.WithFields(logrus.Fields{
		"decodeDurationMs": time.Since(start).Milliseconds(),
		"numRegistrations": numTotalRegistrations,
	}).Debug("Parsed registrations")

	// Handle errors, if any
	if userErr != nil {
		logAndReturnError(log, http.StatusBadRequest, userErr.Error(), err)
		return
	} else if err != nil {
		logAndReturnError(log, http.StatusBadRequest, "", err)
		return
	}

	//
	// All remaining registrations are uncached and need to get checked
	//
	for _, signedValidatorRegistration := range signedValidatorRegistrations {
		regLog := log.WithField("pubkey", signedValidatorRegistration.Message.Pubkey.String())
		numRegProcessed += 1

		// Verify the signature
		regLog.Debug("verifying BLS signature...")
		ok, err := ssz.VerifySignature(signedValidatorRegistration.Message, api.opts.EthNetDetails.DomainBuilder, signedValidatorRegistration.Message.Pubkey[:], signedValidatorRegistration.Signature[:])
		if err != nil {
			regLog.WithError(err).Error("error verifying registerValidator signature")
			break
		} else if !ok {
			regLog.Info("invalid validator signature")
			if api.ffRegValContinueOnInvalidSig {
				continue
			} else {
				logAndReturnError(regLog, http.StatusBadRequest, "failed to verify validator signature for "+signedValidatorRegistration.Message.Pubkey.String(), err)
				break
			}
		}

		// Now we have a new registration to process (store in DB + Cache)
		numRegNew += 1

		// Save to database
		select {
		case api.validatorRegC <- *signedValidatorRegistration:
		default:
			regLog.Error("validator registration channel full")
		}
	}

	log = log.WithFields(logrus.Fields{
		"timeNeededMs":              time.Since(start).Milliseconds(),
		"numRegistrations":          len(signedValidatorRegistrations),
		"numRegistrationsProcessed": numRegProcessed,
		"numRegistrationsNew":       numRegNew,
	})

	// notify that new registrations are available
	select {
	case api.validatorUpdateCh <- struct{}{}:
	default:
	}

	metrics.RegisterValidatorLatencyHistogram.Record(req.Context(), float64(time.Since(start).Milliseconds()))
	registerSuccess = true
	log.Info("validator registrations call processed")
	w.WriteHeader(http.StatusOK)
}

func (api *RelayAPI) parseValidatorRegistrationsJSON(regBytes []byte) ([]*common.SimpleValidatorRegistration, error) {
	validatorRegistrations := make([]*common.SimpleValidatorRegistration, 0)

	// Parse registrations as JSON
	var parseErr error
	_, forEachErr := jsonparser.ArrayEach(regBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		if err != nil {
			parseErr = err
			return
		}

		var reg common.SimpleValidatorRegistration
		if err := reg.UnmarshalJSON(value); err != nil {
			parseErr = err
			return
		}
		validatorRegistrations = append(validatorRegistrations, &reg)
	})
	if forEachErr != nil {
		return nil, forEachErr
	}
	if parseErr != nil {
		return nil, parseErr
	}

	return validatorRegistrations, nil
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slotStr := vars["slot"]
	parentHashHex := vars["parent_hash"]
	proposerPubkeyHex := vars["pubkey"]
	ua := req.UserAgent()
	headSlot := api.headSlot.Load()

	// Negotiate the response media type
	negotiatedResponseMediaType, err := NegotiateRequestResponseType(req)
	if err != nil {
		api.log.WithError(err).Error("failed to negotiate response type")
		api.RespondError(w, http.StatusNotAcceptable, err.Error())
		return
	}

	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSlot.Error())
		return
	}

	requestTime := time.Now().UTC()
	slotStartTimestamp := api.genesisInfo.Data.GenesisTime + (slot * common.SecondsPerSlot)
	msIntoSlot := requestTime.UnixMilli() - int64(slotStartTimestamp*1000) //nolint:gosec

	log := api.log.WithFields(logrus.Fields{
		"method":                      "getHeader",
		"headSlot":                    headSlot,
		"slot":                        slotStr,
		"parentHash":                  parentHashHex,
		"pubkey":                      proposerPubkeyHex,
		"ua":                          ua,
		"mevBoostV":                   common.GetMevBoostVersionFromUserAgent(ua),
		"requestTimestamp":            requestTime.Unix(),
		"slotStartSec":                slotStartTimestamp,
		"msIntoSlot":                  msIntoSlot,
		"negotiatedResponseMediaType": negotiatedResponseMediaType,
	})

	if len(proposerPubkeyHex) != 98 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidHash.Error())
		return
	}

	if slot < headSlot {
		api.RespondError(w, http.StatusBadRequest, "slot is too old")
		return
	}

	log.Debug("getHeader request received")
	getHeaderSuccess := false
	defer func() {
		metrics.GetHeaderLatencyHistogram.Record(
			req.Context(),
			float64(time.Since(requestTime).Milliseconds()),
		)
		status := "error"
		if getHeaderSuccess {
			status = "success"
		}
		metrics.GetHeaderCount.Add(req.Context(), 1,
			otelapi.WithAttributes(attribute.String("status", status)),
		)
	}()

	if slices.Contains(apiNoHeaderUserAgents, ua) {
		log.Info("rejecting getHeader by user agent")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if api.ffForceGetHeader204 {
		log.Info("forced getHeader 204 response")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Only allow requests for the current slot until a certain cutoff time
	if getHeaderRequestCutoffMs > 0 && msIntoSlot > 0 && msIntoSlot > int64(getHeaderRequestCutoffMs) {
		log.Info("getHeader sent too late")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	bid, err := api.redis.GetBestBid(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		log.WithError(err).Error("could not get bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if bid == nil || bid.IsEmpty() {
		log.Info("no bid found")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	value, err := bid.Value()
	if err != nil {
		log.WithError(err).Info("could not get bid value")
		api.RespondError(w, http.StatusBadRequest, err.Error())
	}
	blockHash, err := bid.BlockHash()
	if err != nil {
		log.WithError(err).Info("could not get bid block hash")
		api.RespondError(w, http.StatusBadRequest, err.Error())
	}

	// Error on bid without value
	if value.Cmp(uint256.NewInt(0)) == 0 {
		log.Info("bid has no value")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.WithFields(logrus.Fields{
		"value":     value.String(),
		"blockHash": blockHash.String(),
	}).Info("bid delivered")
	getHeaderSuccess = true

	switch negotiatedResponseMediaType {
	case common.ApplicationOctetStream:
		log.Debug("responding with SSZ")
		api.respondGetHeaderSSZ(w, bid)
	default:
		log.Debug("responding with JSON")
		api.RespondOK(w, bid)
	}
}

// respondGetHeaderSSZ responds to the proposer in SSZ
func (api *RelayAPI) respondGetHeaderSSZ(w http.ResponseWriter, bid *builderSpec.VersionedSignedBuilderBid) {
	// Serialize the response
	var err error
	var sszData []byte
	switch bid.Version {
	case spec.DataVersionBellatrix:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionBellatrix)
		sszData, err = bid.Bellatrix.MarshalSSZ()
	case spec.DataVersionCapella:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionCapella)
		sszData, err = bid.Capella.MarshalSSZ()
	case spec.DataVersionDeneb:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionDeneb)
		sszData, err = bid.Deneb.MarshalSSZ()
	case spec.DataVersionElectra:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionElectra)
		sszData, err = bid.Electra.MarshalSSZ()
	case spec.DataVersionFulu:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionFulu)
		sszData, err = bid.Fulu.MarshalSSZ()
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair:
		err = ErrInvalidForkVersion
	}
	if err != nil {
		api.log.WithError(err).Error("error serializing response as SSZ")
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	// Write the header
	w.Header().Set(HeaderContentType, common.ApplicationOctetStream)
	w.WriteHeader(http.StatusOK)

	// Write SSZ data
	if _, err := w.Write(sszData); err != nil {
		api.log.WithError(err).Error("error writing SSZ response")
		http.Error(w, "failed to write response", http.StatusInternalServerError)
	}
}

func (api *RelayAPI) checkProposerSignature(block *common.VersionedSignedBlindedBeaconBlock, pubKey []byte) (bool, error) {
	switch block.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return verifyBlockSignature(block, api.opts.EthNetDetails.DomainBeaconProposerCapella, pubKey)
	case spec.DataVersionDeneb:
		return verifyBlockSignature(block, api.opts.EthNetDetails.DomainBeaconProposerDeneb, pubKey)
	case spec.DataVersionElectra:
		return verifyBlockSignature(block, api.opts.EthNetDetails.DomainBeaconProposerElectra, pubKey)
	case spec.DataVersionFulu:
		return verifyBlockSignature(block, api.opts.EthNetDetails.DomainBeaconProposerFulu, pubKey)
	default:
		return false, errors.New("unsupported consensus data version")
	}
}

// Deprecated: Use handleGetPayloadV2. For more info visit: https://github.com/ethereum/builder-specs/issues/119
func (api *RelayAPI) handleGetPayloadV1(w http.ResponseWriter, req *http.Request) {
	// Negotiate the response media type
	negotiatedResponseMediaType, err := NegotiateRequestResponseType(req)
	if err != nil {
		api.log.WithError(err).Error("failed to negotiate response type")
		api.RespondError(w, http.StatusNotAcceptable, err.Error())
		return
	}
	api.innerHandleGetPayload(w, req, HandleGetPayloadVersionV1, negotiatedResponseMediaType)
}

func (api *RelayAPI) handleGetPayloadV2(w http.ResponseWriter, req *http.Request) {
	api.innerHandleGetPayload(w, req, HandleGetPayloadVersionV2, "")
}

func (api *RelayAPI) innerHandleGetPayload(w http.ResponseWriter, req *http.Request, version HandleGetPayloadVersion, negotiatedResponseMediaType string) {
	api.getPayloadCallsInFlight.Add(1)
	defer api.getPayloadCallsInFlight.Done()

	// Determine what encoding the proposer sent
	proposerContentType := req.Header.Get(HeaderContentType)
	proposerContentType, _, err := mime.ParseMediaType(proposerContentType)
	if err != nil {
		api.log.WithError(err).Error("failed to parse proposer content type")
		api.RespondError(w, http.StatusUnsupportedMediaType, err.Error())
		return
	}

	// Get the optional consensus version
	proposerEthConsensusVersion := req.Header.Get(HeaderEthConsensusVersion)

	ua := req.UserAgent()
	headSlot := api.headSlot.Load()
	receivedAt := time.Now().UTC()
	log := api.log.WithFields(logrus.Fields{
		"method":                      "getPayload",
		"version":                     version,
		"ua":                          ua,
		"mevBoostV":                   common.GetMevBoostVersionFromUserAgent(ua),
		"contentLength":               req.ContentLength,
		"headSlot":                    headSlot,
		"headSlotEpochPos":            (headSlot % common.SlotsPerEpoch) + 1,
		"idArg":                       req.URL.Query().Get("id"),
		"timestampRequestStart":       receivedAt.UnixMilli(),
		"negotiatedResponseMediaType": negotiatedResponseMediaType,
		"proposerContentType":         proposerContentType,
		"proposerEthConsensusVersion": proposerEthConsensusVersion,
	})

	// Log at start and end of request
	log.Info("request initiated")
	getPayloadSuccess := false
	defer func() {
		log.WithFields(logrus.Fields{
			"timestampRequestFin": time.Now().UTC().UnixMilli(),
			"requestDurationMs":   time.Since(receivedAt).Milliseconds(),
		}).Info("request finished")

		metrics.GetPayloadLatencyHistogram.Record(
			req.Context(),
			float64(time.Since(receivedAt).Milliseconds()),
		)
		status := "error"
		if getPayloadSuccess {
			status = "success"
		}
		metrics.GetPayloadCount.Add(req.Context(), 1,
			otelapi.WithAttributes(attribute.String("status", status)),
		)
	}()

	// Read the body first, so we can decode it later
	limitReader := io.LimitReader(req.Body, int64(apiMaxPayloadBytes))
	body, err := io.ReadAll(limitReader)
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

	// Decode payload
	payload := new(common.VersionedSignedBlindedBeaconBlock)
	err = payload.Unmarshal(body, proposerContentType, proposerEthConsensusVersion)
	if err != nil {
		log.WithError(err).Warn("failed to decode getPayload request")
		api.RespondError(w, http.StatusBadRequest, "failed to decode payload")
		return
	}
	slot, err := payload.Slot()
	if err != nil {
		log.WithError(err).Warn("failed to get payload slot")
		api.RespondError(w, http.StatusBadRequest, "failed to get payload slot")
		return
	}

	err = api.checkPayloadAndHeaderVersion(payload, uint64(slot), proposerEthConsensusVersion)
	if err != nil {
		log.WithError(err).Warn("error checking payload and header version")
		api.RespondError(w, http.StatusBadRequest, errors.Wrap(err, "error checking payload and header version").Error())
		return
	}

	// Take time after the decoding, and add to logging
	decodeTime := time.Now().UTC()
	blockHash, err := payload.ExecutionBlockHash()
	if err != nil {
		log.WithError(err).Warn("failed to get payload block hash")
		api.RespondError(w, http.StatusBadRequest, "failed to get payload block hash")
		return
	}
	proposerIndex, err := payload.ProposerIndex()
	if err != nil {
		log.WithError(err).Warn("failed to get payload proposer index")
		api.RespondError(w, http.StatusBadRequest, "failed to get payload proposer index")
		return
	}
	slotStartTimestamp := api.genesisInfo.Data.GenesisTime + (uint64(slot) * common.SecondsPerSlot)
	msIntoSlot := decodeTime.UnixMilli() - int64(slotStartTimestamp*1000) //nolint:gosec
	log = log.WithFields(logrus.Fields{
		"slot":                 slot,
		"slotEpochPos":         (uint64(slot) % common.SlotsPerEpoch) + 1,
		"blockHash":            blockHash.String(),
		"slotStartSec":         slotStartTimestamp,
		"msIntoSlot":           msIntoSlot,
		"timestampAfterDecode": decodeTime.UnixMilli(),
		"proposerIndex":        proposerIndex,
	})

	// Ensure the proposer index is expected
	api.proposerDutiesLock.RLock()
	slotDuty := api.proposerDutiesMap[uint64(slot)]
	api.proposerDutiesLock.RUnlock()
	if slotDuty == nil {
		log.Warn("could not find slot duty")
	} else {
		log = log.WithField("feeRecipient", slotDuty.Entry.Message.FeeRecipient.String())
		if slotDuty.ValidatorIndex != uint64(proposerIndex) {
			log.WithField("expectedProposerIndex", slotDuty.ValidatorIndex).Warn("not the expected proposer index")
			api.RespondError(w, http.StatusBadRequest, "not the expected proposer index")
			return
		}
	}

	// Get the proposer pubkey based on the validator index from the payload
	proposerPubkey, found := api.datastore.GetKnownValidatorPubkeyByIndex(uint64(proposerIndex))
	if !found {
		log.Errorf("could not find proposer pubkey for index %d", proposerIndex)
		api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	// Add proposer pubkey to logs
	log = log.WithField("proposerPubkey", proposerPubkey)

	// Create a BLS pubkey from the hex pubkey
	pk, err := proposerPubkey.ToPubkey()
	if err != nil {
		log.WithError(err).Warn("could not convert pubkey to phase0.BLSPubKey")
		api.RespondError(w, http.StatusBadRequest, "could not convert pubkey to phase0.BLSPubKey")
		return
	}

	// Validate proposer signature
	ok, err := api.checkProposerSignature(payload, pk[:])
	if !ok || err != nil {
		if api.ffLogInvalidSignaturePayload {
			txt, _ := json.Marshal(payload)
			log.Info("payload_invalid_sig: ", string(txt), "pubkey:", proposerPubkey)
		}
		log.WithError(err).Warn("could not verify payload signature")
		api.RespondError(w, http.StatusBadRequest, "could not verify payload signature")
		return
	}

	// Log about received payload (with a valid proposer signature)
	log = log.WithField("timestampAfterSignatureVerify", time.Now().UTC().UnixMilli())
	log.Info("getPayload request received")

	var getPayloadResp *builderApi.VersionedSubmitBlindedBlockResponse
	var msNeededForPublishing uint64

	// Save information about delivered payload
	defer func() {
		bidTrace, err := api.redis.GetBidTrace(uint64(slot), proposerPubkey.String(), blockHash.String())
		if err != nil {
			log.WithError(err).Info("failed to get bidTrace for delivered payload from redis")
			return
		}

		err = api.db.SaveDeliveredPayload(bidTrace, payload, decodeTime, msNeededForPublishing)
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
		api.optimisticBlocksWG.Wait()

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
		log.Warn("demotion found in getPayload, inserting refund justification")

		// Prepare refund data.
		signedBeaconBlock, err := common.SignedBlindedBeaconBlockToBeaconBlock(payload, getPayloadResp)
		if err != nil {
			log.WithError(err).Error("failed to convert signed blinded beacon block to beacon block")
			api.RespondError(w, http.StatusInternalServerError, "failed to convert signed blinded beacon block to beacon block")
			return
		}

		// Get registration entry from the DB.
		registrationEntry, err := api.db.GetValidatorRegistration(proposerPubkey.String())
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.WithError(err).Error("no registration found for validator " + proposerPubkey)
			} else {
				log.WithError(err).Error("error reading validator registration")
			}
		}
		var signedRegistration *builderApiV1.SignedValidatorRegistration
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

	// Get the response - from Redis, Memcache or DB
	// note that recent mev-boost versions only send getPayload to relays that provided the bid
	getPayloadResp, err = api.datastore.GetGetPayloadResponse(log, uint64(slot), proposerPubkey.String(), blockHash.String())
	if err != nil || getPayloadResp == nil {
		log.WithError(err).Warn("failed getting execution payload (1/2)")
		time.Sleep(time.Duration(timeoutGetPayloadRetryMs) * time.Millisecond)

		// Try again
		getPayloadResp, err = api.datastore.GetGetPayloadResponse(log, uint64(slot), proposerPubkey.String(), blockHash.String())
		if err != nil || getPayloadResp == nil {
			// Still not found! Error out now.
			if errors.Is(err, datastore.ErrExecutionPayloadNotFound) {
				// Couldn't find the execution payload, maybe it never was submitted to our relay! Check that now
				bid, err := api.db.GetBlockSubmissionEntry(uint64(slot), proposerPubkey.String(), blockHash.String())
				if errors.Is(err, sql.ErrNoRows) {
					log.Warn("failed getting execution payload (2/2) - payload not found, block was never submitted to this relay")
					api.RespondError(w, http.StatusBadRequest, "no execution payload for this request - block was never seen by this relay")
				} else if err != nil {
					log.WithError(err).Error("failed getting execution payload (2/2) - payload not found, and error on checking bids")
				} else if bid.EligibleAt.Valid {
					log.Error("failed getting execution payload (2/2) - payload not found, but found bid in database")
				} else {
					log.Info("found bid but payload was never saved as bid was ineligible being below floor value")
				}
			} else { // some other error
				log.WithError(err).Error("failed getting execution payload (2/2) - error")
			}
			api.RespondError(w, http.StatusBadRequest, "no execution payload for this request")
			return
		}
	}

	// Now we know this relay also has the payload
	log = log.WithField("timestampAfterLoadResponse", time.Now().UTC().UnixMilli())

	// Check whether getPayload has already been called -- TODO: do we need to allow multiple submissions of one blinded block?
	err = api.redis.CheckAndSetLastSlotAndHashDelivered(uint64(slot), blockHash.String())
	log = log.WithField("timestampAfterAlreadyDeliveredCheck", time.Now().UTC().UnixMilli())
	if err != nil {
		if errors.Is(err, datastore.ErrAnotherPayloadAlreadyDeliveredForSlot) {
			// BAD VALIDATOR, 2x GETPAYLOAD FOR DIFFERENT PAYLOADS
			log.Warn("validator called getPayload twice for different payload hashes")
			api.RespondError(w, http.StatusBadRequest, "another payload for this slot was already delivered")
			return
		} else if errors.Is(err, datastore.ErrPastSlotAlreadyDelivered) {
			// BAD VALIDATOR, 2x GETPAYLOAD FOR PAST SLOT
			log.Warn("validator called getPayload for past slot")
			api.RespondError(w, http.StatusBadRequest, "payload for this slot was already delivered")
			return
		} else if errors.Is(err, redis.TxFailedErr) {
			// BAD VALIDATOR, 2x GETPAYLOAD + RACE
			log.Warn("validator called getPayload twice (race)")
			api.RespondError(w, http.StatusBadRequest, "payload for this slot was already delivered (race)")
			return
		}
		log.WithError(err).Error("redis.CheckAndSetLastSlotAndHashDelivered failed")
	}

	// Handle early/late requests
	if msIntoSlot < 0 {
		// Wait until slot start (t=0) if still in the future
		_msSinceSlotStart := time.Now().UTC().UnixMilli() - int64(slotStartTimestamp*1000) //nolint:gosec
		if _msSinceSlotStart < 0 {
			delayMillis := _msSinceSlotStart * -1
			log = log.WithField("delayMillis", delayMillis)
			log.Info("waiting until slot start t=0")
			time.Sleep(time.Duration(delayMillis) * time.Millisecond)
		}
	} else if getPayloadRequestCutoffMs > 0 && msIntoSlot > int64(getPayloadRequestCutoffMs) {
		// Reject requests after cutoff time
		log.Warn("getPayload sent too late")
		api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("sent too late - %d ms into slot", msIntoSlot))

		go func() {
			err := api.db.InsertTooLateGetPayload(uint64(slot), proposerPubkey.String(), blockHash.String(), slotStartTimestamp, uint64(receivedAt.UnixMilli()), uint64(decodeTime.UnixMilli()), uint64(msIntoSlot)) //nolint:gosec
			if err != nil {
				log.WithError(err).Error("failed to insert payload too late into db")
			}
		}()
		return
	}

	// Check that BlindedBlockContent fields (sent by the proposer) match our known BlockContents
	err = EqBlindedBlockContentsToBlockContents(payload, getPayloadResp)
	if err != nil {
		log.WithError(err).Warn("ExecutionPayloadHeader not matching known ExecutionPayload")
		api.RespondError(w, http.StatusBadRequest, "invalid execution payload header")
		return
	}

	// Convert to signed beacon block
	signedBeaconBlock, err := common.SignedBlindedBeaconBlockToBeaconBlock(payload, getPayloadResp)
	if err != nil {
		log.WithError(err).Error("failed to convert signed blinded beacon block to beacon block")
		api.RespondError(w, http.StatusInternalServerError, "failed to convert signed blinded beacon block to beacon block")
		return
	}

	if version == HandleGetPayloadVersionV1 {
		timeBeforePublish := time.Now().UTC().UnixMilli()
		log = log.WithField("timestampBeforePublishing", timeBeforePublish)

		code, err := api.beaconClient.PublishBlock(signedBeaconBlock) // errors are logged inside
		if err != nil || (code != http.StatusOK && code != http.StatusAccepted) {
			log.WithError(err).WithField("code", code).Error("failed to publish block")
			api.RespondError(w, http.StatusBadRequest, "failed to publish block")
			return
		}

		timeAfterPublish := time.Now().UTC().UnixMilli()
		msNeededForPublishing = uint64(timeAfterPublish - timeBeforePublish) //nolint:gosec
		log = log.WithField("timestampAfterPublishing", timeAfterPublish)
		log.WithField("msNeededForPublishing", msNeededForPublishing).Info("block published through beacon node")
		metrics.PublishBlockLatencyHistogram.Record(req.Context(), float64(msNeededForPublishing))

		// give the beacon network some time to propagate the block
		time.Sleep(time.Duration(getPayloadResponseDelayMs) * time.Millisecond)

		// Respond appropriately
		getPayloadSuccess = true
		switch negotiatedResponseMediaType {
		case common.ApplicationOctetStream:
			log.Debug("responding with SSZ")
			api.respondGetPayloadSSZ(w, getPayloadResp)
		default:
			log.Debug("responding with JSON")
			api.RespondOK(w, getPayloadResp)
		}
	} else {
		// Start async block publishing process
		go func() {
			timeBeforePublish := time.Now().UTC().UnixMilli()
			log := log.WithField("timestampBeforePublishing", timeBeforePublish)

			code, err := api.beaconClient.PublishBlock(signedBeaconBlock) // errors are logged inside
			if err != nil || (code != http.StatusOK && code != http.StatusAccepted) {
				log.WithError(err).WithField("code", code).Error("failed to publish block")
				return
			}
			timeAfterPublish := time.Now().UTC().UnixMilli()
			msNeededForPublishing := uint64(timeAfterPublish - timeBeforePublish) //nolint:gosec

			log = log.WithFields(logrus.Fields{
				"timestampAfterPublishing": timeAfterPublish,
				"msNeededForPublishing":    msNeededForPublishing,
			})

			log.Info("block published through beacon node")
			metrics.PublishBlockLatencyHistogram.Record(context.Background(), float64(msNeededForPublishing))
		}()

		log.Debug("responding with only accepted status code")
		getPayloadSuccess = true
		w.WriteHeader(http.StatusAccepted)
	}

	blockNumber, err := payload.ExecutionBlockNumber()
	if err != nil {
		log.WithError(err).Info("failed to get block number")
	}
	txs, err := getPayloadResp.Transactions()
	if err != nil {
		log.WithError(err).Info("failed to get transactions")
	}
	log = log.WithFields(logrus.Fields{
		"numTx":       len(txs),
		"blockNumber": blockNumber,
	})
	if getPayloadResp.Version >= spec.DataVersionDeneb {
		blobs, err := getPayloadResp.Blobs()
		if err != nil {
			log.WithError(err).Info("failed to get blobs")
		}
		blobGasUsed, err := getPayloadResp.BlobGasUsed()
		if err != nil {
			log.WithError(err).Info("failed to get blobGasUsed")
		}
		excessBlobGas, err := getPayloadResp.ExcessBlobGas()
		if err != nil {
			log.WithError(err).Info("failed to get excessBlobGas")
		}
		log = log.WithFields(logrus.Fields{
			"numBlobs":      len(blobs),
			"blobGasUsed":   blobGasUsed,
			"excessBlobGas": excessBlobGas,
		})
	}
	log.Info("execution payload delivered")
}

func (api *RelayAPI) checkPayloadAndHeaderVersion(payload *common.VersionedSignedBlindedBeaconBlock, slot uint64, proposerEthConsensusVersion string) error {
	switch api.getForkFromSlot(slot) { //nolint:exhaustive
	case spec.DataVersionFulu:
		if proposerEthConsensusVersion != common.EthConsensusVersionFulu {
			return errors.Errorf("Fulu payload with wrong consensus version. Expected: %s, Got: %s", common.EthConsensusVersionFulu, proposerEthConsensusVersion)
		}
		if payload.Fulu == nil {
			return errors.New("Non-Fulu payload detected and rejected. You need to update mev-boost!")
		}

	case spec.DataVersionElectra:
		if proposerEthConsensusVersion != common.EthConsensusVersionElectra {
			return errors.Errorf("Electra payload with wrong consensus version. Expected: %s, Got: %s", common.EthConsensusVersionElectra, proposerEthConsensusVersion)
		}
		if payload.Electra == nil {
			return errors.New("Non-Electra payload detected and rejected. You need to update mev-boost!")
		}

	case spec.DataVersionDeneb:
		if proposerEthConsensusVersion != common.EthConsensusVersionDeneb {
			return errors.Errorf("Deneb payload with wrong consensus version. Expected: %s, Got: %s", common.EthConsensusVersionDeneb, proposerEthConsensusVersion)
		}
		if payload.Deneb == nil {
			return errors.New("Non-Deneb payload detected and rejected. You need to update mev-boost!")
		}

	case spec.DataVersionCapella:
		if proposerEthConsensusVersion != common.EthConsensusVersionCapella {
			return errors.Errorf("Capella payload with wrong consensus version. Expected: %s, Got: %s", common.EthConsensusVersionCapella, proposerEthConsensusVersion)
		}
		if payload.Capella == nil {
			return errors.New("Non-Capella payload detected and rejected. You need to update mev-boost!")
		}

	case spec.DataVersionBellatrix:
		if proposerEthConsensusVersion != common.EthConsensusVersionBellatrix {
			return errors.Errorf("Bellatrix payload with wrong consensus version. Expected: %s, Got: %s", common.EthConsensusVersionBellatrix, proposerEthConsensusVersion)
		}
		if payload.Bellatrix == nil {
			return errors.New("Non-Bellatrix payload detected and rejected. You need to update mev-boost!")
		}
	case spec.DataVersionUnknown:
		return errors.New("unknown payload version")
	}
	return nil
}

// respondGetPayloadSSZ responds to the proposer in SSZ
func (api *RelayAPI) respondGetPayloadSSZ(w http.ResponseWriter, result *builderApi.VersionedSubmitBlindedBlockResponse) {
	// Serialize the response
	var err error
	var sszData []byte
	switch result.Version {
	case spec.DataVersionBellatrix:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionBellatrix)
		sszData, err = result.Bellatrix.MarshalSSZ()
	case spec.DataVersionCapella:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionCapella)
		sszData, err = result.Capella.MarshalSSZ()
	case spec.DataVersionDeneb:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionDeneb)
		sszData, err = result.Deneb.MarshalSSZ()
	case spec.DataVersionElectra:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionElectra)
		sszData, err = result.Electra.MarshalSSZ()
	case spec.DataVersionFulu:
		w.Header().Set(HeaderEthConsensusVersion, common.EthConsensusVersionFulu)
		sszData, err = result.Fulu.MarshalSSZ()
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair:
		err = ErrInvalidForkVersion
	}
	if err != nil {
		api.log.WithError(err).Error("error serializing response as SSZ")
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	// Write the header
	w.Header().Set(HeaderContentType, common.ApplicationOctetStream)
	w.WriteHeader(http.StatusOK)

	// Write SSZ data
	if _, err := w.Write(sszData); err != nil {
		api.log.WithError(err).Error("error writing SSZ response")
		http.Error(w, "failed to write response", http.StatusInternalServerError)
	}
}

// --------------------
//
//	BLOCK BUILDER APIS
//
// --------------------
func (api *RelayAPI) handleBuilderGetValidators(w http.ResponseWriter, req *http.Request) {
	api.proposerDutiesLock.RLock()
	resp := api.proposerDutiesResponse
	api.proposerDutiesLock.RUnlock()
	_, err := w.Write(*resp)
	if err != nil {
		api.log.WithError(err).Warn("failed to write response for builderGetValidators")
	}
}

func (api *RelayAPI) checkSubmissionFeeRecipient(w http.ResponseWriter, log *logrus.Entry, bidTrace *builderApiV1.BidTrace) (uint64, bool) {
	api.proposerDutiesLock.RLock()
	slotDuty := api.proposerDutiesMap[bidTrace.Slot]
	api.proposerDutiesLock.RUnlock()
	if slotDuty == nil {
		log.Warn("could not find slot duty")
		api.RespondError(w, http.StatusBadRequest, "could not find slot duty")
		return 0, false
	} else if !strings.EqualFold(slotDuty.Entry.Message.FeeRecipient.String(), bidTrace.ProposerFeeRecipient.String()) {
		log.WithFields(logrus.Fields{
			"expectedFeeRecipient": slotDuty.Entry.Message.FeeRecipient.String(),
			"actualFeeRecipient":   bidTrace.ProposerFeeRecipient.String(),
		}).Info("fee recipient does not match")
		api.RespondError(w, http.StatusBadRequest, "fee recipient does not match")
		return 0, false
	}
	return slotDuty.Entry.Message.GasLimit, true
}

func (api *RelayAPI) checkSubmissionPayloadAttrs(w http.ResponseWriter, log *logrus.Entry, submission *common.BlockSubmissionInfo) (payloadAttributesHelper, bool) {
	api.payloadAttributesLock.RLock()
	attrs, ok := api.payloadAttributes[getPayloadAttributesKey(submission.BidTrace.ParentHash.String(), submission.BidTrace.Slot)]
	api.payloadAttributesLock.RUnlock()
	if !ok || submission.BidTrace.Slot != attrs.slot {
		log.WithFields(logrus.Fields{
			"attributesFound": ok,
			"payloadSlot":     submission.BidTrace.Slot,
			"attrsSlot":       attrs.slot,
		}).Warn("payload attributes not (yet) known")
		api.RespondError(w, http.StatusBadRequest, "payload attributes not (yet) known")
		return attrs, false
	}

	if submission.PrevRandao.String() != attrs.payloadAttributes.PrevRandao {
		msg := fmt.Sprintf("incorrect prev_randao - got: %s, expected: %s", submission.PrevRandao.String(), attrs.payloadAttributes.PrevRandao)
		log.Info(msg)
		api.RespondError(w, http.StatusBadRequest, msg)
		return attrs, false
	}

	if hasReachedFork(submission.BidTrace.Slot, api.capellaEpoch) {
		withdrawalsRoot, err := ComputeWithdrawalsRoot(submission.Withdrawals)
		if err != nil {
			log.WithError(err).Warn("could not compute withdrawals root from payload")
			api.RespondError(w, http.StatusBadRequest, "could not compute withdrawals root")
			return attrs, false
		}
		if withdrawalsRoot != attrs.withdrawalsRoot {
			msg := fmt.Sprintf("incorrect withdrawals root - got: %s, expected: %s", withdrawalsRoot.String(), attrs.withdrawalsRoot.String())
			log.Info(msg)
			api.RespondError(w, http.StatusBadRequest, msg)
			return attrs, false
		}
	}

	return attrs, true
}

func (api *RelayAPI) checkSubmissionSlotDetails(w http.ResponseWriter, log *logrus.Entry, headSlot uint64, payload *common.VersionedSubmitBlockRequest, submission *common.BlockSubmissionInfo) bool {
	if api.isFulu(submission.BidTrace.Slot) && payload.Fulu == nil {
		log.Info("rejecting submission - non fulu payload for fulu fork")
		api.RespondError(w, http.StatusBadRequest, "not fulu payload")
		return false
	}
	if api.isElectra(submission.BidTrace.Slot) && payload.Electra == nil {
		log.Info("rejecting submission - non electra payload for electra fork")
		api.RespondError(w, http.StatusBadRequest, "not electra payload")
		return false
	}
	if api.isDeneb(submission.BidTrace.Slot) && payload.Deneb == nil {
		log.Info("rejecting submission - non deneb payload for deneb fork")
		api.RespondError(w, http.StatusBadRequest, "not deneb payload")
		return false
	}
	if api.isCapella(submission.BidTrace.Slot) && payload.Capella == nil {
		log.Info("rejecting submission - non capella payload for capella fork")
		api.RespondError(w, http.StatusBadRequest, "not capella payload")
		return false
	}

	if submission.BidTrace.Slot <= headSlot {
		log.Info("submitNewBlock failed: submission for past slot")
		api.RespondError(w, http.StatusBadRequest, "submission for past slot")
		return false
	}

	// Timestamp check
	expectedTimestamp := api.genesisInfo.Data.GenesisTime + (submission.BidTrace.Slot * common.SecondsPerSlot)
	if submission.Timestamp != expectedTimestamp {
		log.Warnf("incorrect timestamp. got %d, expected %d", submission.Timestamp, expectedTimestamp)
		api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("incorrect timestamp. got %d, expected %d", submission.Timestamp, expectedTimestamp))
		return false
	}

	return true
}

func (api *RelayAPI) checkBuilderEntry(w http.ResponseWriter, log *logrus.Entry, builderPubkey phase0.BLSPubKey) (*blockBuilderCacheEntry, bool) {
	builderEntry, ok := api.blockBuildersCache[builderPubkey.String()]
	if !ok {
		log.Infof("unable to read builder: %s from the builder cache, using low-prio and no collateral", builderPubkey.String())
		builderEntry = &blockBuilderCacheEntry{
			status: common.BuilderStatus{
				IsHighPrio:    false,
				IsOptimistic:  false,
				IsBlacklisted: false,
			},
			collateral: big.NewInt(0),
		}
	}

	if builderEntry.status.IsBlacklisted {
		log.Info("builder is blacklisted")
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		return builderEntry, false
	}

	// In case only high-prio requests are accepted, fail others
	if api.ffDisableLowPrioBuilders && !builderEntry.status.IsHighPrio {
		log.Info("rejecting low-prio builder (ff-disable-low-prio-builders)")
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		return builderEntry, false
	}

	return builderEntry, true
}

type bidFloorOpts struct {
	w                    http.ResponseWriter
	tx                   redis.Pipeliner
	log                  *logrus.Entry
	cancellationsEnabled bool
	simResultC           chan *blockSimResult
	submission           *common.BlockSubmissionInfo
}

func (api *RelayAPI) checkFloorBidValue(opts bidFloorOpts) (*big.Int, bool) {
	// Reject new submissions once the payload for this slot was delivered - TODO: store in memory as well
	slotLastPayloadDelivered, err := api.redis.GetLastSlotDelivered(context.Background(), opts.tx)
	if err != nil && !errors.Is(err, redis.Nil) {
		opts.log.WithError(err).Error("failed to get delivered payload slot from redis")
	} else if opts.submission.BidTrace.Slot <= slotLastPayloadDelivered {
		opts.log.Info("rejecting submission because payload for this slot was already delivered")
		api.RespondError(opts.w, http.StatusBadRequest, "payload for this slot was already delivered")
		return nil, false
	}

	// Grab floor bid value
	floorBidValue, err := api.redis.GetFloorBidValue(context.Background(), opts.tx, opts.submission.BidTrace.Slot, opts.submission.BidTrace.ParentHash.String(), opts.submission.BidTrace.ProposerPubkey.String())
	if err != nil {
		opts.log.WithError(err).Error("failed to get floor bid value from redis")
	} else {
		opts.log = opts.log.WithField("floorBidValue", floorBidValue.String())
	}

	// --------------------------------------------
	// Skip submission if below the floor bid value
	// --------------------------------------------
	isBidBelowFloor := floorBidValue != nil && opts.submission.BidTrace.Value.ToBig().Cmp(floorBidValue) == -1
	isBidAtOrBelowFloor := floorBidValue != nil && opts.submission.BidTrace.Value.ToBig().Cmp(floorBidValue) < 1
	if opts.cancellationsEnabled && isBidBelowFloor { // with cancellations: if below floor -> delete previous bid
		opts.simResultC <- &blockSimResult{false, nil, false, nil, nil}
		opts.log.Info("submission below floor bid value, with cancellation")
		err := api.redis.DelBuilderBid(context.Background(), opts.tx, opts.submission.BidTrace.Slot, opts.submission.BidTrace.ParentHash.String(), opts.submission.BidTrace.ProposerPubkey.String(), opts.submission.BidTrace.BuilderPubkey.String())
		if err != nil {
			opts.log.WithError(err).Error("failed processing cancellable bid below floor")
			api.RespondError(opts.w, http.StatusInternalServerError, "failed processing cancellable bid below floor")
			return nil, false
		}
		api.Respond(opts.w, http.StatusAccepted, "accepted bid below floor, skipped validation")
		return nil, false
	} else if !opts.cancellationsEnabled && isBidAtOrBelowFloor { // without cancellations: if at or below floor -> ignore
		opts.simResultC <- &blockSimResult{false, nil, false, nil, nil}
		opts.log.Info("submission at or below floor bid value, without cancellation")
		api.RespondMsg(opts.w, http.StatusAccepted, "accepted bid below floor, skipped validation")
		return nil, false
	}
	return floorBidValue, true
}

type redisUpdateBidOpts struct {
	w                    http.ResponseWriter
	tx                   redis.Pipeliner
	log                  *logrus.Entry
	cancellationsEnabled bool
	receivedAt           time.Time
	floorBidValue        *big.Int
	payload              *common.VersionedSubmitBlockRequest
}

func (api *RelayAPI) updateRedisBid(opts redisUpdateBidOpts) (*datastore.SaveBidAndUpdateTopBidResponse, *builderApi.VersionedSubmitBlindedBlockResponse, bool) {
	// Prepare the response data
	getHeaderResponse, err := common.BuildGetHeaderResponse(opts.payload, api.blsSk, api.publicKey, api.opts.EthNetDetails.DomainBuilder)
	if err != nil {
		opts.log.WithError(err).Error("could not sign builder bid")
		api.RespondError(opts.w, http.StatusBadRequest, err.Error())
		return nil, nil, false
	}

	getPayloadResponse, err := common.BuildGetPayloadResponse(opts.payload)
	if err != nil {
		opts.log.WithError(err).Error("could not build getPayload response")
		api.RespondError(opts.w, http.StatusBadRequest, err.Error())
		return nil, nil, false
	}

	submission, err := common.GetBlockSubmissionInfo(opts.payload)
	if err != nil {
		opts.log.WithError(err).Error("could not get block submission info")
		api.RespondError(opts.w, http.StatusBadRequest, err.Error())
		return nil, nil, false
	}

	bidTrace := common.BidTraceV2WithBlobFields{
		BidTrace:      *submission.BidTrace,
		BlockNumber:   submission.BlockNumber,
		NumTx:         uint64(len(submission.Transactions)),
		NumBlobs:      uint64(len(submission.Blobs)),
		BlobGasUsed:   submission.BlobGasUsed,
		ExcessBlobGas: submission.ExcessBlobGas,
	}

	//
	// Save to Redis
	//
	updateBidResult, err := api.redis.SaveBidAndUpdateTopBid(context.Background(), opts.tx, &bidTrace, opts.payload, getPayloadResponse, getHeaderResponse, opts.receivedAt, opts.cancellationsEnabled, opts.floorBidValue)
	if err != nil {
		opts.log.WithError(err).Error("could not save bid and update top bids")
		api.RespondError(opts.w, http.StatusInternalServerError, "failed saving and updating bid")
		return nil, nil, false
	}
	return &updateBidResult, getPayloadResponse, true
}

func (api *RelayAPI) getForkFromSlot(slot uint64) spec.DataVersion {
	switch {
	case api.isFulu(slot):
		return spec.DataVersionFulu
	case api.isElectra(slot):
		return spec.DataVersionElectra
	case api.isDeneb(slot):
		return spec.DataVersionDeneb
	case api.isCapella(slot):
		return spec.DataVersionCapella
	default:
		return spec.DataVersionUnknown
	}
}

func (api *RelayAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	var pf common.Profile
	var prevTime, nextTime time.Time

	headSlot := api.headSlot.Load()
	receivedAt := time.Now().UTC()
	prevTime = receivedAt
	submissionSuccess := false

	args := req.URL.Query()
	isCancellationEnabled := args.Get("cancellations") == "1"

	log := api.log.WithFields(logrus.Fields{
		"method":                "submitNewBlock",
		"contentLength":         req.ContentLength,
		"headSlot":              headSlot,
		"cancellationEnabled":   isCancellationEnabled,
		"timestampRequestStart": receivedAt.UnixMilli(),
	})

	// Log at start and end of request
	log.Info("request initiated")
	defer func() {
		log.WithFields(logrus.Fields{
			"timestampRequestFin": time.Now().UTC().UnixMilli(),
			"requestDurationMs":   time.Since(receivedAt).Milliseconds(),
		}).Info("request finished")

		// metrics
		api.saveBlockSubmissionMetrics(pf, receivedAt, submissionSuccess)
	}()

	// If cancellations are disabled but builder requested it, return error
	if isCancellationEnabled && !api.ffEnableCancellations {
		log.Info("builder submitted with cancellations enabled, but feature flag is disabled")
		api.RespondError(w, http.StatusBadRequest, "cancellations are disabled")
		return
	}

	var err error
	var r io.Reader = req.Body
	isGzip := req.Header.Get("Content-Encoding") == "gzip"
	pf.IsGzip = isGzip
	log = log.WithField("reqIsGzip", isGzip)
	if isGzip {
		r, err = gzip.NewReader(req.Body)
		if err != nil {
			log.WithError(err).Warn("could not create gzip reader")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	limitReader := io.LimitReader(r, int64(apiMaxPayloadBytes))
	requestPayloadBytes, err := io.ReadAll(limitReader)
	if err != nil {
		log.WithError(err).Warn("could not read payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	nextTime = time.Now().UTC()
	pf.PayloadLoad = uint64(nextTime.Sub(prevTime).Microseconds()) //nolint:gosec
	prevTime = nextTime

	payload := new(common.VersionedSubmitBlockRequest)

	// Check for SSZ encoding
	contentType, _, err := getHeaderContentType(req.Header)
	if err != nil {
		api.log.WithError(err).Error("failed to parse proposer content type")
		api.RespondError(w, http.StatusUnsupportedMediaType, err.Error())
		return
	}

	if contentType == common.ApplicationOctetStream {
		log = log.WithField("reqContentType", "ssz")
	} else {
		log = log.WithField("reqContentType", "json")
	}

	builderEthConsensusVersion := req.Header.Get(HeaderEthConsensusVersion)
	if builderEthConsensusVersion == "" {
		// don't reject a builder submission if the Eth-Consensus-Version header is not present
		if contentType == common.ApplicationOctetStream {
			slot, err := getSlotFromBuilderSSZPayload(requestPayloadBytes)
			if err != nil {
				log.WithError(err).Warn("could not get slot from builder ssz payload")
				api.RespondError(w, http.StatusBadRequest, err.Error())
				return
			}
			builderEthConsensusVersion = api.getForkFromSlot(slot).String()
		} else {
			slot, err := getSlotFromBuilderJSONPayload(requestPayloadBytes)
			if err != nil {
				log.WithError(err).Warn("could not get slot from builder json payload")
				api.RespondError(w, http.StatusBadRequest, err.Error())
				return
			}
			builderEthConsensusVersion = api.getForkFromSlot(slot).String()
		}
	}

	nextTime = time.Now().UTC()
	if err := payload.UnmarshalWithVersion(requestPayloadBytes, contentType, builderEthConsensusVersion); err != nil {
		log.WithError(err).Warn("could not decode payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	pf.Decode = uint64(nextTime.Sub(prevTime).Microseconds()) //nolint:gosec
	prevTime = nextTime

	isLargeRequest := len(requestPayloadBytes) > fastTrackPayloadSizeLimit
	// getting block submission info also validates bid trace and execution submission are not empty
	submission, err := common.GetBlockSubmissionInfo(payload)
	if err != nil {
		log.WithError(err).Warn("missing fields in submit block request")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Populate profile metadata for metrics
	bidValueWei := submission.BidTrace.Value.ToBig()
	bidValueEth := new(big.Float).Quo(new(big.Float).SetInt(bidValueWei), new(big.Float).SetFloat64(1e18))
	pf.BidValueEth, _ = bidValueEth.Float64()
	pf.PayloadBytes = len(requestPayloadBytes)
	slotStartTimestamp := api.genesisInfo.Data.GenesisTime + (submission.BidTrace.Slot * common.SecondsPerSlot)
	pf.MsIntoSlot = receivedAt.UnixMilli() - int64(slotStartTimestamp*1000) //nolint:gosec

	log = log.WithFields(logrus.Fields{
		"timestampAfterDecoding": time.Now().UTC().UnixMilli(),
		"slot":                   submission.BidTrace.Slot,
		"builderPubkey":          submission.BidTrace.BuilderPubkey.String(),
		"blockHash":              submission.BidTrace.BlockHash.String(),
		"proposerPubkey":         submission.BidTrace.ProposerPubkey.String(),
		"parentHash":             submission.BidTrace.ParentHash.String(),
		"value":                  submission.BidTrace.Value.Dec(),
		"numTx":                  len(submission.Transactions),
		"payloadBytes":           len(requestPayloadBytes),
		"isLargeRequest":         isLargeRequest,
	})
	if payload.Version >= spec.DataVersionDeneb {
		blobs, err := payload.Blobs()
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		blobGasUsed, err := payload.BlobGasUsed()
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		excessBlobGas, err := payload.ExcessBlobGas()
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log = log.WithFields(logrus.Fields{
			"numBlobs":      len(blobs),
			"blobGasUsed":   blobGasUsed,
			"excessBlobGas": excessBlobGas,
		})
	}

	ok := api.checkSubmissionSlotDetails(w, log, headSlot, payload, submission)
	if !ok {
		return
	}

	builderPubkey := submission.BidTrace.BuilderPubkey
	builderEntry, ok := api.checkBuilderEntry(w, log, builderPubkey)
	if !ok {
		return
	}

	log = log.WithField("builderIsHighPrio", builderEntry.status.IsHighPrio)

	gasLimit, ok := api.checkSubmissionFeeRecipient(w, log, submission.BidTrace)
	if !ok {
		return
	}

	// Don't accept blocks with 0 value
	if submission.BidTrace.Value.ToBig().Cmp(ZeroU256.BigInt()) == 0 || len(submission.Transactions) == 0 {
		log.Info("submitNewBlock failed: block with 0 value or no txs")
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

	attrs, ok := api.checkSubmissionPayloadAttrs(w, log, submission)
	if !ok {
		return
	}

	// Verify the signature
	log = log.WithField("timestampBeforeSignatureCheck", time.Now().UTC().UnixMilli())
	signature := submission.Signature
	ok, err = ssz.VerifySignature(submission.BidTrace, api.opts.EthNetDetails.DomainBuilder, builderPubkey[:], signature[:])
	log = log.WithField("timestampAfterSignatureCheck", time.Now().UTC().UnixMilli())
	if err != nil {
		log.WithError(err).Warn("failed verifying builder signature")
		api.RespondError(w, http.StatusBadRequest, "failed verifying builder signature")
		return
	} else if !ok {
		log.Warn("invalid builder signature")
		api.RespondError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	log = log.WithField("timestampBeforeCheckingFloorBid", time.Now().UTC().UnixMilli())

	// Create the redis pipeline tx
	tx := api.redis.NewTxPipeline()

	// channel to send simulation result to the deferred function
	simResultC := make(chan *blockSimResult, 1)
	var eligibleAt time.Time // will be set once the bid is ready

	bfOpts := bidFloorOpts{
		w:                    w,
		tx:                   tx,
		log:                  log,
		cancellationsEnabled: isCancellationEnabled,
		simResultC:           simResultC,
		submission:           submission,
	}
	floorBidValue, ok := api.checkFloorBidValue(bfOpts)
	if !ok {
		return
	}

	pf.AboveFloorBid = true
	log = log.WithField("timestampAfterCheckingFloorBid", time.Now().UTC().UnixMilli())

	// Deferred saving of the builder submission to database (whenever this function ends)
	defer func() {
		savePayloadToDatabase := !api.ffDisablePayloadDBStorage
		var simResult *blockSimResult
		select {
		case simResult = <-simResultC:
		case <-time.After(10 * time.Second):
			log.Warn("timed out waiting for simulation result")
			simResult = &blockSimResult{false, nil, false, nil, nil}
		}

		dbStart := time.Now()
		submissionEntry, err := api.db.SaveBuilderBlockSubmission(payload, simResult.requestErr, simResult.validationErr, receivedAt, eligibleAt, simResult.wasSimulated, savePayloadToDatabase, pf, simResult.optimisticSubmission, simResult.blockValue)
		metrics.DatabaseSaveLatencyHistogram.Record(context.Background(), float64(time.Since(dbStart).Milliseconds()))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"payload":   payload,
				"simResult": simResult,
			}).Error("saving builder block submission to database failed")
			return
		}

		err = api.db.UpsertBlockBuilderEntryAfterSubmission(submissionEntry, simResult.validationErr != nil)
		if err != nil {
			log.WithError(err).Error("failed to upsert block-builder-entry")
		}
	}()

	// ---------------------------------
	// THE BID WILL BE SIMULATED SHORTLY
	// ---------------------------------

	log = log.WithField("timestampBeforeCheckingTopBid", time.Now().UTC().UnixMilli())

	// Get the latest top bid value from Redis
	bidIsTopBid := false
	topBidValue, err := api.redis.GetTopBidValue(context.Background(), tx, submission.BidTrace.Slot, submission.BidTrace.ParentHash.String(), (submission.BidTrace.ProposerPubkey.String()))
	if err != nil {
		log.WithError(err).Error("failed to get top bid value from redis")
	} else {
		bidIsTopBid = submission.BidTrace.Value.ToBig().Cmp(topBidValue) == 1
		log = log.WithFields(logrus.Fields{
			"topBidValue":    topBidValue.String(),
			"newBidIsTopBid": bidIsTopBid,
		})
	}

	log = log.WithField("timestampAfterCheckingTopBid", time.Now().UTC().UnixMilli())

	nextTime = time.Now().UTC()
	pf.Prechecks = uint64(nextTime.Sub(prevTime).Microseconds()) //nolint:gosec
	prevTime = nextTime

	// Simulate the block submission and save to db
	fastTrackValidation := builderEntry.status.IsHighPrio && bidIsTopBid && !isLargeRequest
	timeBeforeValidation := time.Now().UTC()

	log = log.WithFields(logrus.Fields{
		"timestampBeforeValidation": timeBeforeValidation.UTC().UnixMilli(),
		"fastTrackValidation":       fastTrackValidation,
	})

	// Construct simulation request
	opts := blockSimOptions{
		isHighPrio: builderEntry.status.IsHighPrio,
		fastTrack:  fastTrackValidation,
		log:        log,
		builder:    builderEntry,
		req: &common.BuilderBlockValidationRequest{
			VersionedSubmitBlockRequest: payload,
			RegisteredGasLimit:          gasLimit,
			ParentBeaconBlockRoot:       attrs.parentBeaconRoot,
		},
	}
	// With sufficient collateral, process the block optimistically.
	optimistic := builderEntry.status.IsOptimistic &&
		builderEntry.collateral.Cmp(submission.BidTrace.Value.ToBig()) >= 0 &&
		submission.BidTrace.Slot == api.optimisticSlot.Load()
	pf.Optimistic = optimistic
	if optimistic {
		go api.processOptimisticBlock(opts, simResultC)
	} else {
		// Simulate block (synchronously).
		blockValue, requestErr, validationErr := api.simulateBlock(context.Background(), opts) // success/error logging happens inside
		simResultC <- &blockSimResult{requestErr == nil, blockValue, false, requestErr, validationErr}
		validationDurationMs := time.Since(timeBeforeValidation).Milliseconds()
		log = log.WithFields(logrus.Fields{
			"timestampAfterValidation": time.Now().UTC().UnixMilli(),
			"validationDurationMs":     validationDurationMs,
		})
		if requestErr != nil { // Request error
			if os.IsTimeout(requestErr) {
				api.RespondError(w, http.StatusGatewayTimeout, "validation request timeout")
			} else {
				api.RespondError(w, http.StatusBadRequest, requestErr.Error())
			}
			return
		} else {
			if validationErr != nil {
				api.RespondError(w, http.StatusBadRequest, validationErr.Error())
				return
			}
		}
	}

	nextTime = time.Now().UTC()
	pf.Simulation = uint64(nextTime.Sub(prevTime).Microseconds()) //nolint:gosec
	pf.SimulationSuccess = true
	prevTime = nextTime

	// If cancellations are enabled, then abort now if this submission is not the latest one
	if isCancellationEnabled {
		// Ensure this request is still the latest one. This logic intentionally ignores the value of the bids and makes the current active bid the one
		// that arrived at the relay last. This allows for builders to reduce the value of their bid (effectively cancel a high bid) by ensuring a lower
		// bid arrives later. Even if the higher bid takes longer to simulate, by checking the receivedAt timestamp, this logic ensures that the low bid
		// is not overwritten by the high bid.
		//
		// NOTE: this can lead to a rather tricky race condition. If a builder submits two blocks to the relay concurrently, then the randomness of network
		// latency will make it impossible to predict which arrives first. Thus a high bid could unintentionally be overwritten by a low bid that happened
		// to arrive a few microseconds later. If builders are submitting blocks at a frequency where they cannot reliably predict which bid will arrive at
		// the relay first, they should instead use multiple pubkeys to avoid uninitentionally overwriting their own bids.
		latestPayloadReceivedAt, err := api.redis.GetBuilderLatestPayloadReceivedAt(context.Background(), tx, submission.BidTrace.Slot, submission.BidTrace.BuilderPubkey.String(), submission.BidTrace.ParentHash.String(), submission.BidTrace.ProposerPubkey.String())
		if err != nil {
			log.WithError(err).Error("failed getting latest payload receivedAt from redis")
		} else if receivedAt.UnixMilli() < latestPayloadReceivedAt {
			log.Infof("already have a newer payload: now=%d / prev=%d", receivedAt.UnixMilli(), latestPayloadReceivedAt)
			api.RespondError(w, http.StatusBadRequest, "already using a newer payload")
			return
		}
	}

	redisOpts := redisUpdateBidOpts{
		w:                    w,
		tx:                   tx,
		log:                  log,
		cancellationsEnabled: isCancellationEnabled,
		receivedAt:           receivedAt,
		floorBidValue:        floorBidValue,
		payload:              payload,
	}
	updateBidResult, getPayloadResponse, ok := api.updateRedisBid(redisOpts)
	if !ok {
		return
	}

	// Add fields to logs
	log = log.WithFields(logrus.Fields{
		"timestampAfterBidUpdate":    time.Now().UTC().UnixMilli(),
		"wasBidSavedInRedis":         updateBidResult.WasBidSaved,
		"wasTopBidUpdated":           updateBidResult.WasTopBidUpdated,
		"topBidValue":                updateBidResult.TopBidValue,
		"prevTopBidValue":            updateBidResult.PrevTopBidValue,
		"profileRedisSavePayloadUs":  updateBidResult.TimeSavePayload.Microseconds(),
		"profileRedisUpdateTopBidUs": updateBidResult.TimeUpdateTopBid.Microseconds(),
		"profileRedisUpdateFloorUs":  updateBidResult.TimeUpdateFloor.Microseconds(),
	})

	if updateBidResult.WasBidSaved {
		// Bid is eligible to win the auction
		eligibleAt = time.Now().UTC()
		log = log.WithField("timestampEligibleAt", eligibleAt.UnixMilli())

		// Save to memcache in the background
		if api.memcached != nil {
			go func() {
				err = api.memcached.SaveExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String(), getPayloadResponse)
				if err != nil {
					log.WithError(err).Error("failed saving execution payload in memcached")
				}
			}()
		}
	}

	nextTime = time.Now().UTC()
	pf.WasBidSaved = updateBidResult.WasBidSaved
	pf.RedisUpdate = uint64(nextTime.Sub(prevTime).Microseconds())                 //nolint:gosec
	pf.RedisSavePayload = uint64(updateBidResult.TimeSavePayload.Microseconds())   //nolint:gosec
	pf.RedisUpdateTopBid = uint64(updateBidResult.TimeUpdateTopBid.Microseconds()) //nolint:gosec
	pf.RedisUpdateFloor = uint64(updateBidResult.TimeUpdateFloor.Microseconds())   //nolint:gosec
	pf.Total = uint64(nextTime.Sub(receivedAt).Microseconds())                     //nolint:gosec

	// All done, log with profiling information
	log.WithFields(logrus.Fields{
		"profileDecodeUs":    pf.Decode,
		"profilePrechecksUs": pf.Prechecks,
		"profileSimUs":       pf.Simulation,
		"profileRedisUs":     pf.RedisUpdate,
		"profileTotalUs":     pf.Total,
	}).Info("received block from builder")
	submissionSuccess = true
	w.WriteHeader(http.StatusOK)
}

func (api *RelayAPI) saveBlockSubmissionMetrics(pf common.Profile, receivedTime time.Time, success bool) {
	status := "error"
	if success {
		status = "success"
	}
	metrics.SubmitNewBlockCount.Add(context.Background(), 1,
		otelapi.WithAttributes(attribute.String("status", status)),
	)

	if pf.PayloadLoad > 0 {
		metrics.SubmitNewBlockReadLatencyHistogram.Record(
			context.Background(),
			float64(pf.PayloadLoad)/1000,
			otelapi.WithAttributes(attribute.Bool("isGzip", pf.IsGzip)),
		)
	}
	if pf.Decode > 0 {
		metrics.SubmitNewBlockDecodeLatencyHistogram.Record(
			context.Background(),
			float64(pf.Decode)/1000,
			otelapi.WithAttributes(attribute.String("contentType", pf.ContentType)),
		)
	}

	if pf.Prechecks > 0 {
		metrics.SubmitNewBlockPrechecksLatencyHistogram.Record(
			context.Background(),
			float64(pf.Prechecks)/1000,
		)
	}

	if pf.Simulation > 0 {
		metrics.SubmitNewBlockSimulationLatencyHistogram.Record(
			context.Background(),
			float64(pf.Simulation)/1000,
			otelapi.WithAttributes(attribute.Bool("simulationSuccess", pf.SimulationSuccess)),
		)
	}

	if pf.RedisUpdate > 0 {
		metrics.SubmitNewBlockRedisLatencyHistogram.Record(
			context.Background(),
			float64(pf.RedisUpdate)/1000,
			otelapi.WithAttributes(attribute.Bool("wasBidSaved", pf.WasBidSaved)),
		)
	}

	if pf.RedisSavePayload > 0 {
		metrics.SubmitNewBlockRedisPayloadLatencyHistogram.Record(
			context.Background(),
			float64(pf.RedisSavePayload)/1000,
		)
	}

	if pf.RedisUpdateTopBid > 0 {
		metrics.SubmitNewBlockRedisTopBidLatencyHistogram.Record(
			context.Background(),
			float64(pf.RedisUpdateTopBid)/1000,
		)
	}

	if pf.RedisUpdateFloor > 0 {
		metrics.SubmitNewBlockRedisFloorLatencyHistogram.Record(
			context.Background(),
			float64(pf.RedisUpdateFloor)/1000,
		)
	}

	if pf.BidValueEth > 0 {
		metrics.SubmitNewBlockBidValueHistogram.Record(
			context.Background(),
			pf.BidValueEth,
		)
	}

	if pf.PayloadBytes > 0 {
		metrics.SubmitNewBlockPayloadSizeHistogram.Record(
			context.Background(),
			float64(pf.PayloadBytes),
		)
	}

	if pf.MsIntoSlot > 0 {
		metrics.SubmitNewBlockSlotAgeHistogram.Record(
			context.Background(),
			float64(pf.MsIntoSlot),
		)
	}

	metrics.SubmitNewBlockLatencyHistogram.Record(
		context.Background(),
		float64(time.Since(receivedTime).Milliseconds()),
		otelapi.WithAttributes(
			attribute.String("contentType", pf.ContentType),
			attribute.Bool("isGzip", pf.IsGzip),
			attribute.Bool("aboveFloorBid", pf.AboveFloorBid),
			attribute.Bool("simulationSuccess", pf.SimulationSuccess),
			attribute.Bool("wasBidSaved", pf.WasBidSaved),
			attribute.Bool("optimistic", pf.Optimistic),
			attribute.String("status", status),
		),
	)
}

// ---------------
//
//	INTERNAL APIS
//
// ---------------
func (api *RelayAPI) handleInternalBuilderStatus(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	builderPubkey := vars["pubkey"]
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
	switch req.Method {
	case http.MethodGet:
		api.RespondOK(w, builderEntry)
		return
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		st := common.BuilderStatus{
			IsHighPrio:    builderEntry.IsHighPrio,
			IsBlacklisted: builderEntry.IsBlacklisted,
			IsOptimistic:  builderEntry.IsOptimistic,
		}
		trueStr := "true"
		args := req.URL.Query()
		if args.Get("high_prio") != "" {
			st.IsHighPrio = args.Get("high_prio") == trueStr
		}
		if args.Get("blacklisted") != "" {
			st.IsBlacklisted = args.Get("blacklisted") == trueStr
		}
		if args.Get("optimistic") != "" {
			st.IsOptimistic = args.Get("optimistic") == trueStr
		}
		api.log.WithFields(logrus.Fields{
			"builderPubkey": builderPubkey,
			"isHighPrio":    st.IsHighPrio,
			"isBlacklisted": st.IsBlacklisted,
			"isOptimistic":  st.IsOptimistic,
		}).Info("updating builder status")
		err := api.db.SetBlockBuilderStatus(builderPubkey, st)
		if err != nil {
			err := fmt.Errorf("error setting builder: %v status: %w", builderPubkey, err)
			api.log.Error(err)
			api.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		api.RespondOK(w, st)
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
			fullErr := fmt.Errorf("unable to set collateral in db for pubkey: %v: %w", builderPubkey, err)
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
		filters.Slot, err = strconv.ParseInt(args.Get("slot"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
	} else if args.Get("cursor") != "" {
		filters.Cursor, err = strconv.ParseInt(args.Get("cursor"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid cursor argument")
			return
		}
	}

	if args.Get("block_hash") != "" {
		_, err := utils.HexToHash(args.Get("block_hash"))
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_hash argument")
			return
		}
		filters.BlockHash = args.Get("block_hash")
	}

	if args.Get("block_number") != "" {
		filters.BlockNumber, err = strconv.ParseInt(args.Get("block_number"), 10, 64)
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
		api.log.WithError(err).Error("error getting recently delivered payloads")
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
		filters.Slot, err = strconv.ParseInt(args.Get("slot"), 10, 64)
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid slot argument")
			return
		}
	}

	if args.Get("block_hash") != "" {
		_, err := utils.HexToHash(args.Get("block_hash"))
		if err != nil {
			api.RespondError(w, http.StatusBadRequest, "invalid block_hash argument")
			return
		}
		filters.BlockHash = args.Get("block_hash")
	}

	if args.Get("block_number") != "" {
		filters.BlockNumber, err = strconv.ParseInt(args.Get("block_number"), 10, 64)
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
		_limit, err := strconv.ParseInt(args.Get("limit"), 10, 64)
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
		api.log.WithError(err).Error("error getting recent builder submissions")
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

	_, err := utils.HexToPubkey(pkStr)
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

func (api *RelayAPI) handleLivez(w http.ResponseWriter, req *http.Request) {
	api.RespondMsg(w, http.StatusOK, "live")
}

func (api *RelayAPI) handleReadyz(w http.ResponseWriter, req *http.Request) {
	if api.IsReady() {
		api.RespondMsg(w, http.StatusOK, "ready")
	} else {
		api.RespondMsg(w, http.StatusServiceUnavailable, "not ready")
	}
}

func (api *RelayAPI) processValidatorRegistrationJSON(regs []*common.SimpleValidatorRegistration) (newRegistrations []*builderApiV1.SignedValidatorRegistration, userErr, err error) {
	newRegistrations = make([]*builderApiV1.SignedValidatorRegistration, 0)
	registrationTimestampUpperBound := time.Now().UTC().Unix() + 10 // 10 seconds from now

	for _, reg := range regs {
		// Ensure a valid timestamp (not too early, and not too far in the future)
		regTS := reg.Timestamp.Unix()
		if regTS < int64(api.genesisInfo.Data.GenesisTime) { //nolint:gosec
			return nil, common.ErrTimestampTooEarly, nil
		} else if regTS > registrationTimestampUpperBound {
			return nil, common.ErrTimestampTooFarInFuture, nil
		}

		// Check for a previous registration timestamp and see if fields changed
		cachedRegistrationData, err := api.datastore.GetCachedValidatorRegistration(reg.Pubkey)
		haveCachedRegistration := cachedRegistrationData != nil

		if err != nil {
			api.log.WithError(err).Error("error getting last validator registration") // maybe a Redis error. continue to validation + processing
		} else if haveCachedRegistration {
			// See if we can discard (if no fields changed, or old timestamp)
			isChangedFeeRecipient := cachedRegistrationData.FeeRecipient != reg.FeeRecipient
			isChangedGasLimit := cachedRegistrationData.GasLimit != reg.GasLimit
			isNewerTimestamp := reg.Timestamp.After(cachedRegistrationData.Timestamp)

			// If key fields haven't changed, can just discard without signature validation
			if !isChangedFeeRecipient && !isChangedGasLimit {
				continue
			}

			// Ensure it's not a replay of an old registration
			if !isNewerTimestamp {
				continue
			}
		}

		// Before verifying signature, check if a real validator
		isKnownValidator := api.datastore.IsKnownValidator(reg.Pubkey)
		if !isKnownValidator {
			return nil, fmt.Errorf("not a known validator: %s", reg.Pubkey), nil //nolint:err113
		}

		// Now convert to the final signed validator registration for processing
		pk, _ := reg.Pubkey.ToPubkey()
		signature, _ := utils.HexToSignature(reg.Signature)

		newRegistrations = append(newRegistrations, &builderApiV1.SignedValidatorRegistration{
			Message: &builderApiV1.ValidatorRegistration{
				Pubkey:       pk,
				FeeRecipient: reg.FeeRecipient,
				GasLimit:     reg.GasLimit,
				Timestamp:    reg.Timestamp,
			},
			Signature: signature,
		})
	}

	return newRegistrations, nil, nil
}

func (api *RelayAPI) processValidatorRegistrationsSSZ(regs []*builderApiV1.SignedValidatorRegistration) (newRegistrations []*builderApiV1.SignedValidatorRegistration, userErr, err error) {
	newRegistrations = make([]*builderApiV1.SignedValidatorRegistration, 0)
	registrationTimestampUpperBound := time.Now().UTC().Unix() + 10 // 10 seconds from now

	for _, signedValidatorRegistration := range regs {
		pk := common.NewPubkeyHex(signedValidatorRegistration.Message.Pubkey.String())

		// Ensure a valid timestamp (not too early, and not too far in the future)
		registrationTimestamp := signedValidatorRegistration.Message.Timestamp.Unix()
		if registrationTimestamp < int64(api.genesisInfo.Data.GenesisTime) { //nolint:gosec
			return nil, common.ErrTimestampTooEarly, nil
		} else if registrationTimestamp > registrationTimestampUpperBound {
			return nil, common.ErrTimestampTooFarInFuture, nil
		}

		// Check for a previous registration timestamp and see if fields changed
		cachedRegistrationData, err := api.datastore.GetCachedValidatorRegistration(pk)
		haveCachedRegistration := cachedRegistrationData != nil

		if err != nil {
			api.log.WithError(err).Error("error getting last validator registration") // maybe a Redis error. continue to validation + processing
		} else if haveCachedRegistration {
			// See if we can discard (if no fields changed, or old timestamp)
			isChangedFeeRecipient := cachedRegistrationData.FeeRecipient != signedValidatorRegistration.Message.FeeRecipient
			isChangedGasLimit := cachedRegistrationData.GasLimit != signedValidatorRegistration.Message.GasLimit
			isNewerTimestamp := signedValidatorRegistration.Message.Timestamp.UTC().Unix() > cachedRegistrationData.Timestamp.UTC().Unix()

			// If key fields haven't changed, can just discard without signature validation
			if !isChangedFeeRecipient && !isChangedGasLimit {
				continue
			}

			// Ensure it's not a replay of an old registration
			if !isNewerTimestamp {
				continue
			}
		}

		// Before verifying signature, check if a real validator
		isKnownValidator := api.datastore.IsKnownValidator(pk)
		if !isKnownValidator {
			return nil, fmt.Errorf("not a known validator: %s", pk), nil //nolint:err113
		}

		newRegistrations = append(newRegistrations, signedValidatorRegistration)
	}

	return newRegistrations, nil, nil
}
