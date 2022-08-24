// Package website contains the service delivering the website
package website

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"text/template"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/go-redis/redis/v9"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var ErrServerAlreadyStarted = errors.New("server was already started")

var (
	// Printer for pretty printing numbers
	printer = message.NewPrinter(language.English)

	// Caser is used for casing strings
	caser = cases.Title(language.English)
)

type WebserverOpts struct {
	ListenAddress  string
	RelayPubkeyHex string
	NetworkDetails *common.EthNetworkDetails
	Redis          *datastore.RedisCache
	DB             *database.DatabaseService
	Log            *logrus.Entry
}

type Webserver struct {
	opts *WebserverOpts
	log  *logrus.Entry

	redis *datastore.RedisCache
	db    *database.DatabaseService

	srv        *http.Server
	srvStarted uberatomic.Bool

	indexTemplate      *template.Template
	statusHTMLData     StatusHTMLData
	statusHTMLDataLock sync.RWMutex
}

func NewWebserver(opts *WebserverOpts) (*Webserver, error) {
	var err error
	server := &Webserver{
		opts:  opts,
		log:   opts.Log.WithField("module", "webserver"),
		redis: opts.Redis,
		db:    opts.DB,
	}

	server.indexTemplate, err = parseIndexTemplate()
	if err != nil {
		return nil, err
	}

	server.statusHTMLData = StatusHTMLData{
		Network:                     caser.String(opts.NetworkDetails.Name),
		RelayPubkey:                 opts.RelayPubkeyHex,
		ValidatorsTotal:             "",
		ValidatorsRegistered:        "",
		BellatrixForkVersion:        opts.NetworkDetails.BellatrixForkVersionHex,
		GenesisForkVersion:          opts.NetworkDetails.GenesisForkVersionHex,
		GenesisValidatorsRoot:       opts.NetworkDetails.GenesisValidatorsRootHex,
		BuilderSigningDomain:        hexutil.Encode(opts.NetworkDetails.DomainBuilder[:]),
		BeaconProposerSigningDomain: hexutil.Encode(opts.NetworkDetails.DomainBeaconProposer[:]),
		HeadSlot:                    "",
		NumPayloadsDelivered:        "",
		// Payloads:                    []*database.DeliveredPayloadEntry{},
	}

	return server, nil
}

func (srv *Webserver) StartServer() (err error) {
	if srv.srvStarted.Swap(true) {
		return ErrServerAlreadyStarted
	}

	// Start background task to regularly update status HTML data
	go func() {
		for {
			srv.updateStatusHTMLData()
			time.Sleep(5 * time.Second)
		}
	}()

	srv.srv = &http.Server{
		Addr:    srv.opts.ListenAddress,
		Handler: srv.getRouter(),

		ReadTimeout:       600 * time.Millisecond,
		ReadHeaderTimeout: 400 * time.Millisecond,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       3 * time.Second,
	}

	err = srv.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (srv *Webserver) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", srv.handleRoot).Methods(http.MethodGet)
	loggedRouter := httplogger.LoggingMiddlewareLogrus(srv.log, r)
	return loggedRouter
}

func (srv *Webserver) updateStatusHTMLData() {
	knownValidators, err := srv.redis.GetKnownValidators()
	if err != nil {
		srv.log.WithError(err).Error("error getting known validators in updateStatusHTMLData")
	}

	_numRegistered, err := srv.redis.NumRegisteredValidators()
	if err != nil {
		srv.log.WithError(err).Error("error getting number of registered validators in updateStatusHTMLData")
	}

	// payloads, err := srv.db.GetRecentDeliveredPayloads(database.GetPayloadsFilters{Limit: 30})
	// if err != nil {
	// 	srv.log.WithError(err).Error("error getting recent payloads")
	// }

	_numPayloadsDelivered, err := srv.db.GetNumDeliveredPayloads()
	if err != nil {
		srv.log.WithError(err).Error("error getting number of delivered payloads")
	}

	_latestSlot, err := srv.redis.GetStats(datastore.RedisStatsFieldLatestSlot)
	if err != nil && !errors.Is(err, redis.Nil) {
		srv.log.WithError(err).Error("error getting latest slot")
	}
	_latestSlotInt, _ := strconv.ParseUint(_latestSlot, 10, 64)

	numRegistered := printer.Sprintf("%d", _numRegistered)
	numKnown := printer.Sprintf("%d", len(knownValidators))
	numPayloads := printer.Sprintf("%d", _numPayloadsDelivered)
	latestSlot := printer.Sprintf("%d", _latestSlotInt)

	srv.statusHTMLDataLock.Lock()
	srv.statusHTMLData.ValidatorsTotal = numKnown
	srv.statusHTMLData.ValidatorsRegistered = numRegistered
	// srv.statusHTMLData.Payloads = payloads
	srv.statusHTMLData.HeadSlot = latestSlot
	srv.statusHTMLData.NumPayloadsDelivered = numPayloads
	srv.statusHTMLDataLock.Unlock()
}

func (srv *Webserver) handleRoot(w http.ResponseWriter, req *http.Request) {
	srv.statusHTMLDataLock.RLock()
	defer srv.statusHTMLDataLock.RUnlock()

	if err := srv.indexTemplate.Execute(w, srv.statusHTMLData); err != nil {
		srv.log.WithError(err).Error("error rendering index template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
