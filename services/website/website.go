// Package website contains the service delivering the website
package website

import (
	"context"
	"net/http"
	"sync"
	"text/template"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

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

	srv   *http.Server
	srvMu sync.Mutex

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
		BellatrixForkVersion:        opts.NetworkDetails.BellatrixForkVersionHex,
		GenesisForkVersion:          opts.NetworkDetails.GenesisForkVersionHex,
		GenesisValidatorsRoot:       opts.NetworkDetails.GenesisValidatorsRootHex,
		BuilderSigningDomain:        hexutil.Encode(opts.NetworkDetails.DomainBuilder[:]),
		BeaconProposerSigningDomain: hexutil.Encode(opts.NetworkDetails.DomainBeaconProposer[:]),
	}

	return server, nil
}

func (srv *Webserver) StartServer(ctx context.Context) (err error) {

	srv.srvMu.Lock()
	// Start background task to regularly update status HTML data
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				srv.updateStatusHTMLData(ctx)
				<-time.After(5 * time.Second)
			}

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
	srv.srvMu.Unlock()
	err = srv.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (srv *Webserver) Stop(ctx context.Context) {
	srv.srvMu.Lock()
	defer srv.srvMu.Unlock()
	if srv.srv != nil {
		srv.srv.Shutdown(ctx)
	}
}

func (srv *Webserver) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", srv.handleRoot).Methods(http.MethodGet)
	// if api.opts.PprofAPI {
	// 	r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	// }

	// r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(srv.log, r)
	return loggedRouter
}

func (srv *Webserver) updateStatusHTMLData(ctx context.Context) {
	knownValidators, err := srv.redis.GetKnownValidators(ctx)
	if err != nil {
		srv.log.WithError(err).Error("error getting known validators in updateStatusHTMLData")
	}

	_numRegistered, err := srv.redis.NumRegisteredValidators(ctx)
	if err != nil {
		srv.log.WithError(err).Error("error getting number of registered validators in updateStatusHTMLData")
	}

	payloads, err := srv.db.GetRecentDeliveredPayloads(ctx, database.GetPayloadsFilters{Limit: 20})
	if err != nil {
		srv.log.WithError(err).Error("error getting recent payloads")
	}

	numRegistered := printer.Sprintf("%d", _numRegistered)
	numKnown := printer.Sprintf("%d", len(knownValidators))

	srv.statusHTMLDataLock.Lock()
	srv.statusHTMLData.ValidatorsTotal = numKnown
	srv.statusHTMLData.ValidatorsRegistered = numRegistered
	srv.statusHTMLData.Payloads = payloads
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
