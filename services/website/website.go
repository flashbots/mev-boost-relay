// Package website contains the service delivering the website
package website

import (
	"bytes"
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

	indexTemplate    *template.Template
	statusHTMLData   StatusHTMLData
	rootResponseLock sync.RWMutex

	htmlDefault     *bytes.Buffer
	htmlByValueDesc *bytes.Buffer
	htmlByValueAsc  *bytes.Buffer
}

func NewWebserver(opts *WebserverOpts) (*Webserver, error) {
	var err error
	server := &Webserver{
		opts:  opts,
		log:   opts.Log,
		redis: opts.Redis,
		db:    opts.DB,

		htmlDefault:     &bytes.Buffer{},
		htmlByValueDesc: &bytes.Buffer{},
		htmlByValueAsc:  &bytes.Buffer{},
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
		Payloads:                    []*database.DeliveredPayloadEntry{},
		ValueLink:                   "",
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
			srv.updateHTML()
			time.Sleep(10 * time.Second)
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

func (srv *Webserver) updateHTML() {
	knownValidators, err := srv.redis.GetKnownValidators()
	if err != nil {
		srv.log.WithError(err).Error("error getting known validators in updateStatusHTMLData")
	}

	_numRegistered, err := srv.redis.NumRegisteredValidators()
	if err != nil {
		srv.log.WithError(err).Error("error getting number of registered validators in updateStatusHTMLData")
	}

	payloads, err := srv.db.GetRecentDeliveredPayloads(database.GetPayloadsFilters{Limit: 30})
	if err != nil {
		srv.log.WithError(err).Error("error getting recent payloads")
	}

	payloadsByValueDesc, err := srv.db.GetRecentDeliveredPayloads(database.GetPayloadsFilters{Limit: 30, OrderByValue: -1})
	if err != nil {
		srv.log.WithError(err).Error("error getting recent payloads")
	}

	payloadsByValueAsc, err := srv.db.GetRecentDeliveredPayloads(database.GetPayloadsFilters{Limit: 30, OrderByValue: 1})
	if err != nil {
		srv.log.WithError(err).Error("error getting recent payloads")
	}

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

	srv.statusHTMLData.ValidatorsTotal = numKnown
	srv.statusHTMLData.ValidatorsRegistered = numRegistered
	srv.statusHTMLData.HeadSlot = latestSlot
	srv.statusHTMLData.NumPayloadsDelivered = numPayloads

	// Now generate the HTML
	htmlDefault := bytes.Buffer{}
	htmlByValueDesc := bytes.Buffer{}
	htmlByValueAsc := bytes.Buffer{}

	srv.statusHTMLData.ValueLink = "/?order_by=-value"
	srv.statusHTMLData.Payloads = payloads
	if err := srv.indexTemplate.Execute(&htmlDefault, srv.statusHTMLData); err != nil {
		srv.log.WithError(err).Error("error rendering template")
	}

	srv.statusHTMLData.ValueLink = "/?order_by=value"
	srv.statusHTMLData.Payloads = payloadsByValueDesc
	if err := srv.indexTemplate.Execute(&htmlByValueDesc, srv.statusHTMLData); err != nil {
		srv.log.WithError(err).Error("error rendering template (by value)")
	}

	srv.statusHTMLData.ValueLink = "/"
	srv.statusHTMLData.Payloads = payloadsByValueAsc
	if err := srv.indexTemplate.Execute(&htmlByValueAsc, srv.statusHTMLData); err != nil {
		srv.log.WithError(err).Error("error rendering template (by -value)")
	}

	// Swap the html pointers
	srv.rootResponseLock.Lock()
	srv.htmlDefault = &htmlDefault
	srv.htmlByValueDesc = &htmlByValueDesc
	srv.htmlByValueAsc = &htmlByValueAsc
	srv.rootResponseLock.Unlock()
}

func (srv *Webserver) handleRoot(w http.ResponseWriter, req *http.Request) {
	var err error

	srv.rootResponseLock.RLock()
	defer srv.rootResponseLock.RUnlock()
	if req.URL.Query().Get("order_by") == "-value" {
		_, err = w.Write(srv.htmlByValueDesc.Bytes())
	} else if req.URL.Query().Get("order_by") == "value" {
		_, err = w.Write(srv.htmlByValueAsc.Bytes())
	} else {
		_, err = w.Write(srv.htmlDefault.Bytes())
	}
	if err != nil {
		srv.log.WithError(err).Error("error writing template")
	}
}
