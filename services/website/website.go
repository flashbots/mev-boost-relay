// Package website contains the service delivering the website
package website

import (
	"bytes"
	"errors"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"sync"
	"text/template"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/go-redis/redis/v9"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/tdewolff/minify"
	"github.com/tdewolff/minify/html"
	uberatomic "go.uber.org/atomic"
)

var (
	ErrServerAlreadyStarted = errors.New("server was already started")
	EnablePprof             = os.Getenv("PPROF") == "1"
)

type WebserverOpts struct {
	ListenAddress  string
	RelayPubkeyHex string
	NetworkDetails *common.EthNetworkDetails
	Redis          *datastore.RedisCache
	DB             *database.DatabaseService
	Log            *logrus.Entry

	ShowConfigDetails bool
	LinkBeaconchain   string
	LinkEtherscan     string
	LinkDataAPI       string
	RelayURL          string
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

	htmlDefault     *[]byte
	htmlByValueDesc *[]byte
	htmlByValueAsc  *[]byte

	minifier *minify.M
}

func NewWebserver(opts *WebserverOpts) (*Webserver, error) {
	var err error

	minifier := minify.New()
	minifier.AddFunc("text/css", html.Minify)
	minifier.AddFunc("text/html", html.Minify)

	server := &Webserver{
		opts:  opts,
		log:   opts.Log,
		redis: opts.Redis,
		db:    opts.DB,

		htmlDefault:     &[]byte{},
		htmlByValueDesc: &[]byte{},
		htmlByValueAsc:  &[]byte{},

		minifier: minifier,
	}

	server.indexTemplate, err = ParseIndexTemplate()
	if err != nil {
		return nil, err
	}

	server.statusHTMLData = StatusHTMLData{
		Network:                     opts.NetworkDetails.Name,
		RelayPubkey:                 opts.RelayPubkeyHex,
		ValidatorsTotal:             0,
		ValidatorsRegistered:        0,
		BellatrixForkVersion:        opts.NetworkDetails.BellatrixForkVersionHex,
		CapellaForkVersion:          opts.NetworkDetails.CapellaForkVersionHex,
		GenesisForkVersion:          opts.NetworkDetails.GenesisForkVersionHex,
		GenesisValidatorsRoot:       opts.NetworkDetails.GenesisValidatorsRootHex,
		BuilderSigningDomain:        hexutil.Encode(opts.NetworkDetails.DomainBuilder[:]),
		BeaconProposerSigningDomain: hexutil.Encode(opts.NetworkDetails.DomainBeaconProposerBellatrix[:]),
		HeadSlot:                    0,
		NumPayloadsDelivered:        0,
		Payloads:                    []*database.DeliveredPayloadEntry{},
		ValueLink:                   "",
		ValueOrderIcon:              "",
		ShowConfigDetails:           opts.ShowConfigDetails,
		LinkBeaconchain:             opts.LinkBeaconchain,
		LinkEtherscan:               opts.LinkEtherscan,
		LinkDataAPI:                 opts.LinkDataAPI,
		RelayURL:                    opts.RelayURL,
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
	if EnablePprof {
		srv.log.Info("pprof API enabled")
		r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	}

	loggedRouter := httplogger.LoggingMiddlewareLogrus(srv.log, r)
	withGz := gziphandler.GzipHandler(loggedRouter)
	return withGz
}

func (srv *Webserver) updateHTML() {
	_numRegistered, err := srv.db.NumRegisteredValidators()
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
	if len(payloads) > 0 && payloads[0].Slot > _latestSlotInt {
		_latestSlotInt = payloads[0].Slot
	}

	_validatorsTotal, err := srv.redis.GetStats(datastore.RedisStatsFieldValidatorsTotal)
	if err != nil && !errors.Is(err, redis.Nil) {
		srv.log.WithError(err).Error("error getting latest stats: validators_total")
	}
	_validatorsTotalInt, _ := strconv.ParseUint(_validatorsTotal, 10, 64)

	srv.statusHTMLData.ValidatorsTotal = _validatorsTotalInt
	srv.statusHTMLData.ValidatorsRegistered = _numRegistered
	srv.statusHTMLData.NumPayloadsDelivered = _numPayloadsDelivered
	srv.statusHTMLData.HeadSlot = _latestSlotInt

	// Now generate the HTML
	htmlDefault := bytes.Buffer{}
	htmlByValueDesc := bytes.Buffer{}
	htmlByValueAsc := bytes.Buffer{}

	// default view
	srv.statusHTMLData.Payloads = payloads
	srv.statusHTMLData.ValueLink = "/?order_by=-value"
	srv.statusHTMLData.ValueOrderIcon = ""
	if err := srv.indexTemplate.Execute(&htmlDefault, srv.statusHTMLData); err != nil {
		srv.log.WithError(err).Error("error rendering template")
	}

	// descending order view
	srv.statusHTMLData.Payloads = payloadsByValueDesc
	srv.statusHTMLData.ValueLink = "/?order_by=value"
	srv.statusHTMLData.ValueOrderIcon = " <svg style=\"width:12px;\" xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"0 0 24 24\" stroke-width=\"1.5\" stroke=\"currentColor\" class=\"w-6 h-6\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" d=\"M19.5 13.5L12 21m0 0l-7.5-7.5M12 21V3\" /></svg>"
	if err := srv.indexTemplate.Execute(&htmlByValueDesc, srv.statusHTMLData); err != nil {
		srv.log.WithError(err).Error("error rendering template (by value)")
	}

	// ascending order view
	srv.statusHTMLData.Payloads = payloadsByValueAsc
	srv.statusHTMLData.ValueLink = "/"
	srv.statusHTMLData.ValueOrderIcon = " <svg style=\"width:12px;\" xmlns=\"http://www.w3.org/2000/svg\" fill=\"none\" viewBox=\"0 0 24 24\" stroke-width=\"1.5\" stroke=\"currentColor\" class=\"w-6 h-6\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" d=\"M4.5 10.5L12 3m0 0l7.5 7.5M12 3v18\" /></svg>"
	if err := srv.indexTemplate.Execute(&htmlByValueAsc, srv.statusHTMLData); err != nil {
		srv.log.WithError(err).Error("error rendering template (by -value)")
	}

	// Minify
	htmlDefaultBytes, err := srv.minifier.Bytes("text/html", htmlDefault.Bytes())
	if err != nil {
		srv.log.WithError(err).Error("error minifying htmlDefault")
	}
	htmlValueDescBytes, err := srv.minifier.Bytes("text/html", htmlByValueDesc.Bytes())
	if err != nil {
		srv.log.WithError(err).Error("error minifying htmlByValueDesc")
	}
	htmlValueDescAsc, err := srv.minifier.Bytes("text/html", htmlByValueAsc.Bytes())
	if err != nil {
		srv.log.WithError(err).Error("error minifying htmlByValueAsc")
	}

	// Swap the html pointers
	srv.rootResponseLock.Lock()
	srv.htmlDefault = &htmlDefaultBytes
	srv.htmlByValueDesc = &htmlValueDescBytes
	srv.htmlByValueAsc = &htmlValueDescAsc
	srv.rootResponseLock.Unlock()
}

func (srv *Webserver) handleRoot(w http.ResponseWriter, req *http.Request) {
	var err error

	srv.rootResponseLock.RLock()
	defer srv.rootResponseLock.RUnlock()
	if req.URL.Query().Get("order_by") == "-value" {
		_, err = w.Write(*srv.htmlByValueDesc)
	} else if req.URL.Query().Get("order_by") == "value" {
		_, err = w.Write(*srv.htmlByValueAsc)
	} else {
		_, err = w.Write(*srv.htmlDefault)
	}
	if err != nil {
		srv.log.WithError(err).Error("error writing template")
	}
}
