// Package builder contains everything for the Relay server
package builder

import (
	"fmt"
	"net/http"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	pathStatus                = "/builder/v1/status"
	pathGetValidatorsForEpoch = "/builder/v1/validators/epoch/{epoch:[0-9]+}"
	pathSubmitNewBlock        = "/builder/v1/blocks"
)

// BuilderAPIService TODO
type BuilderAPIService struct {
	listenAddr string
	builders   []*common.BuilderEntry
	log        *logrus.Entry
	srv        *http.Server

	serverTimeouts common.HTTPServerTimeouts
}

// NewBuilderAPIService creates a new service. if builders is nil, allow any builder
func NewBuilderAPIService(listenAddr string, log *logrus.Entry) (*BuilderAPIService, error) {
	return &BuilderAPIService{
		listenAddr: listenAddr,
		builders:   nil,
		log:        log.WithField("module", "builder-api"),

		serverTimeouts: common.NewDefaultHTTPServerTimeouts(),
	}, nil
}

func (m *BuilderAPIService) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", m.handleRoot)
	r.HandleFunc(pathStatus, m.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathGetValidatorsForEpoch, m.handleGetValidatorsForEpoch).Methods(http.MethodGet)
	r.HandleFunc(pathSubmitNewBlock, m.handleSubmitNewBlock).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(m.log, r)
	return loggedRouter
}

// StartHTTPServer starts the HTTP server for this boost service instance
func (m *BuilderAPIService) StartHTTPServer() error {
	if m.srv != nil {
		return common.ErrServerAlreadyRunning
	}

	m.srv = &http.Server{
		Addr:    m.listenAddr,
		Handler: m.getRouter(),

		ReadTimeout:       m.serverTimeouts.Read,
		ReadHeaderTimeout: m.serverTimeouts.ReadHeader,
		WriteTimeout:      m.serverTimeouts.Write,
		IdleTimeout:       m.serverTimeouts.Idle,
	}

	err := m.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (m *BuilderAPIService) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (m *BuilderAPIService) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (m *BuilderAPIService) handleGetValidatorsForEpoch(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getValidatorsForEpoch")
	log.Info("request")
}

func (m *BuilderAPIService) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "submitNewBlock")
	log.Info("request")
}
