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

func (s *BuilderAPIService) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", s.handleRoot)
	r.HandleFunc(pathStatus, s.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathGetValidatorsForEpoch, s.handleGetValidatorsForEpoch).Methods(http.MethodGet)
	r.HandleFunc(pathSubmitNewBlock, s.handleSubmitNewBlock).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(s.log, r)
	return loggedRouter
}

// StartHTTPServer starts the HTTP server for this boost service instance
func (s *BuilderAPIService) StartHTTPServer() error {
	if s.srv != nil {
		return common.ErrServerAlreadyRunning
	}

	s.srv = &http.Server{
		Addr:    s.listenAddr,
		Handler: s.getRouter(),

		ReadTimeout:       s.serverTimeouts.Read,
		ReadHeaderTimeout: s.serverTimeouts.ReadHeader,
		WriteTimeout:      s.serverTimeouts.Write,
		IdleTimeout:       s.serverTimeouts.Idle,
	}

	err := s.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *BuilderAPIService) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (s *BuilderAPIService) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (s *BuilderAPIService) handleGetValidatorsForEpoch(w http.ResponseWriter, req *http.Request) {
	log := s.log.WithField("method", "getValidatorsForEpoch")
	log.Info("request")
}

func (s *BuilderAPIService) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	log := s.log.WithField("method", "submitNewBlock")
	log.Info("request")
}
