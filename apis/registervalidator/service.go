// Package registervalidator contains everything for the Relay server
package registervalidator

import (
	"fmt"
	"net/http"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
)

// RegisterValidatorService TODO
type RegisterValidatorService struct {
	listenAddr       string
	validatorService ValidatorService
	log              *logrus.Entry
	srv              *http.Server

	serverTimeouts common.HTTPServerTimeouts
}

// NewRegisterValidatorService creates a new service. if builders is nil, allow any builder
func NewRegisterValidatorService(listenAddr string, validatorService ValidatorService, log *logrus.Entry) (*RegisterValidatorService, error) {
	return &RegisterValidatorService{
		listenAddr:       listenAddr,
		validatorService: validatorService,
		log:              log.WithField("module", "proposer-api"),

		serverTimeouts: common.NewDefaultHTTPServerTimeouts(),
	}, nil
}

func (s *RegisterValidatorService) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", s.handleRoot)
	r.HandleFunc(pathStatus, s.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathRegisterValidator, s.handleRegisterValidator).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(s.log, r)
	return loggedRouter
}

// StartHTTPServer starts the HTTP server for this boost service instance
func (s *RegisterValidatorService) StartHTTPServer() error {
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

func (s *RegisterValidatorService) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (s *RegisterValidatorService) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (s *RegisterValidatorService) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := s.log.WithField("method", "registerValidator")
	log.Info("registerValidator")
	// s.validatorService.IsValidator(...)
}
