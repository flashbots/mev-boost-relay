// Package server contains everything for the Relay server
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	errInvalidSlot      = errors.New("invalid slot")
	errInvalidHash      = errors.New("invalid hash")
	errInvalidPubkey    = errors.New("invalid pubkey")
	errInvalidSignature = errors.New("invalid signature")

	errServerAlreadyRunning = errors.New("server already running")

	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"
)

// HTTPServerTimeouts are various timeouts for requests to the mev-boost HTTP server
type HTTPServerTimeouts struct {
	Read       time.Duration // Timeout for body reads. None if 0.
	ReadHeader time.Duration // Timeout for header reads. None if 0.
	Write      time.Duration // Timeout for writes. None if 0.
	Idle       time.Duration // Timeout to disconnect idle client connections. None if 0.
}

// NewDefaultHTTPServerTimeouts creates default server timeouts
func NewDefaultHTTPServerTimeouts() HTTPServerTimeouts {
	return HTTPServerTimeouts{
		Read:       4 * time.Second,
		ReadHeader: 2 * time.Second,
		Write:      6 * time.Second,
		Idle:       10 * time.Second,
	}
}

// BoostService TODO
type BoostService struct {
	listenAddr string
	builders   []*BuilderEntry
	log        *logrus.Entry
	srv        *http.Server

	serverTimeouts HTTPServerTimeouts

	httpClient http.Client
}

// NewBoostService created a new BoostService
func NewBoostService(listenAddr string, builders []*BuilderEntry, log *logrus.Entry, relayRequestTimeout time.Duration) (*BoostService, error) {
	// TODO: validate builders
	if len(builders) == 0 {
		return nil, errors.New("no relays")
	}

	return &BoostService{
		listenAddr: listenAddr,
		builders:   builders,
		log:        log.WithField("module", "service"),

		serverTimeouts: NewDefaultHTTPServerTimeouts(),
		httpClient:     http.Client{Timeout: relayRequestTimeout},
	}, nil
}

func (m *BoostService) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", m.handleRoot)

	r.HandleFunc(pathStatus, m.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathRegisterValidator, m.handleRegisterValidator).Methods(http.MethodPost)
	r.HandleFunc(pathGetHeader, m.handleGetHeader).Methods(http.MethodGet)
	r.HandleFunc(pathGetPayload, m.handleGetPayload).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(m.log, r)
	return loggedRouter
}

// StartHTTPServer starts the HTTP server for this boost service instance
func (m *BoostService) StartHTTPServer() error {
	if m.srv != nil {
		return errServerAlreadyRunning
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

func (m *BoostService) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (m *BoostService) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

// RegisterValidatorV1 - returns 200 if at least one relay returns 200
func (m *BoostService) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "registerValidator")
	log.Info("registerValidator")
}

// GetHeaderV1 TODO
func (m *BoostService) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slot := vars["slot"]
	parentHashHex := vars["parent_hash"]
	pubkey := vars["pubkey"]
	log := m.log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slot,
		"parentHash": parentHashHex,
		"pubkey":     pubkey,
	})
	log.Info("getHeader")

	if _, err := strconv.ParseUint(slot, 10, 64); err != nil {
		http.Error(w, errInvalidSlot.Error(), http.StatusBadRequest)
		return
	}

	if len(pubkey) != 98 {
		http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
		return
	}

	if len(parentHashHex) != 66 {
		http.Error(w, errInvalidHash.Error(), http.StatusBadRequest)
		return
	}

	result := new(types.GetHeaderResponse)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (m *BoostService) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getPayload")
	log.Info("getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Signature) != 96 {
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	result := new(types.GetPayloadResponse)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
