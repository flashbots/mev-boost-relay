// package proposer contains APIs for the proposer as per builder-specs
package proposer

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"
)

type ProposerAPI struct {
	common.BaseAPI

	datastore            common.Datastore
	builderSigningDomain types.Domain
}

func NewProposerAPI(log *logrus.Entry, datastore common.Datastore, genesisForkVersionHex string) (ret common.APIComponent, err error) {
	if log == nil {
		return nil, errors.New("log parameter is nil")
	}

	api := new(ProposerAPI)
	api.Log = log.WithField("module", "apiRegisterValidator")
	api.datastore = datastore

	// Setup the signing domain
	api.builderSigningDomain, err = common.ComputeDomain(types.DomainTypeAppBuilder, genesisForkVersionHex, types.Root{}.String())
	if err != nil {
		return nil, err
	}

	return api, nil
}

func (api *ProposerAPI) RegisterHandlers(r *mux.Router) {
	r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
	r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
	r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)
}

func (api *ProposerAPI) Start() error {
	return nil
}

func (api *ProposerAPI) Stop() error {
	return nil
}

func (api *ProposerAPI) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := api.Log.WithField("method", "registerValidator")
	log.Info("registerValidator")

	payload := []types.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// TODO: maybe parallelize this
	for _, registration := range payload {
		if len(registration.Message.Pubkey) != 48 {
			continue
		}

		if len(registration.Signature) != 96 {
			continue
		}

		// Check if actually a real validator
		// if !api.validatorService.IsValidator(common.NewPubkeyHex(registration.Message.Pubkey.String())) {
		// 	log.WithField("registration", registration).Warn("not a known validator")
		// 	continue
		// }

		// Verify the signature
		ok, err := types.VerifySignature(registration.Message, api.builderSigningDomain, registration.Message.Pubkey[:], registration.Signature[:])
		if err != nil {
			log.WithError(err).WithField("registration", registration).Warn("error verifying registerValidator signature")
			continue
		}
		if !ok {
			log.WithError(err).WithField("registration", registration).Warn("failed to verify registerValidator signature")
			continue
		}

		// Save if first time or if newer timestamp than last registration
		lastEntry, err := api.datastore.GetValidatorRegistration(registration.Message.Pubkey)
		if err != nil {
			log.WithError(err).WithField("registration", registration).Error("error getting validator registration")
			continue
		}

		if lastEntry == nil || lastEntry.Message.Timestamp > registration.Message.Timestamp {
			api.datastore.SaveValidatorRegistration(registration)
		}
	}

	api.RespondOK(w, common.NilResponse)
}

func (api *ProposerAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slot := vars["slot"]
	parentHashHex := vars["parent_hash"]
	pubkey := vars["pubkey"]
	log := api.Log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slot,
		"parentHash": parentHashHex,
		"pubkey":     pubkey,
	})
	log.Info("getHeader")

	if _, err := strconv.ParseUint(slot, 10, 64); err != nil {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSlot.Error())
		return
	}

	if len(pubkey) != 98 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidHash.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
	if err := json.NewEncoder(w).Encode(common.NilResponse); err != nil {
		api.Log.WithError(err).Error("Couldn't write getHeader response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *ProposerAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := api.Log.WithField("method", "getPayload")
	log.Info("getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(payload.Signature) != 96 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSignature.Error())
		return
	}

	api.RespondOKEmpty(w)
}
