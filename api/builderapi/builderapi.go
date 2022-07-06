// Package proposerapi contains APIs for the proposer as per builder-specs
package builderapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	// Block builder APIs
	pathGetValidatorsForEpoch = "/relay/v1/builder/validators"
	pathSubmitNewBlock        = "/relay/v1/builder/blocks"
)

type BuilderAPI struct {
	common.BaseAPI

	ctx                  context.Context
	datastore            datastore.ProposerDatastore
	builderSigningDomain types.Domain
}

func NewBuilderAPI(
	ctx context.Context,
	log *logrus.Entry,
	ds datastore.ProposerDatastore,
	genesisForkVersionHex string,
) (ret common.APIComponent, err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if log == nil {
		return nil, errors.New("log parameter is nil")
	}

	api := &BuilderAPI{
		ctx:       ctx,
		datastore: ds,
	}

	// Setup the remaining properties
	api.Log = log.WithField("module", "api/builer")
	api.builderSigningDomain, err = common.ComputerBuilderSigningDomain(genesisForkVersionHex)
	return api, err
}

func (api *BuilderAPI) RegisterHandlers(r *mux.Router) {
	r.HandleFunc(pathGetValidatorsForEpoch, api.handleGetValidatorsForEpoch).Methods(http.MethodPost)
	// r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodGet)
}

func (api *BuilderAPI) Start() (err error) {
	// c := make(chan uint64)
	// go .validatorService.SubscribeToHeadEvents(c)
	// for {
	// 	m.slotCurrent = <-c
	// 	m.log.WithField("slot", m.slotCurrent).Info("new slot")
	// }

	return nil
}

func (api *BuilderAPI) Stop() error {
	api.ctx.Done()
	return nil
}

func (api *BuilderAPI) handleGetValidatorsForEpoch(w http.ResponseWriter, req *http.Request) {
	log := api.Log.WithField("method", "getValidatorsForEpoch")
	log.Info("request")
	api.RespondOKEmpty(w)
}

// func (m *ProposerAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
// 	log := m.Log.WithField("method", "submitNewBlock")
// 	log.Info("request")
// 	m.RespondOKEmpty(w)
// }
