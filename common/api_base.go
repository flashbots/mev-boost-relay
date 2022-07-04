package common

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type APIComponent interface {
	RegisterHandlers(r *mux.Router)
	Start() error
	Stop() error
}

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type BaseAPI struct {
	Log *logrus.Entry
}

func (api *BaseAPI) RespondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := HTTPErrorResp{code, message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		api.Log.WithField("response", resp).WithError(err).Error("Couldn't write error response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *BaseAPI) RespondOK(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		api.Log.WithField("response", response).WithError(err).Error("Couldn't write OK response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *BaseAPI) RespondOKEmpty(w http.ResponseWriter) {
	api.RespondOK(w, NilResponse)
}
