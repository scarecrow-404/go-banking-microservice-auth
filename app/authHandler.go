package app

import (
	"encoding/json"
	"net/http"

	"github.com/scarecrow-404/banking-auth/dto"
	"github.com/scarecrow-404/banking-auth/logger"
	"github.com/scarecrow-404/banking-auth/service"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var request dto.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		logger.Error("Error while decoding login request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token, appError := h.service.Login(request)
	if appError != nil {
		writeResponse(w,appError.Code,appError.AsMessage())
		return
	}
	writeResponse(w, http.StatusOK, *token)
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	for k:= range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}
	if urlParams["token"] != ""{
		appErr := h.service.Verify(urlParams)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())
			return
		}
		writeResponse(w, http.StatusOK, autherizedResponse())
		return
	}else {
		writeResponse(w, http.StatusForbidden, notAutherizeResponse("Token not found"))
		return
	}
}

func (h AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var request dto.RefreshTokenRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		logger.Error("Error while decoding login request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token, appError := h.service.Refresh(request)
	if appError != nil {
		writeResponse(w,appError.Code,appError.AsMessage())
		return
	}
	writeResponse(w, http.StatusOK, *token)
}

func notAutherizeResponse(msg string) map[string]interface{}{
	return map[string] interface{}{
		"isAutherized" : false,
		"message" : msg,
	}
}

func autherizedResponse() map[string]bool{
	return map[string]bool{
		"isAutherized" : true,
	}
}


func writeResponse( w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		panic(err)
	}
}