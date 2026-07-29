package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

const jsonContentType = "application/json; charset=utf-8"

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

func writeError(
	w http.ResponseWriter,
	statusCode int,
	code string,
	message string,
	requestID string,
	logger *slog.Logger,
) {
	writeJSON(
		w,
		statusCode,
		errorResponse{
			Error: errorBody{
				Code:      code,
				Message:   message,
				RequestID: requestID,
			},
		},
		logger,
	)
}

func writeJSON(
	w http.ResponseWriter,
	statusCode int,
	payload any,
	logger *slog.Logger,
) {
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Warn(
			"failed to encode HTTP response",
			slog.String("error", err.Error()),
		)
	}
}
