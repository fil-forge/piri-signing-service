package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/fil-forge/piri-signing-service/pkg/signer"
	"github.com/fil-forge/piri-signing-service/pkg/types"
)

// Handler serves the health check, which reports the signer address
type Handler struct {
	signer *signer.Signer
}

// NewHandler creates a new HTTP handler
func NewHandler(s *signer.Signer) *Handler {
	return &Handler{signer: s}
}

// Health returns service health status
func (h *Handler) Health(c echo.Context) error {
	response := types.HealthResponse{
		Status: "healthy",
		Signer: h.signer.GetAddress().Hex(),
	}
	return c.JSON(http.StatusOK, response)
}
