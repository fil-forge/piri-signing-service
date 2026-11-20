package handlers

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fil-forge/piri-signing-service/pkg/signer"
)

// createTestSigner creates a test signer with a random key
func createTestSigner(t *testing.T) *signer.Signer {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	chainID := big.NewInt(314159) // Calibration testnet
	contractAddr := common.HexToAddress("0x8b7aa0a68f5717e400F1C4D37F7a28f84f76dF91")

	return signer.NewSigner(privateKey, chainID, contractAddr)
}

func TestHealth(t *testing.T) {
	e := echo.New()
	s := createTestSigner(t)
	handler := NewHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.Health(c)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "healthy", response["status"])
	assert.Equal(t, s.GetAddress().Hex(), response["signer"])
}
