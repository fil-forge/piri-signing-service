package handlers_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fil-forge/go-libstoracha/capabilities/pdp/sign"
	"github.com/fil-forge/go-libstoracha/testutil"
	"github.com/fil-forge/go-ucanto/core/delegation"
	"github.com/fil-forge/go-ucanto/core/result"
	"github.com/fil-forge/go-ucanto/ucan"
	"github.com/fil-forge/piri-signing-service/pkg/server/handlers"
	"github.com/fil-forge/piri-signing-service/pkg/signer"
	logging "github.com/ipfs/go-log/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	logging.SetDebugLogging()
}

// createTestSigner creates a test signer with a random key
func createTestSigner(t *testing.T) *signer.Signer {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	chainID := big.NewInt(314159) // Calibration testnet
	contractAddr := common.HexToAddress("0x8b7aa0a68f5717e400F1C4D37F7a28f84f76dF91")

	return signer.NewSigner(privateKey, chainID, contractAddr)
}

func TestSignCreateDataSet_Success(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewDataSetCreateHandler(service, s)

	// Use a valid checksummed address
	testPayee := common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb")

	prf := delegation.FromDelegation(
		testutil.Must(
			delegation.Delegate(
				service,
				alice,
				[]ucan.Capability[ucan.NoCaveats]{
					ucan.NewCapability("pdp/sign/*", service.DID().String(), ucan.NoCaveats{}),
				},
			),
		)(t),
	)

	nb := sign.DataSetCreateCaveats{
		DataSet: big.NewInt(123),
		Payee:   testPayee,
		Metadata: sign.Metadata{
			Keys:   []string{"name", "version"},
			Values: map[string]string{"name": "test-dataset", "version": "1.0"},
		},
	}
	cap := ucan.NewCapability(sign.DataSetCreateAbility, service.DID().String(), nb)
	inv, err := sign.DataSetCreate.Invoke(alice, service, service.DID().String(), nb, delegation.WithProof(prf))
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Nil(t, x)
	assertSignature(t, s.GetAddress(), o)
}

func TestSignCreateDataSet_InvalidResource(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewDataSetCreateHandler(service, s)

	// Use a valid checksummed address
	testPayee := common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb")

	nb := sign.DataSetCreateCaveats{
		DataSet: big.NewInt(123),
		Payee:   testPayee,
		Metadata: sign.Metadata{
			Keys:   []string{"name", "version"},
			Values: map[string]string{"name": "test-dataset", "version": "1.0"},
		},
	}
	// alice should not be able to self sign
	cap := ucan.NewCapability(sign.DataSetCreateAbility, alice.DID().String(), nb)
	inv, err := sign.DataSetCreate.Invoke(alice, service, alice.DID().String(), nb)
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Empty(t, o)
	require.Equal(t, sign.InvalidResourceErrorName, x.Name())
}

func TestSignDeleteDataSet_Success(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewDataSetDeleteHandler(service, s)

	prf := delegation.FromDelegation(
		testutil.Must(
			delegation.Delegate(
				service,
				alice,
				[]ucan.Capability[ucan.NoCaveats]{
					ucan.NewCapability("pdp/sign/*", service.DID().String(), ucan.NoCaveats{}),
				},
			),
		)(t),
	)

	nb := sign.DataSetDeleteCaveats{
		DataSet: big.NewInt(123),
	}
	cap := ucan.NewCapability(sign.DataSetDeleteAbility, service.DID().String(), nb)
	inv, err := sign.DataSetDelete.Invoke(alice, service, service.DID().String(), nb, delegation.WithProof(prf))
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Nil(t, x)
	assertSignature(t, s.GetAddress(), o)
}

func TestSignDeleteDataSet_InvalidResource(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewDataSetDeleteHandler(service, s)

	nb := sign.DataSetDeleteCaveats{
		DataSet: big.NewInt(123),
	}
	// alice should not be able to self sign
	cap := ucan.NewCapability(sign.DataSetDeleteAbility, alice.DID().String(), nb)
	inv, err := sign.DataSetDelete.Invoke(alice, service, alice.DID().String(), nb)
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Empty(t, o)
	require.Equal(t, sign.InvalidResourceErrorName, x.Name())
}

func TestSignAddPieces_Success(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewPiecesAddHandler(service, s)

	prf := delegation.FromDelegation(
		testutil.Must(
			delegation.Delegate(
				service,
				alice,
				[]ucan.Capability[ucan.NoCaveats]{
					ucan.NewCapability("pdp/sign/*", service.DID().String(), ucan.NoCaveats{}),
				},
			),
		)(t),
	)

	nb := sign.PiecesAddCaveats{
		DataSet: big.NewInt(123),
		Nonce:   big.NewInt(0),
		PieceData: [][]byte{
			testutil.Must(hex.DecodeString("0001020304"))(t),
			testutil.Must(hex.DecodeString("0506070809"))(t),
		},
		Metadata: []sign.Metadata{
			{Keys: []string{"size"}, Values: map[string]string{"size": "1024"}},
			{Keys: []string{"size"}, Values: map[string]string{"size": "2048"}},
		},
	}
	cap := ucan.NewCapability(sign.PiecesAddAbility, service.DID().String(), nb)
	inv, err := sign.PiecesAdd.Invoke(alice, service, service.DID().String(), nb, delegation.WithProof(prf))
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Nil(t, x)
	assertSignature(t, s.GetAddress(), o)
}

func TestSignAddPieces_InvalidResource(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewDataSetDeleteHandler(service, s)

	nb := sign.DataSetDeleteCaveats{
		DataSet: big.NewInt(123),
	}
	// alice should not be able to self sign
	cap := ucan.NewCapability(sign.DataSetDeleteAbility, alice.DID().String(), nb)
	inv, err := sign.DataSetDelete.Invoke(alice, service, alice.DID().String(), nb)
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Empty(t, o)
	require.Equal(t, sign.InvalidResourceErrorName, x.Name())
}

func TestSignScheduleRemovePieces_Success(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewPiecesRemoveScheduleHandler(service, s)

	prf := delegation.FromDelegation(
		testutil.Must(
			delegation.Delegate(
				service,
				alice,
				[]ucan.Capability[ucan.NoCaveats]{
					ucan.NewCapability("pdp/sign/*", service.DID().String(), ucan.NoCaveats{}),
				},
			),
		)(t),
	)

	nb := sign.PiecesRemoveScheduleCaveats{
		DataSet: big.NewInt(123),
		Pieces:  []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
	}
	cap := ucan.NewCapability(sign.PiecesRemoveScheduleAbility, service.DID().String(), nb)
	inv, err := sign.PiecesRemoveSchedule.Invoke(alice, service, service.DID().String(), nb, delegation.WithProof(prf))
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Nil(t, x)
	assertSignature(t, s.GetAddress(), o)
}

func TestSignScheduleRemovePieces_InvalidResource(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	s := createTestSigner(t)
	handler := handlers.NewPiecesRemoveScheduleHandler(service, s)

	nb := sign.PiecesRemoveScheduleCaveats{
		DataSet: big.NewInt(123),
		Pieces:  []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
	}
	// alice should not be able to self sign
	cap := ucan.NewCapability(sign.PiecesRemoveScheduleAbility, alice.DID().String(), nb)
	inv, err := sign.PiecesRemoveSchedule.Invoke(alice, service, alice.DID().String(), nb)
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Empty(t, o)
	require.Equal(t, sign.InvalidResourceErrorName, x.Name())
}

func assertSignature(t *testing.T, signerAddr common.Address, sig sign.AuthSignature) {
	assert.NotEmpty(t, sig.Signature)
	assert.Equal(t, signerAddr, sig.Signer)
	assert.NotEmpty(t, sig.SignedData)
	assert.True(t, sig.V == 27 || sig.V == 28, "V should be 27 or 28")
}
