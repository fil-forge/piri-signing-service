package client

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fil-forge/filecoin-services/go/eip712"
	"github.com/fil-forge/go-libstoracha/capabilities/pdp/sign"
	"github.com/fil-forge/go-libstoracha/testutil"
	"github.com/fil-forge/go-ucanto/client"
	"github.com/fil-forge/go-ucanto/core/delegation"
	"github.com/fil-forge/go-ucanto/core/invocation"
	"github.com/fil-forge/go-ucanto/core/ipld"
	"github.com/fil-forge/go-ucanto/core/message"
	"github.com/fil-forge/go-ucanto/core/receipt"
	"github.com/fil-forge/go-ucanto/core/receipt/fx"
	"github.com/fil-forge/go-ucanto/core/receipt/ran"
	"github.com/fil-forge/go-ucanto/core/result"
	"github.com/fil-forge/go-ucanto/core/result/failure"
	"github.com/fil-forge/go-ucanto/core/result/ok"
	"github.com/fil-forge/go-ucanto/server"
	"github.com/fil-forge/go-ucanto/ucan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_SignCreateDataSet(t *testing.T) {
	mockSignature := mockSignature()

	server, err := server.NewServer(testutil.WebService, server.WithServiceMethod(
		sign.DataSetCreateAbility,
		server.Provide(
			sign.DataSetCreate,
			func(
				ctx context.Context,
				capability ucan.Capability[sign.DataSetCreateCaveats],
				invocation invocation.Invocation,
				context server.InvocationContext,
			) (result.Result[sign.DataSetCreateOk, failure.IPLDBuilderFailure], fx.Effects, error) {
				req := capability.Nb()
				assert.Equal(t, "12345", req.DataSet.String())
				assert.Equal(t, "0xabCDEF1234567890ABcDEF1234567890aBCDeF12", req.Payee.String())
				assert.Len(t, req.Metadata.Keys, 1)
				assert.Equal(t, "test-key", req.Metadata.Keys[0])
				return result.Ok[sign.DataSetCreateOk, failure.IPLDBuilderFailure](sign.DataSetCreateOk(*mockSignature)), nil, nil
			},
		),
	))
	require.NoError(t, err)

	client := Client{Connection: testutil.Must(client.NewConnection(testutil.WebService, server))(t)}

	dataSet := big.NewInt(12345)
	payee := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	metadata := []eip712.MetadataEntry{
		{Key: "test-key", Value: "test-value"},
	}

	signature, err := client.SignCreateDataSet(
		t.Context(),
		testutil.Alice,
		dataSet,
		payee,
		metadata,
		delegation.WithProof(delegation.FromDelegation(mkproof(t))),
	)
	require.NoError(t, err)
	assert.NotNil(t, signature)
	assert.Equal(t, mockSignature.Signer, signature.Signer)
	assert.Equal(t, mockSignature.R, signature.R)
	assert.Equal(t, mockSignature.S, signature.S)
	assert.Equal(t, mockSignature.V, signature.V)
}

func TestClient_SignAddPieces(t *testing.T) {
	mockSignature := mockSignature()

	server, err := server.NewServer(testutil.WebService, server.WithServiceMethod(
		sign.PiecesAddAbility,
		server.Provide(
			sign.PiecesAdd,
			func(
				ctx context.Context,
				capability ucan.Capability[sign.PiecesAddCaveats],
				invocation invocation.Invocation,
				context server.InvocationContext,
			) (result.Result[sign.PiecesAddOk, failure.IPLDBuilderFailure], fx.Effects, error) {
				req := capability.Nb()
				assert.Equal(t, "12345", req.DataSet.String())
				assert.Equal(t, "0", req.Nonce.String())
				assert.Len(t, req.PieceData, 2)
				assert.Equal(t, []byte("piece1"), req.PieceData[0])
				assert.Len(t, req.Proofs, 1)
				assert.Len(t, req.Proofs[0], 1)
				return result.Ok[sign.PiecesAddOk, failure.IPLDBuilderFailure](sign.PiecesAddOk(*mockSignature)), nil, nil
			},
		),
	))
	require.NoError(t, err)

	client := Client{Connection: testutil.Must(client.NewConnection(testutil.WebService, server))(t)}

	dataSet := big.NewInt(12345)
	firstAdded := big.NewInt(0)
	pieceData := [][]byte{
		[]byte("piece1"),
		[]byte("piece2"),
	}
	metadata := [][]eip712.MetadataEntry{
		{{Key: "piece1-key", Value: "piece1-value"}},
		{{Key: "piece2-key", Value: "piece2-value"}},
	}
	task := testutil.RandomCID(t)
	rcpt, err := receipt.Issue(
		testutil.Alice,
		result.Ok[ok.Unit, failure.IPLDBuilderFailure](ok.Unit{}),
		ran.FromLink(task),
	)
	require.NoError(t, err)

	msg, err := message.Build(nil, []receipt.AnyReceipt{rcpt})
	require.NoError(t, err)

	signature, err := client.SignAddPieces(
		t.Context(),
		testutil.Alice,
		dataSet,
		firstAdded,
		pieceData,
		metadata,
		[][]ipld.Link{{task}},
		[][]message.AgentMessage{{msg}},
		delegation.WithProof(delegation.FromDelegation(mkproof(t))),
	)
	require.NoError(t, err)
	assert.NotNil(t, signature)
	assert.Equal(t, mockSignature.Signer, signature.Signer)
}

func TestClient_SignSchedulePieceRemovals(t *testing.T) {
	mockSignature := mockSignature()

	server, err := server.NewServer(testutil.WebService, server.WithServiceMethod(
		sign.PiecesRemoveScheduleAbility,
		server.Provide(
			sign.PiecesRemoveSchedule,
			func(
				ctx context.Context,
				capability ucan.Capability[sign.PiecesRemoveScheduleCaveats],
				invocation invocation.Invocation,
				context server.InvocationContext,
			) (result.Result[sign.PiecesRemoveScheduleOk, failure.IPLDBuilderFailure], fx.Effects, error) {
				req := capability.Nb()
				assert.Equal(t, "12345", req.DataSet.String())
				assert.Len(t, req.Pieces, 3)
				assert.Equal(t, "1", req.Pieces[0].String())
				assert.Equal(t, "2", req.Pieces[1].String())
				assert.Equal(t, "3", req.Pieces[2].String())
				return result.Ok[sign.PiecesRemoveScheduleOk, failure.IPLDBuilderFailure](sign.PiecesRemoveScheduleOk(*mockSignature)), nil, nil
			},
		),
	))
	require.NoError(t, err)

	client := Client{Connection: testutil.Must(client.NewConnection(testutil.WebService, server))(t)}

	dataSet := big.NewInt(12345)
	pieces := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}

	signature, err := client.SignSchedulePieceRemovals(
		t.Context(),
		testutil.Alice,
		dataSet,
		pieces,
		delegation.WithProof(delegation.FromDelegation(mkproof(t))),
	)
	require.NoError(t, err)
	assert.NotNil(t, signature)
	assert.Equal(t, mockSignature.Signer, signature.Signer)
}

func TestClient_SignDeleteDataSet(t *testing.T) {
	mockSignature := mockSignature()

	server, err := server.NewServer(testutil.WebService, server.WithServiceMethod(
		sign.DataSetDeleteAbility,
		server.Provide(
			sign.DataSetDelete,
			func(
				ctx context.Context,
				capability ucan.Capability[sign.DataSetDeleteCaveats],
				invocation invocation.Invocation,
				context server.InvocationContext,
			) (result.Result[sign.DataSetDeleteOk, failure.IPLDBuilderFailure], fx.Effects, error) {
				req := capability.Nb()
				assert.Equal(t, "12345", req.DataSet.String())
				return result.Ok[sign.DataSetDeleteOk, failure.IPLDBuilderFailure](sign.DataSetDeleteOk(*mockSignature)), nil, nil
			},
		),
	))
	require.NoError(t, err)

	client := Client{Connection: testutil.Must(client.NewConnection(testutil.WebService, server))(t)}

	dataSet := big.NewInt(12345)

	signature, err := client.SignDeleteDataSet(
		t.Context(),
		testutil.Alice,
		dataSet,
		delegation.WithProof(delegation.FromDelegation(mkproof(t))),
	)
	require.NoError(t, err)
	assert.NotNil(t, signature)
	assert.Equal(t, mockSignature.Signer, signature.Signer)
}

func TestClient_ServerError(t *testing.T) {
	server, err := server.NewServer(testutil.WebService, server.WithServiceMethod(
		sign.DataSetCreateAbility,
		server.Provide(
			sign.DataSetCreate,
			func(
				ctx context.Context,
				capability ucan.Capability[sign.DataSetCreateCaveats],
				invocation invocation.Invocation,
				context server.InvocationContext,
			) (result.Result[sign.DataSetCreateOk, failure.IPLDBuilderFailure], fx.Effects, error) {
				return nil, nil, errors.New("boom")
			},
		),
	))
	require.NoError(t, err)

	client := Client{Connection: testutil.Must(client.NewConnection(testutil.WebService, server))(t)}

	clientDataSetId := big.NewInt(12345)
	payee := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	metadata := []eip712.MetadataEntry{}

	_, err = client.SignCreateDataSet(
		t.Context(),
		testutil.Alice,
		clientDataSetId,
		payee,
		metadata,
		delegation.WithProof(delegation.FromDelegation(mkproof(t))),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestClient_Unauthorized(t *testing.T) {
	server, err := server.NewServer(testutil.WebService, server.WithServiceMethod(
		sign.DataSetCreateAbility,
		server.Provide(
			sign.DataSetCreate,
			func(
				ctx context.Context,
				capability ucan.Capability[sign.DataSetCreateCaveats],
				invocation invocation.Invocation,
				context server.InvocationContext,
			) (result.Result[sign.DataSetCreateOk, failure.IPLDBuilderFailure], fx.Effects, error) {
				return nil, nil, errors.New("boom")
			},
		),
	))
	require.NoError(t, err)

	client := Client{Connection: testutil.Must(client.NewConnection(testutil.WebService, server))(t)}

	clientDataSetId := big.NewInt(12345)
	payee := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	metadata := []eip712.MetadataEntry{}

	_, err = client.SignCreateDataSet(
		t.Context(),
		testutil.Alice,
		clientDataSetId,
		payee,
		metadata,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func mkproof(t *testing.T) delegation.Delegation {
	return testutil.Must(
		delegation.Delegate(
			testutil.WebService,
			testutil.Alice,
			[]ucan.Capability[ucan.NoCaveats]{
				ucan.NewCapability("pdp/sign/*", testutil.WebService.DID().String(), ucan.NoCaveats{}),
			},
		),
	)(t)
}

func mockSignature() *eip712.AuthSignature {
	return &eip712.AuthSignature{
		Signer: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		R:      common.BigToHash(big.NewInt(12345)),
		S:      common.BigToHash(big.NewInt(67890)),
		V:      27,
	}
}
