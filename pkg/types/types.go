package types

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fil-forge/filecoin-services/go/eip712"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
)

// CreateDataSetRequest represents the request payload for creating a dataset
type CreateDataSetRequest struct {
	ClientDataSetId string                 `json:"clientDataSetId"`
	Payee           string                 `json:"payee"`
	Metadata        []eip712.MetadataEntry `json:"metadata"`
}

// AddPiecesRequest represents the request payload for adding pieces
type AddPiecesRequest struct {
	ClientDataSetId string                   `json:"clientDataSetId"`
	Nonce           string                   `json:"nonce"`
	PieceData       []string                 `json:"pieceData"` // hex-encoded bytes
	Metadata        [][]eip712.MetadataEntry `json:"metadata"`
}

// SchedulePieceRemovalsRequest represents the request payload for scheduling piece removals
type SchedulePieceRemovalsRequest struct {
	ClientDataSetId string   `json:"clientDataSetId"`
	PieceIds        []string `json:"pieceIds"`
}

// DeleteDataSetRequest represents the request payload for deleting a dataset
type DeleteDataSetRequest struct {
	ClientDataSetId string `json:"clientDataSetId"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string `json:"status"`
	Signer string `json:"signer"`
}

// SigningService defines the interface for authorized PDP operation signing.
// This can be implemented by:
//   - UCAN client (remote signing service)
//   - In-process signer (for testing/dev)
//
// This allows piri nodes to use either implementation interchangeably,
// enabling easy testing and development without running a separate service.
type SigningService interface {
	// SignCreateDataSet signs a CreateDataSet operation
	SignCreateDataSet(
		ctx context.Context,
		issuer ucan.Signer,
		dataSet *big.Int,
		payee common.Address,
		metadata []eip712.MetadataEntry,
		options ...invocation.Option,
	) (*eip712.AuthSignature, error)

	// SignAddPieces signs an AddPieces operation. `proofs` references prior
	// `blob/accept` task CIDs; `proofBundle` carries the invocation/receipt
	// container for the proof chain.
	SignAddPieces(
		ctx context.Context,
		issuer ucan.Signer,
		dataSet *big.Int,
		nonce *big.Int,
		pieceData [][]byte,
		metadata [][]eip712.MetadataEntry,
		proofs [][]cid.Cid,
		proofBundle []*container.Container,
		options ...invocation.Option,
	) (*eip712.AuthSignature, error)

	// SignSchedulePieceRemovals signs a SchedulePieceRemovals operation
	SignSchedulePieceRemovals(
		ctx context.Context,
		issuer ucan.Signer,
		dataSet *big.Int,
		pieceIds []*big.Int,
		options ...invocation.Option,
	) (*eip712.AuthSignature, error)

	// SignDeleteDataSet signs a DeleteDataSet operation
	SignDeleteDataSet(
		ctx context.Context,
		issuer ucan.Signer,
		dataSet *big.Int,
		options ...invocation.Option,
	) (*eip712.AuthSignature, error)
}

// OperationSigner defines the interface for PDP operation signing.
type OperationSigner interface {
	// SignCreateDataSet signs a CreateDataSet operation
	SignCreateDataSet(dataSet *big.Int, payee common.Address, metadata []eip712.MetadataEntry) (*eip712.AuthSignature, error)

	// SignAddPieces signs an AddPieces operation
	SignAddPieces(dataSet *big.Int, nonce *big.Int, pieceData [][]byte, metadata [][]eip712.MetadataEntry) (*eip712.AuthSignature, error)

	// SignSchedulePieceRemovals signs a SchedulePieceRemovals operation
	SignSchedulePieceRemovals(dataSet *big.Int, pieceIds []*big.Int) (*eip712.AuthSignature, error)

	// SignDeleteDataSet signs a DeleteDataSet operation
	SignDeleteDataSet(dataSet *big.Int) (*eip712.AuthSignature, error)
}
