package inprocess

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fil-forge/filecoin-services/go/eip712"
	"github.com/fil-forge/go-ucanto/core/delegation"
	"github.com/fil-forge/go-ucanto/core/ipld"
	"github.com/fil-forge/go-ucanto/core/message"
	"github.com/fil-forge/go-ucanto/ucan"
	"github.com/fil-forge/piri-signing-service/pkg/signer"
	"github.com/fil-forge/piri-signing-service/pkg/types"
)

// Signer implements [types.SigningService] using eip712.Signer directly.
// This provides an in-process implementation that bypasses network calls, and
// authorization checks - useful for testing and development.
type Signer struct {
	signer *signer.Signer
}

// Verify that Signer implements types.SigningService at compile time
var _ types.SigningService = (*Signer)(nil)

// New creates a new in-process signing service
func New(signer *signer.Signer) *Signer {
	return &Signer{signer: signer}
}

// SignCreateDataSet signs a CreateDataSet operation directly
func (s *Signer) SignCreateDataSet(ctx context.Context,
	issuer ucan.Signer,
	clientDataSetId *big.Int,
	payee common.Address,
	metadata []eip712.MetadataEntry,
	options ...delegation.Option) (*eip712.AuthSignature, error) {
	// Context is accepted but not used since signing is synchronous
	return s.signer.SignCreateDataSet(clientDataSetId, payee, metadata)
}

// SignAddPieces signs an AddPieces operation directly
func (s *Signer) SignAddPieces(ctx context.Context,
	issuer ucan.Signer,
	clientDataSetId *big.Int,
	nonce *big.Int,
	pieceData [][]byte,
	metadata [][]eip712.MetadataEntry,
	proofs [][]ipld.Link,
	proofData [][]message.AgentMessage,
	options ...delegation.Option) (*eip712.AuthSignature, error) {
	return s.signer.SignAddPieces(clientDataSetId, nonce, pieceData, metadata)
}

// SignSchedulePieceRemovals signs a SchedulePieceRemovals operation directly
func (s *Signer) SignSchedulePieceRemovals(ctx context.Context,
	issuer ucan.Signer,
	clientDataSetId *big.Int,
	pieceIds []*big.Int,
	options ...delegation.Option) (*eip712.AuthSignature, error) {
	return s.signer.SignSchedulePieceRemovals(clientDataSetId, pieceIds)
}

// SignDeleteDataSet signs a DeleteDataSet operation directly
func (s *Signer) SignDeleteDataSet(ctx context.Context,
	issuer ucan.Signer,
	clientDataSetId *big.Int,
	options ...delegation.Option) (*eip712.AuthSignature, error) {
	return s.signer.SignDeleteDataSet(clientDataSetId)
}
