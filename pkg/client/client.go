package client

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/url"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fil-forge/filecoin-services/go/eip712"
	"github.com/fil-forge/go-libstoracha/capabilities/pdp/sign"
	"github.com/fil-forge/go-ucanto/client"
	"github.com/fil-forge/go-ucanto/core/dag/blockstore"
	"github.com/fil-forge/go-ucanto/core/delegation"
	"github.com/fil-forge/go-ucanto/core/invocation"
	"github.com/fil-forge/go-ucanto/core/ipld"
	"github.com/fil-forge/go-ucanto/core/message"
	"github.com/fil-forge/go-ucanto/core/receipt"
	"github.com/fil-forge/go-ucanto/core/result"
	fdm "github.com/fil-forge/go-ucanto/core/result/failure/datamodel"
	ucan_http "github.com/fil-forge/go-ucanto/transport/http"
	"github.com/fil-forge/go-ucanto/ucan"

	"github.com/fil-forge/piri-signing-service/pkg/types"
)

// Client uses UCAN invocations to request a remote signing service to sign PDP operations.
type Client struct {
	Connection        client.Connection   // Connection to the service.
	InvocationOptions []delegation.Option // Options added to every invocation.
}

// Verify that Client implements types.SigningService at compile time
var _ types.SigningService = (*Client)(nil)

type clientConfig struct {
	httpClient        *http.Client
	invocationOptions []delegation.Option
}

type Option func(*clientConfig)

// WithHTTPClient configures a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *clientConfig) {
		c.httpClient = client
	}
}

// WithInvocationOptions configures invocation options that are sent with every
// request.
func WithInvocationOptions(opts ...delegation.Option) Option {
	return func(c *clientConfig) {
		c.invocationOptions = append(c.invocationOptions, opts...)
	}
}

// New creates a new client for the signing service.
func New(serviceID ucan.Principal, serviceURL string, options ...Option) (*Client, error) {
	cfg := clientConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	endpoint, err := url.Parse(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing signing service URL: %w", err)
	}
	channel := ucan_http.NewChannel(endpoint, ucan_http.WithClient(cfg.httpClient))
	conn, err := client.NewConnection(serviceID, channel)
	if err != nil {
		return nil, fmt.Errorf("creating signing service connection: %w", err)
	}
	return &Client{conn, cfg.invocationOptions}, nil
}

// SignCreateDataSet signs a CreateDataSet operation via UCAN invocation
func (c *Client) SignCreateDataSet(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	payee common.Address,
	metadata []eip712.MetadataEntry,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	var opts []delegation.Option
	opts = append(append(opts, c.InvocationOptions...), options...)
	inv, err := sign.DataSetCreate.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.DataSetCreateCaveats{
			DataSet:  dataSet,
			Payee:    payee,
			Metadata: fromEIP712MetadataEntries(metadata),
		},
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.DataSetCreateAbility, err)
	}
	return execInvocation(ctx, c.Connection, inv)
}

// SignAddPieces signs an AddPieces operation via UCAN invocation
func (c *Client) SignAddPieces(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	nonce *big.Int,
	pieceData [][]byte,
	metadata [][]eip712.MetadataEntry,
	proofs [][]ipld.Link,
	proofData [][]message.AgentMessage,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	metaModel := make([]sign.Metadata, 0, len(metadata))
	for _, m := range metadata {
		metaModel = append(metaModel, fromEIP712MetadataEntries(m))
	}

	var opts []delegation.Option
	opts = append(append(opts, c.InvocationOptions...), options...)
	inv, err := sign.PiecesAdd.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.PiecesAddCaveats{
			DataSet:   dataSet,
			Nonce:     nonce,
			PieceData: pieceData,
			Metadata:  metaModel,
			Proofs:    proofs,
		},
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.PiecesAddAbility, err)
	}

	for _, pd := range proofData {
		for _, msg := range pd {
			for b, err := range msg.Blocks() {
				if err != nil {
					return nil, fmt.Errorf("iterating blocks in proof data %s: %w", msg.Root().Link(), err)
				}
				if err := inv.Attach(b); err != nil {
					return nil, fmt.Errorf("attaching block %s: %w", b.Link(), err)
				}
			}
		}
	}

	return execInvocation(ctx, c.Connection, inv)
}

// SignSchedulePieceRemovals signs a SchedulePieceRemovals operation via UCAN invocation
func (c *Client) SignSchedulePieceRemovals(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	pieceIds []*big.Int,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	var opts []delegation.Option
	opts = append(append(opts, c.InvocationOptions...), options...)
	inv, err := sign.PiecesRemoveSchedule.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.PiecesRemoveScheduleCaveats{
			DataSet: dataSet,
			Pieces:  pieceIds,
		},
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.PiecesRemoveScheduleAbility, err)
	}
	return execInvocation(ctx, c.Connection, inv)
}

// SignDeleteDataSet signs a DeleteDataSet operation via UCAN invocation
func (c *Client) SignDeleteDataSet(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	options ...delegation.Option,
) (*eip712.AuthSignature, error) {
	var opts []delegation.Option
	opts = append(append(opts, c.InvocationOptions...), options...)
	inv, err := sign.DataSetDelete.Invoke(
		issuer,
		c.Connection.ID(),
		c.Connection.ID().DID().String(),
		sign.DataSetDeleteCaveats{
			DataSet: dataSet,
		},
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("invoking %s: %w", sign.DataSetDeleteAbility, err)
	}
	return execInvocation(ctx, c.Connection, inv)
}

func execInvocation(ctx context.Context, conn client.Connection, inv invocation.Invocation) (*eip712.AuthSignature, error) {
	xres, err := client.Execute(ctx, []invocation.Invocation{inv}, conn)
	if err != nil {
		return nil, fmt.Errorf("executing %s: %w", inv.Capabilities()[0].Can(), err)
	}
	rcptLink, ok := xres.Get(inv.Link())
	if !ok {
		return nil, fmt.Errorf("missing receipt for invocation: %s", inv.Link())
	}
	blocks, err := blockstore.NewBlockReader(blockstore.WithBlocksIterator(xres.Blocks()))
	if err != nil {
		return nil, fmt.Errorf("reading agent message blocks: %w", err)
	}
	rcpt, err := receipt.NewAnyReceipt(rcptLink, blocks)
	if err != nil {
		return nil, fmt.Errorf("creating receipt: %w", err)
	}
	return result.MatchResultR2(
		rcpt.Out(),
		func(o ipld.Node) (*eip712.AuthSignature, error) {
			sig, err := sign.AuthSignatureReader.Read(o)
			if err != nil {
				return nil, fmt.Errorf("reading signature: %w", err)
			}
			eipSig := eip712.AuthSignature(sig)
			return &eipSig, nil
		},
		func(x ipld.Node) (*eip712.AuthSignature, error) {
			signErr, err := sign.SignErrorReader.Read(x)
			if err != nil {
				return nil, fdm.Bind(x)
			}
			return nil, signErr
		},
	)
}

func fromEIP712MetadataEntries(entries []eip712.MetadataEntry) sign.Metadata {
	meta := sign.Metadata{
		Keys:   make([]string, 0, len(entries)),
		Values: make(map[string]string, len(entries)),
	}
	for _, e := range entries {
		meta.Keys = append(meta.Keys, e.Key)
		meta.Values[e.Key] = e.Value
	}
	return meta
}
