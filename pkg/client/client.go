// Package client is a remote-mode UCAN client for piri-signing-service.
//
// Each Sign* method builds the matching /pdp/sign/* invocation, sends it
// over the configured ucantone HTTP transport, and decodes the eip712
// AuthSignature from the response receipt.
//
// Authorization proofs:
//   - The optional `...delegation.Option` parameter accepts extra invocation
//     options (typically WithProofs(...)) so callers can attach a delegation
//     authorizing the issuer to sign on behalf of the audience.
//   - For /pdp/sign/pieces/add, the caller may also pass `proofBundle` — a
//     list of containers holding the (invocation, receipt) pairs proving
//     the pieces' sub-pieces have been accepted. All blocks from those
//     bundles are attached to the outgoing container.
package client

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"net/url"

	"github.com/fil-forge/ucantone/did"
	"github.com/ethereum/go-ethereum/common"
	"github.com/fil-forge/filecoin-services/go/eip712"
	signcaps "github.com/fil-forge/libforge/capabilities/pdp/sign"
	ucanclient "github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"

	"github.com/fil-forge/piri-signing-service/pkg/types"
)

// Client invokes the four /pdp/sign/* capabilities against a remote
// piri-signing-service.
type Client struct {
	serviceID   did.DID
	executor    execution.Executor
	defaultOpts []invocation.Option
}

// Verify that Client implements types.SigningService at compile time.
var _ types.SigningService = (*Client)(nil)

type clientConfig struct {
	httpOptions []ucanclient.HTTPOption
	invOptions  []invocation.Option
}

// Option configures a Client.
type Option func(*clientConfig)

// WithHTTPOption forwards a ucantone HTTP client option to the underlying
// transport (e.g. custom *http.Client, event listeners).
func WithHTTPOption(opt ucanclient.HTTPOption) Option {
	return func(cfg *clientConfig) {
		cfg.httpOptions = append(cfg.httpOptions, opt)
	}
}

// WithInvocationOptions configures invocation options that are sent with
// every request (e.g. a default proof chain).
func WithInvocationOptions(opts ...invocation.Option) Option {
	return func(cfg *clientConfig) {
		cfg.invOptions = append(cfg.invOptions, opts...)
	}
}

// New constructs a Client targeting `serviceURL`. `serviceID` is the
// signing service's DID — used as the invocation audience.
func New(serviceID did.DID, serviceURL string, options ...Option) (*Client, error) {
	endpoint, err := url.Parse(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing signing service URL: %w", err)
	}
	cfg := clientConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	httpC, err := ucanclient.NewHTTP(endpoint, cfg.httpOptions...)
	if err != nil {
		return nil, fmt.Errorf("constructing ucantone HTTP client: %w", err)
	}
	return NewFromHTTPClient(serviceID, httpC, cfg.invOptions...), nil
}

// NewFromHTTPClient constructs a Client from a pre-built ucantone
// HTTPClient. Useful when the transport has already been assembled (e.g.
// by a config layer that bundled DID + HTTPClient together).
func NewFromHTTPClient(
	serviceID did.DID, 
	executor execution.Executor, 
	defaultOpts ...invocation.Option,
	) *Client {
	return &Client{
		serviceID:   serviceID,
		executor:  executor,
		defaultOpts: defaultOpts,
	}
}

// SignCreateDataSet invokes /pdp/sign/dataset/create.
func (c *Client) SignCreateDataSet(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	payee common.Address,
	metadata []eip712.MetadataEntry,
	options ...invocation.Option,
) (*eip712.AuthSignature, error) {
	args := &signcaps.DataSetCreateArguments{
		DataSet:  signcaps.BigIntToBytes(dataSet),
		Payee:    payee.Bytes(),
		Metadata: entriesToMetadata(metadata),
	}
	inv, err := signcaps.DataSetCreate.Invoke(issuer, c.serviceID, args, c.invocationOptions(options)...)
	if err != nil {
		return nil, fmt.Errorf("building DataSetCreate invocation: %w", err)
	}
	return c.exec(ctx, inv, nil)
}

// SignDeleteDataSet invokes /pdp/sign/dataset/delete.
func (c *Client) SignDeleteDataSet(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	options ...invocation.Option,
) (*eip712.AuthSignature, error) {
	args := &signcaps.DataSetDeleteArguments{
		DataSet: signcaps.BigIntToBytes(dataSet),
	}
	inv, err := signcaps.DataSetDelete.Invoke(issuer, c.serviceID, args, c.invocationOptions(options)...)
	if err != nil {
		return nil, fmt.Errorf("building DataSetDelete invocation: %w", err)
	}
	return c.exec(ctx, inv, nil)
}

// SignAddPieces invokes /pdp/sign/pieces/add. `proofs` is a per-piece list
// of `blob/accept` invocation CIDs; `proofBundle` contains the matching
// (invocation, receipt) pairs that the server validates against.
func (c *Client) SignAddPieces(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	nonce *big.Int,
	pieceData [][]byte,
	metadata [][]eip712.MetadataEntry,
	proofs [][]cid.Cid,
	proofBundle []*container.Container,
	options ...invocation.Option,
) (*eip712.AuthSignature, error) {
	if len(pieceData) != len(metadata) {
		return nil, fmt.Errorf("pieceData (%d) and metadata (%d) length mismatch", len(pieceData), len(metadata))
	}
	if len(proofs) != 0 && len(proofs) != len(pieceData) {
		return nil, fmt.Errorf("proofs (%d) and pieceData (%d) length mismatch", len(proofs), len(pieceData))
	}
	mdModels := make([]signcaps.Metadata, len(metadata))
	for i, m := range metadata {
		mdModels[i] = entriesToMetadata(m)
	}
	proofModels := make([]signcaps.PieceProofs, len(pieceData))
	for i := range proofModels {
		if i < len(proofs) {
			proofModels[i] = signcaps.PieceProofs{Proofs: proofs[i]}
		} else {
			proofModels[i] = signcaps.PieceProofs{}
		}
	}
	args := &signcaps.PiecesAddArguments{
		DataSet:   signcaps.BigIntToBytes(dataSet),
		Nonce:     signcaps.BigIntToBytes(nonce),
		PieceData: pieceData,
		Metadata:  mdModels,
		Proofs:    proofModels,
	}
	inv, err := signcaps.PiecesAdd.Invoke(issuer, c.serviceID, args, c.invocationOptions(options)...)
	if err != nil {
		return nil, fmt.Errorf("building PiecesAdd invocation: %w", err)
	}
	return c.exec(ctx, inv, proofBundle)
}

// SignSchedulePieceRemovals invokes /pdp/sign/pieces/remove/schedule.
func (c *Client) SignSchedulePieceRemovals(
	ctx context.Context,
	issuer ucan.Signer,
	dataSet *big.Int,
	pieceIds []*big.Int,
	options ...invocation.Option,
) (*eip712.AuthSignature, error) {
	pieces := make([][]byte, len(pieceIds))
	for i, p := range pieceIds {
		pieces[i] = signcaps.BigIntToBytes(p)
	}
	args := &signcaps.PiecesRemoveScheduleArguments{
		DataSet: signcaps.BigIntToBytes(dataSet),
		Pieces:  pieces,
	}
	inv, err := signcaps.PiecesRemoveSchedule.Invoke(issuer, c.serviceID, args, c.invocationOptions(options)...)
	if err != nil {
		return nil, fmt.Errorf("building PiecesRemoveSchedule invocation: %w", err)
	}
	return c.exec(ctx, inv, nil)
}

// exec sends `inv` to the signing service, optionally merging additional
// proof-bundle containers into the request, and decodes the AuthSignature
// from the receipt.
func (c *Client) exec(ctx context.Context, inv *invocation.Invocation, proofBundle []*container.Container) (*eip712.AuthSignature, error) {
	reqOpts := []execution.RequestOption{}
	for _, b := range proofBundle {
		if b == nil {
			continue
		}
		reqOpts = append(reqOpts,
			execution.WithInvocations(b.Invocations()...),
			execution.WithReceipts(b.Receipts()...),
			execution.WithDelegations(b.Delegations()...),
		)
	}
	req := execution.NewRequest(ctx, inv, reqOpts...)
	resp, err := c.executor.Execute(req)
	if err != nil {
		return nil, fmt.Errorf("executing %s: %w", inv.Command(), err)
	}
	rcpt := resp.Receipt()
	if rcpt == nil {
		return nil, fmt.Errorf("no receipt for %s", inv.Command())
	}
	out := rcpt.Out()
	if !out.IsOK() {
		_, errBytes := out.Unpack()
		return nil, fmt.Errorf("receipt failure for %s: %s", inv.Command(), string(errBytes))
	}
	okBytes, _ := out.Unpack()
	var model signcaps.AuthSignature
	if err := model.UnmarshalCBOR(bytes.NewReader(okBytes)); err != nil {
		return nil, fmt.Errorf("decoding AuthSignature: %w", err)
	}
	return modelToAuthSignature(&model), nil
}

func (c *Client) invocationOptions(extras []invocation.Option) []invocation.Option {
	// Default options first (typically WithProofs), then caller extras.
	out := append([]invocation.Option{}, c.defaultOpts...)
	out = append(out, extras...)
	return out
}

// entriesToMetadata builds a libforge MetadataModel from a flat list of
// eip712 metadata entries. Insertion order is preserved via Keys.
func entriesToMetadata(entries []eip712.MetadataEntry) signcaps.Metadata {
	m := signcaps.Metadata{
		Keys:   make([]string, 0, len(entries)),
		Values: make(map[string]string, len(entries)),
	}
	for _, e := range entries {
		m.Keys = append(m.Keys, e.Key)
		m.Values[e.Key] = e.Value
	}
	return m
}

// modelToAuthSignature rehydrates an eip712.AuthSignature from the wire model.
func modelToAuthSignature(m *signcaps.AuthSignature) *eip712.AuthSignature {
	return &eip712.AuthSignature{
		Signature:  m.Signature,
		V:          m.V,
		R:          common.BytesToHash(m.R),
		S:          common.BytesToHash(m.S),
		SignedData: m.SignedData,
		Signer:     common.BytesToAddress(m.Signer),
	}
}
