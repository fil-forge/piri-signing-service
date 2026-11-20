package server_test

import (
	"bytes"
	"math/big"
	"net/http"
	"net/url"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fil-forge/libforge/commands/access"
	"github.com/fil-forge/libforge/commands/pdp/sign"
	"github.com/fil-forge/libforge/identity"
	ucanclient "github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"

	"github.com/fil-forge/piri-signing-service/pkg/client"
	"github.com/fil-forge/piri-signing-service/pkg/server"
	"github.com/fil-forge/piri-signing-service/pkg/signer"
)

// signCall invokes one signing command through the client. The subject is the
// client's ServiceDID, so a test picks it by building the client over that DID.
type signCall struct {
	command ucan.Command
	invoke  func(c *client.Client, issuer ucan.Issuer, proofs []ucan.Delegation, opts ...invocation.Option) error
}

func signCalls(t *testing.T) []signCall {
	return []signCall{
		{sign.DataSetCreate.Command, func(c *client.Client, issuer ucan.Issuer, proofs []ucan.Delegation, opts ...invocation.Option) error {
			_, err := c.SignCreateDataSet(t.Context(), issuer, big.NewInt(1), common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12"), nil, proofs, opts...)
			return err
		}},
		{sign.DataSetDelete.Command, func(c *client.Client, issuer ucan.Issuer, proofs []ucan.Delegation, opts ...invocation.Option) error {
			_, err := c.SignDeleteDataSet(t.Context(), issuer, big.NewInt(1), proofs, opts...)
			return err
		}},
		{sign.PiecesAdd.Command, func(c *client.Client, issuer ucan.Issuer, proofs []ucan.Delegation, opts ...invocation.Option) error {
			_, err := c.SignAddPieces(t.Context(), issuer, big.NewInt(1), big.NewInt(2), nil, nil, nil, nil, proofs, opts...)
			return err
		}},
		{sign.PiecesRemoveSchedule.Command, func(c *client.Client, issuer ucan.Issuer, proofs []ucan.Delegation, opts ...invocation.Option) error {
			_, err := c.SignSchedulePieceRemovals(t.Context(), issuer, big.NewInt(1), []*big.Int{big.NewInt(3)}, proofs, opts...)
			return err
		}},
	}
}

// newService starts the real server over a random identity and signing key, and
// returns a ucantone client whose transport is the server itself.
func newService(t *testing.T) (identity.Identity, *ucanclient.HTTPClient) {
	t.Helper()
	id := identity.Identity{Issuer: testutil.RandomMultikeyIssuer(t)}
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	s := signer.NewSigner(key, big.NewInt(314159), common.HexToAddress("0x8b7aa0a68f5717e400F1C4D37F7a28f84f76dF91"))

	srv, err := server.New(id, s)
	require.NoError(t, err)

	endpoint, err := url.Parse("http://test")
	require.NoError(t, err)
	httpClient, err := ucanclient.NewHTTP(endpoint, ucanclient.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)
	return id, httpClient
}

// requestGrant asks the service for a delegation the way a node does: with a
// self-issued /access/grant invocation addressed to the service.
func requestGrant(t *testing.T, httpClient *ucanclient.HTTPClient, issuer ucan.Issuer, service did.DID, cmd ucan.Command) ucan.Delegation {
	t.Helper()
	inv, err := access.Grant.Invoke(issuer, issuer.DID(), &access.GrantArguments{
		Attenuations: []access.CapabilityRequest{{Command: cmd}},
	}, invocation.WithAudience(service))
	require.NoError(t, err)

	resp, err := httpClient.Execute(execution.NewRequest(t.Context(), inv))
	require.NoError(t, err)
	out := resp.Receipt().Out()
	okBytes, errBytes := out.Unpack()
	require.True(t, out.IsOK(), "grant failed: %s", errBytes)

	var ok access.GrantOK
	require.NoError(t, ok.UnmarshalCBOR(bytes.NewReader(okBytes)))
	require.Len(t, ok.Delegations, 1)
	for _, d := range resp.Metadata().Delegations() {
		if d.Link() == ok.Delegations[0] {
			return d
		}
	}
	t.Fatalf("response did not carry delegation %s", ok.Delegations[0])
	return nil
}

func TestSigningRoutes(t *testing.T) {
	t.Run("signs for a node holding a grant", func(t *testing.T) {
		id, httpClient := newService(t)
		node := testutil.RandomIssuer(t)
		c := &client.Client{ServiceDID: id.DID(), HTTP: httpClient}

		for _, call := range signCalls(t) {
			t.Run(call.command.String(), func(t *testing.T) {
				grant := requestGrant(t, httpClient, node, id.DID(), call.command)
				require.NoError(t, call.invoke(c, node, []ucan.Delegation{grant}))
			})
		}
	})

	t.Run("rejects an invocation without a grant", func(t *testing.T) {
		id, httpClient := newService(t)
		node := testutil.RandomIssuer(t)
		c := &client.Client{ServiceDID: id.DID(), HTTP: httpClient}

		for _, call := range signCalls(t) {
			t.Run(call.command.String(), func(t *testing.T) {
				require.Error(t, call.invoke(c, node, nil))
			})
		}
	})

	t.Run("rejects a grant for another command", func(t *testing.T) {
		id, httpClient := newService(t)
		node := testutil.RandomIssuer(t)
		c := &client.Client{ServiceDID: id.DID(), HTTP: httpClient}

		grant := requestGrant(t, httpClient, node, id.DID(), sign.DataSetDelete.Command)
		for _, call := range signCalls(t) {
			if call.command == sign.DataSetDelete.Command {
				continue
			}
			t.Run(call.command.String(), func(t *testing.T) {
				require.Error(t, call.invoke(c, node, []ucan.Delegation{grant}))
			})
		}
	})

	t.Run("rejects an invocation the caller issued over its own DID", func(t *testing.T) {
		id, httpClient := newService(t)
		node := testutil.RandomIssuer(t)
		// The node is the subject, so the invocation needs no proofs to validate.
		c := &client.Client{ServiceDID: node.DID(), HTTP: httpClient}

		for _, call := range signCalls(t) {
			t.Run(call.command.String(), func(t *testing.T) {
				err := call.invoke(c, node, nil, invocation.WithAudience(id.DID()))
				require.ErrorContains(t, err, middleware.SelfSignedInvocationErrorName)
			})
		}
	})

	t.Run("rejects a valid delegation chain rooted in another subject", func(t *testing.T) {
		id, httpClient := newService(t)
		node := testutil.RandomIssuer(t)
		other := testutil.RandomIssuer(t)
		c := &client.Client{ServiceDID: other.DID(), HTTP: httpClient}

		for _, call := range signCalls(t) {
			t.Run(call.command.String(), func(t *testing.T) {
				dlg, err := delegation.Delegate(other, node.DID(), other.DID(), call.command)
				require.NoError(t, err)
				err = call.invoke(c, node, []ucan.Delegation{dlg}, invocation.WithAudience(id.DID()))
				require.ErrorContains(t, err, middleware.InvalidSubjectErrorName)
			})
		}
	})
}
