package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fil-forge/libforge/commands/access"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRejectionLog_UnresolvableDIDWebIssuer(t *testing.T) {
	service, logs, invoke := startServer(t)
	piri := unresolvableDIDWebIssuer(t)
	inv := grantInvocation(t, piri, service.DID())

	require.NoError(t, invoke(inv))

	require.Equal(t, []map[string]any{{
		"command": access.Grant.Command.String(),
		"issuer":  piri.DID().String(),
		"subject": service.DID().String(),
		"task":    inv.Task().Link().String(),
		"error":   "DIDKeyResolutionError",
		"reason": fmt.Sprintf(
			"unable to resolve %[1]q key: not resolvable by any resolver: "+
				"unable to resolve %[1]q key: not found in mapping: %[1]s\nunexpected status: 404",
			piri.DID().String(),
		),
	}}, warnings(logs))
}

func TestRejectionLog_InvocationForAnotherService(t *testing.T) {
	_, logs, invoke := startServer(t)
	alice := testutil.RandomIssuer(t)
	otherService := testutil.RandomIssuer(t)
	inv := grantInvocation(t, alice, otherService.DID())

	// The server skips the invocation without a receipt, which the client
	// reports as an error.
	_ = invoke(inv)

	require.Equal(t, []map[string]any{{
		"command": access.Grant.Command.String(),
		"issuer":  alice.DID().String(),
		"subject": otherService.DID().String(),
		"task":    inv.Task().Link().String(),
		"error":   "InvalidAudience",
		"reason":  "invocation is not addressed to this service did:web:signer.test",
	}}, warnings(logs))
}

func TestRejectionLog_AcceptedInvocationIsNotLogged(t *testing.T) {
	service, logs, invoke := startServer(t)

	require.NoError(t, invoke(grantInvocation(t, service, service.DID())))

	require.Empty(t, warnings(logs))
}

// startServer runs the signing service's UCAN server with its log captured. It
// returns the service identity, the captured log and a function that sends one
// invocation to the server and returns the client's error.
func startServer(t *testing.T) (identity.Identity, *observer.ObservedLogs, func(ucan.Invocation) error) {
	t.Helper()
	serviceDID, err := did.Parse("did:web:signer.test")
	require.NoError(t, err)
	service := identity.Identity{Issuer: multikey.NewIssuer(serviceDID, testutil.RandomMultikeySigner(t))}

	core, logs := observer.New(zapcore.DebugLevel)
	handler, err := New(service, nil, WithInsecureDIDResolution(), withLogger(zap.New(core).Sugar()))
	require.NoError(t, err)
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)

	endpoint, err := url.Parse(httpServer.URL)
	require.NoError(t, err)
	ucanClient, err := client.NewHTTP(endpoint)
	require.NoError(t, err)

	invoke := func(inv ucan.Invocation) error {
		_, err := ucanClient.Execute(execution.NewRequest(t.Context(), inv))
		return err
	}
	return service, logs, invoke
}

// unresolvableDIDWebIssuer returns an issuer whose did:web points at a host
// that answers every DID document request with 404.
func unresolvableDIDWebIssuer(t *testing.T) ucan.Issuer {
	t.Helper()
	host := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(host.Close)
	hostPort := strings.TrimPrefix(host.URL, "http://")
	issuerDID, err := did.Parse("did:web:" + strings.ReplaceAll(hostPort, ":", "%3A"))
	require.NoError(t, err)
	return multikey.NewIssuer(issuerDID, testutil.RandomMultikeySigner(t))
}

func grantInvocation(t *testing.T, issuer ucan.Issuer, subject did.DID) ucan.Invocation {
	t.Helper()
	inv, err := access.Grant.Invoke(issuer, subject, &access.GrantArguments{
		Attenuations: []access.CapabilityRequest{{Command: command.MustParse("/pdp/sign/pieces/add")}},
	})
	require.NoError(t, err)
	return inv
}

func warnings(logs *observer.ObservedLogs) []map[string]any {
	var entries []map[string]any
	for _, entry := range logs.FilterMessage(rejectionLogMessage).FilterLevelExact(zapcore.WarnLevel).All() {
		entries = append(entries, entry.ContextMap())
	}
	return entries
}

func withLogger(logger *zap.SugaredLogger) Option {
	return func(c *config) error {
		c.log = logger
		return nil
	}
}
