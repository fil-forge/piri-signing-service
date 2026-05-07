package handlers_test

import (
	"testing"

	"github.com/fil-forge/go-libstoracha/capabilities/access"
	"github.com/fil-forge/go-libstoracha/testutil"
	"github.com/fil-forge/go-ucanto/core/invocation"
	"github.com/fil-forge/go-ucanto/core/result"
	"github.com/fil-forge/go-ucanto/ucan"
	"github.com/fil-forge/piri-signing-service/pkg/server/handlers"
	"github.com/stretchr/testify/require"
)

func TestAccessGrant_Success(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	handler := handlers.NewAccessGrantHandler(service)

	nb := access.GrantCaveats{
		Att: []access.CapabilityRequest{{Can: "pdp/sign/pieces/add"}},
	}
	cap := ucan.NewCapability(access.GrantAbility, alice.DID().String(), nb)
	inv, err := invocation.Invoke(alice, service, cap)
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Nil(t, x)
	require.Len(t, o.Delegations.Values, 1)
}

func TestAccessGrant_UnknownAbility(t *testing.T) {
	alice := testutil.Alice
	service := testutil.WebService

	handler := handlers.NewAccessGrantHandler(service)

	nb := access.GrantCaveats{
		Att: []access.CapabilityRequest{{Can: "foo/bar"}},
	}
	cap := ucan.NewCapability(access.GrantAbility, alice.DID().String(), nb)
	inv, err := invocation.Invoke(alice, service, cap)
	require.NoError(t, err)

	res, fx, err := handler(t.Context(), cap, inv, nil)
	require.NoError(t, err)
	require.Nil(t, fx)

	o, x := result.Unwrap(res)
	require.Empty(t, o)
	require.Equal(t, access.UnknownAbilityErrorName, x.Name())
}
