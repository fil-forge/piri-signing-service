package handlers_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/libforge/commands/access"
	"github.com/fil-forge/ucantone/execution/bindexec"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"

	"github.com/fil-forge/piri-signing-service/pkg/server/handlers"
)

func TestAccessGrant_Success(t *testing.T) {
	alice := testutil.RandomSigner(t)
	service := testutil.RandomSigner(t)

	handler := handlers.NewAccessGrantHandler(service)

	inv, err := access.Grant.Invoke(alice, service.DID(), &access.GrantArguments{
		Attenuations: []access.CapabilityRequest{{Command: "/pdp/sign/pieces/add"}},
	})
	require.NoError(t, err)

	req, err := bindexec.NewRequest[*access.GrantArguments](t.Context(), inv)
	require.NoError(t, err)
	res, err := bindexec.NewResponse[*access.GrantOK](inv.Task().Link(), bindexec.WithSigner[*access.GrantOK](service))
	require.NoError(t, err)

	require.NoError(t, handler(req, res))

	okBytes, errBytes := res.Receipt().Out().Unpack()
	require.Nil(t, errBytes)
	require.NotNil(t, okBytes)

	var ok access.GrantOK
	require.NoError(t, ok.UnmarshalCBOR(bytes.NewReader(okBytes)))
	require.Len(t, ok.Delegations, 1)

	// Delegation envelope is attached to the response metadata.
	require.Len(t, res.Metadata().Delegations(), 1)
}

func TestAccessGrant_UnknownAbility(t *testing.T) {
	alice := testutil.RandomSigner(t)
	service := testutil.RandomSigner(t)

	handler := handlers.NewAccessGrantHandler(service)

	inv, err := access.Grant.Invoke(alice, service.DID(), &access.GrantArguments{
		Attenuations: []access.CapabilityRequest{{Command: "/foo/bar"}},
	})
	require.NoError(t, err)

	req, err := bindexec.NewRequest[*access.GrantArguments](t.Context(), inv)
	require.NoError(t, err)
	res, err := bindexec.NewResponse[*access.GrantOK](inv.Task().Link(), bindexec.WithSigner[*access.GrantOK](service))
	require.NoError(t, err)

	require.NoError(t, handler(req, res))

	require.False(t, res.Receipt().Out().IsOK())
}

// silence unused-import warning while keeping a hook for future test helpers
var _ = invocation.Invoke
