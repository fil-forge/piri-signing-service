package handlers

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fil-forge/go-libstoracha/capabilities/access"
	"github.com/fil-forge/go-ucanto/core/dag/blockstore"
	"github.com/fil-forge/go-ucanto/core/delegation"
	"github.com/fil-forge/go-ucanto/core/invocation"
	"github.com/fil-forge/go-ucanto/core/receipt/fx"
	"github.com/fil-forge/go-ucanto/core/result"
	"github.com/fil-forge/go-ucanto/core/result/failure"
	"github.com/fil-forge/go-ucanto/principal"
	"github.com/fil-forge/go-ucanto/server"
	"github.com/fil-forge/go-ucanto/ucan"
)

// validity is the time a granted delegation is valid for.
const validity = time.Hour

func NewAccessGrantHandler(id principal.Signer) server.HandlerFunc[access.GrantCaveats, access.GrantOk, failure.IPLDBuilderFailure] {
	return func(
		ctx context.Context,
		cap ucan.Capability[access.GrantCaveats],
		inv invocation.Invocation,
		ictx server.InvocationContext,
	) (result.Result[access.GrantOk, failure.IPLDBuilderFailure], fx.Effects, error) {
		nb := cap.Nb()
		log.Infow(
			"handling access request",
			"ability", access.GrantAbility,
			"issuer", inv.Issuer().DID(),
			"capabilities", nb.Att,
			"cause", nb.Cause,
		)
		if len(nb.Att) == 0 {
			return result.Error[access.GrantOk, failure.IPLDBuilderFailure](access.NewMissingCapabilityError()), nil, nil
		}
		var cause invocation.Invocation
		if cap.Nb().Cause != nil {
			bs, err := blockstore.NewBlockReader(blockstore.WithBlocksIterator(inv.Blocks()))
			if err != nil {
				return nil, nil, fmt.Errorf("reading invocation blocks: %w", err)
			}
			cause, err = invocation.NewInvocationView(cap.Nb().Cause, bs)
			if err != nil {
				return nil, nil, fmt.Errorf("creating cause invocation: %w", err)
			}
		}

		delegations := map[string]delegation.Delegation{}
		for _, cap := range cap.Nb().Att {
			res, err := grantCapability(ctx, id, inv.Issuer(), cap.Can, cause)
			if err != nil {
				return nil, nil, err
			}
			o, x := result.Unwrap(res)
			if x != nil {
				return result.Error[access.GrantOk](x), nil, nil
			}
			delegations[o.Link().String()] = o
		}

		res := access.GrantOk{
			Delegations: access.DelegationsModel{Values: map[string][]byte{}},
		}
		for cid, dlg := range delegations {
			r := dlg.Archive()
			b, err := io.ReadAll(r)
			if err != nil {
				return nil, nil, fmt.Errorf("reading granted delegation archive: %w", err)
			}
			res.Delegations.Keys = append(res.Delegations.Keys, cid)
			res.Delegations.Values[cid] = b
		}

		return result.Ok[access.GrantOk, failure.IPLDBuilderFailure](res), nil, nil
	}
}

func grantCapability(
	ctx context.Context,
	id ucan.Signer,
	audience ucan.Principal,
	ability ucan.Ability,
	cause invocation.Invocation,
) (result.Result[delegation.Delegation, failure.IPLDBuilderFailure], error) {
	if !strings.HasPrefix(ability, "pdp/sign") {
		return result.Error[delegation.Delegation, failure.IPLDBuilderFailure](access.NewUnknownAbilityError(ability)), nil
	}

	// TODO: validate the issuer is a node known to be operating on the network

	d, err := delegation.Delegate(
		id,
		audience,
		[]ucan.Capability[ucan.NoCaveats]{
			ucan.NewCapability(ability, id.DID().String(), ucan.NoCaveats{}),
		},
		delegation.WithExpiration(ucan.Now()+int(validity.Seconds())),
	)
	if err != nil {
		return nil, err
	}

	log.Infow("delegated capability", "ability", ability, "audience", audience.DID().String())
	return result.Ok[delegation.Delegation, failure.IPLDBuilderFailure](d), nil
}
