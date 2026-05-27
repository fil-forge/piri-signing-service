package server

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/libforge/commands/access"
	"github.com/fil-forge/libforge/commands/pdp/sign"
	"github.com/fil-forge/libforge/didresolver"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
	logging "github.com/ipfs/go-log/v2"

	"github.com/fil-forge/piri-signing-service/pkg/server/handlers"
	"github.com/fil-forge/piri-signing-service/pkg/types"
)

var log = logging.Logger("pkg/server")

// New constructs a UCAN 1.0 HTTP server that handles the five
// signing-service capabilities:
//
//   - /access/grant            — issue a delegation for a /pdp/sign/* ability
//   - /pdp/sign/dataset/create
//   - /pdp/sign/dataset/delete
//   - /pdp/sign/pieces/add
//   - /pdp/sign/pieces/remove/schedule
//
// The returned server implements http.Handler.
//
// Piri clients sign invocations as did:web:piri-N, so the server registers a
// did:web resolver (HTTP did.json fetch, cached). Without this, the default
// validator only accepts did:key issuers and rejects invocations with
// "unsupported DID method: web". Returns an error if the resolver fails to
// initialize.
func New(id principal.Signer, signer types.OperationSigner) (*server.HTTPServer, error) {
	httpResolver, err := didresolver.NewHTTPResolver(didresolver.InsecureResolution())
	if err != nil {
		return nil, err
	}
	cacheResolver, err := didresolver.NewCachedResolver(httpResolver.Resolve, time.Hour*3)
	if err != nil {
		return nil, err
	}

	// Self-resolution short-circuit: when an incoming invocation carries a
	// proof issued by this service's own DID (e.g. piri presenting a
	// /access/grant we issued), the validator otherwise tries to fetch our own
	// did.json over HTTP from ourselves — which fails because we don't listen
	// on port 80, and would be wasteful even if we did. Hand back the
	// in-memory identity instead. Falls through to the HTTP resolver for any
	// other did:web.
	webResolver := didresolver.NewTieredResolver(
		selfResolver(id),
		cacheResolver.Resolve,
	)

	srv := server.NewHTTP(id,
		server.WithValidationOptions(
			validator.WithDIDVerifierResolvers(validator.VerifierResolverMap{
				"key": validator.ResolveDIDKeyVerifier,
				"web": webResolver.Resolve,
			}),
		),
	)

	srv.Handle(access.Grant.Command, binding.NewHandler(handlers.NewAccessGrantHandler(id)))
	srv.Handle(sign.DataSetCreate.Command, binding.NewHandler(handlers.NewDataSetCreateHandler(id, signer)))
	srv.Handle(sign.DataSetDelete.Command, binding.NewHandler(handlers.NewDataSetDeleteHandler(id, signer)))
	srv.Handle(sign.PiecesAdd.Command, binding.NewHandler(handlers.NewPiecesAddHandler(id, signer)))
	srv.Handle(sign.PiecesRemoveSchedule.Command, binding.NewHandler(handlers.NewPiecesRemoveScheduleHandler(id, signer)))

	return srv, nil
}

// selfResolver returns a DID resolver tier that satisfies requests for the
// service's own DID using the in-memory identity. Returns an error for any
// other DID so a TieredResolver falls through to the next tier.
func selfResolver(id principal.Signer) didresolver.DIDVerifierResolverFunc {
	selfDID := id.DID()
	verifier := id.Verifier()
	return func(_ context.Context, input did.DID) (ucan.Verifier, error) {
		if input != selfDID {
			return nil, fmt.Errorf("not the service's own DID")
		}
		return verifier, nil
	}
}
