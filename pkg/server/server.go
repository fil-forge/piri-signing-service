package server

import (
	"fmt"
	"time"

	"github.com/fil-forge/libforge/commands/access"
	"github.com/fil-forge/libforge/commands/pdp/sign"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/validator"

	"github.com/fil-forge/piri-signing-service/pkg/server/handlers"
	"github.com/fil-forge/piri-signing-service/pkg/types"
)

type config struct {
	insecureDidResolution bool
}

type Option func(*config) error

func WithInsecureDIDResolution() Option {
	return func(c *config) error {
		c.insecureDidResolution = true
		return nil
	}
}

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
// did:web resolver (HTTPS did.json fetch, cached; HTTP only with the insecure
// dev flag). Without this, the default validator only accepts did:key issuers
// and rejects invocations with "unsupported DID method: web". Returns an error
// if the resolver fails to initialize.
func New(id identity.Identity, signer types.OperationSigner, opts ...Option) (*server.HTTPServer, error) {
	cfg := &config{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	webResolverOpts := []web.Option{}
	if cfg.insecureDidResolution {
		webResolverOpts = append(webResolverOpts, web.WithInsecure(true))
	}
	webResolver, err := web.NewResolver(webResolverOpts...)
	if err != nil {
		return nil, err
	}

	selfDoc, err := identity.Identity{Issuer: id}.DIDDocument()
	if err != nil {
		return nil, fmt.Errorf("creating DID document for service identity: %w", err)
	}

	srv := server.NewHTTP(id,
		server.WithValidationOptions(
			validator.WithDIDResolver(resolver.ByMethod{
				"key": key.Resolver,
				"web": resolver.Tiered{
					resolver.WellKnown{id.DID(): selfDoc},
					resolver.NewCached(webResolver, time.Hour*3),
				},
			}),
		),
	)

	// /access/grant is how a node gets its first delegation, so it is invoked
	// self-issued, over the caller's own DID, and is served as it is.
	srv.HandleRoute(access.Grant.Route(handlers.NewAccessGrantHandler(id)))

	// A signing command is served only over this service's DID and only to
	// someone it delegated to, so every signature traces back to a grant.
	signing := middleware.Apply(
		[]server.Route{
			sign.DataSetCreate.Route(handlers.NewDataSetCreateHandler(signer)),
			sign.DataSetDelete.Route(handlers.NewDataSetDeleteHandler(signer)),
			sign.PiecesAdd.Route(handlers.NewPiecesAddHandler(signer)),
			sign.PiecesRemoveSchedule.Route(handlers.NewPiecesRemoveScheduleHandler(signer)),
		},
		middleware.NotSelfSigned(),
		middleware.OnlySubject(id.DID()),
	)
	for _, route := range signing {
		srv.HandleRoute(route)
	}

	return srv, nil
}
