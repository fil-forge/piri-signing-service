package server

import (
	"fmt"
	"net/http"

	"github.com/fil-forge/libforge/commands/access"
	"github.com/fil-forge/libforge/commands/pdp/sign"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/validator"
	"go.uber.org/zap"

	"github.com/fil-forge/piri-signing-service/pkg/server/handlers"
	"github.com/fil-forge/piri-signing-service/pkg/types"
)

type config struct {
	insecureDidResolution bool
	log                   *zap.SugaredLogger
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
// The returned handler logs every invocation it rejects at warn level, with
// the reason; see rejectionLogger.
//
// Piri clients sign invocations as did:web:piri-N, so the server registers a
// did:web resolver (HTTPS did.json fetch, cached; HTTP only with the insecure
// dev flag). Without this, the default validator only accepts did:key issuers
// and rejects invocations with "unsupported DID method: web". Returns an error
// if the resolver fails to initialize.
func New(id identity.Identity, signer types.OperationSigner, opts ...Option) (http.Handler, error) {
	cfg := &config{log: &log.SugaredLogger}
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

	rejections := &rejectionLogger{serviceDID: id.DID().String(), log: cfg.log}
	srv := server.NewHTTP(id,
		server.WithEventListener(rejections),
		server.WithValidationOptions(
			validator.WithDIDResolver(resolver.ByMethod{
				"key": key.Resolver,
				"web": resolver.Tiered{
					resolver.WellKnown{id.DID(): selfDoc},
					webResolver,
				},
			}),
		),
	)

	srv.Handle(access.Grant.Command, binding.NewHandler(handlers.NewAccessGrantHandler(id)))
	srv.Handle(sign.DataSetCreate.Command, binding.NewHandler(handlers.NewDataSetCreateHandler(id, signer)))
	srv.Handle(sign.DataSetDelete.Command, binding.NewHandler(handlers.NewDataSetDeleteHandler(id, signer)))
	srv.Handle(sign.PiecesAdd.Command, binding.NewHandler(handlers.NewPiecesAddHandler(id, signer)))
	srv.Handle(sign.PiecesRemoveSchedule.Command, binding.NewHandler(handlers.NewPiecesRemoveScheduleHandler(id, signer)))

	return withRequestRecord(srv), nil
}
