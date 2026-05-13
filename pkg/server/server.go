// Package server hosts the UCAN-facing HTTP server for piri-signing-service.
//
// The server exposes the four /pdp/sign/* capabilities — DataSetCreate,
// DataSetDelete, PiecesAdd, PiecesRemoveSchedule — backed by an in-process
// eip712 OperationSigner. Authorization is currently delegated to the UCAN
// validator's standard proof-chain checks; per-operation policies (e.g.
// authorized-operator only) can be layered on top via principal-resolution
// hooks.
package server

import (
	"net/http"

	signcaps "github.com/fil-forge/libforge/capabilities/pdp/sign"
	"github.com/fil-forge/ucantone/principal"
	ucanserver "github.com/fil-forge/ucantone/server"
	logging "github.com/ipfs/go-log/v2"

	"github.com/fil-forge/piri-signing-service/pkg/server/handlers"
	"github.com/fil-forge/piri-signing-service/pkg/types"
)

var log = logging.Logger("pkg/server")

// Server wraps a *ucanserver.HTTPServer with the /pdp/sign/* handlers
// pre-registered.
type Server struct {
	srv *ucanserver.HTTPServer
}

// New constructs a UCAN server with the four /pdp/sign/* handlers bound
// to `signer`. `id` is the service identity used to sign emitted receipts.
func New(id principal.Signer, signer types.OperationSigner) (*Server, error) {
	h := handlers.New(signer)
	srv := ucanserver.NewHTTP(id)
	srv.Handle(signcaps.DataSetCreate, h.DataSetCreate())
	srv.Handle(signcaps.DataSetDelete, h.DataSetDelete())
	srv.Handle(signcaps.PiecesAdd, h.PiecesAdd())
	srv.Handle(signcaps.PiecesRemoveSchedule, h.PiecesRemoveSchedule())
	log.Infow("piri-signing-service UCAN server initialized",
		"id", id.DID(),
		"commands", []string{
			signcaps.DataSetCreateCommand,
			signcaps.DataSetDeleteCommand,
			signcaps.PiecesAddCommand,
			signcaps.PiecesRemoveScheduleCommand,
		},
	)
	return &Server{srv: srv}, nil
}

// ServeHTTP forwards to the underlying ucantone HTTP server. Lets `*Server`
// drop into any net/http or echo route directly.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.srv.ServeHTTP(w, r)
}

// HTTPServer returns the underlying ucantone server for callers that need
// to register additional handlers or options.
func (s *Server) HTTPServer() *ucanserver.HTTPServer {
	return s.srv
}
