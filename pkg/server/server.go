package server

import (
	"github.com/fil-forge/libforge/commands/access"
	"github.com/fil-forge/libforge/commands/pdp/sign"
	"github.com/fil-forge/ucantone/execution/bindexec"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/server"
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
func New(id principal.Signer, signer types.OperationSigner) *server.HTTPServer {
	srv := server.NewHTTP(id)

	srv.Handle(access.Grant.Command, bindexec.NewHandler(handlers.NewAccessGrantHandler(id)))
	srv.Handle(sign.DataSetCreate.Command, bindexec.NewHandler(handlers.NewDataSetCreateHandler(id, signer)))
	srv.Handle(sign.DataSetDelete.Command, bindexec.NewHandler(handlers.NewDataSetDeleteHandler(id, signer)))
	srv.Handle(sign.PiecesAdd.Command, bindexec.NewHandler(handlers.NewPiecesAddHandler(id, signer)))
	srv.Handle(sign.PiecesRemoveSchedule.Command, bindexec.NewHandler(handlers.NewPiecesRemoveScheduleHandler(id, signer)))

	return srv
}
