package handlers

import (
	"fmt"
	"math/big"

	"github.com/fil-forge/filecoin-services/go/eip712"
	signcaps "github.com/fil-forge/libforge/capabilities/pdp/sign"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/bindexec"

	"github.com/fil-forge/piri-signing-service/pkg/types"
)

// SignHandlers bundles the four /pdp/sign/* handlers, all backed by the
// same eip712 OperationSigner.
type SignHandlers struct {
	signer types.OperationSigner
}

// New constructs the handler set bound to `signer`.
func New(signer types.OperationSigner) *SignHandlers {
	return &SignHandlers{signer: signer}
}

// DataSetCreate returns the bindexec handler for /pdp/sign/dataset/create.
func (h *SignHandlers) DataSetCreate() execution.HandlerFunc {
	return bindexec.NewHandler(func(
		req *bindexec.Request[*signcaps.DataSetCreateArguments],
		res *bindexec.Response[*signcaps.DataSetCreateOK],
	) error {
		args := req.Task().Arguments()
		dataSet, err := signcaps.BigIntFromBytes(args.DataSet)
		if err != nil {
			return fmt.Errorf("decoding dataSet: %w", err)
		}
		sig, err := h.signer.SignCreateDataSet(
			dataSet,
			addressFromBytes(args.Payee),
			metadataToEntries(args.Metadata),
		)
		if err != nil {
			return fmt.Errorf("eip712 sign create dataset: %w", err)
		}
		return res.SetSuccess(authSignatureToModel(sig))
	})
}

// DataSetDelete returns the bindexec handler for /pdp/sign/dataset/delete.
func (h *SignHandlers) DataSetDelete() execution.HandlerFunc {
	return bindexec.NewHandler(func(
		req *bindexec.Request[*signcaps.DataSetDeleteArguments],
		res *bindexec.Response[*signcaps.DataSetDeleteOK],
	) error {
		args := req.Task().Arguments()
		dataSet, err := signcaps.BigIntFromBytes(args.DataSet)
		if err != nil {
			return fmt.Errorf("decoding dataSet: %w", err)
		}
		sig, err := h.signer.SignDeleteDataSet(dataSet)
		if err != nil {
			return fmt.Errorf("eip712 sign delete dataset: %w", err)
		}
		return res.SetSuccess(authSignatureToModel(sig))
	})
}

// PiecesAdd returns the bindexec handler for /pdp/sign/pieces/add.
//
// `args.Proofs` (the per-piece blob/accept invocation CID lists) is
// accepted for protocol completeness but unused by the eip712 signer —
// the receipts are validated upstream of the sign call.
func (h *SignHandlers) PiecesAdd() execution.HandlerFunc {
	return bindexec.NewHandler(func(
		req *bindexec.Request[*signcaps.PiecesAddArguments],
		res *bindexec.Response[*signcaps.PiecesAddOK],
	) error {
		args := req.Task().Arguments()
		dataSet, err := signcaps.BigIntFromBytes(args.DataSet)
		if err != nil {
			return fmt.Errorf("decoding dataSet: %w", err)
		}
		nonce, err := signcaps.BigIntFromBytes(args.Nonce)
		if err != nil {
			return fmt.Errorf("decoding nonce: %w", err)
		}
		if len(args.PieceData) != len(args.Metadata) {
			return fmt.Errorf("pieceData (%d) and metadata (%d) length mismatch",
				len(args.PieceData), len(args.Metadata))
		}
		metadata := make([][]eip712.MetadataEntry, len(args.Metadata))
		for i, m := range args.Metadata {
			metadata[i] = metadataToEntries(m)
		}
		sig, err := h.signer.SignAddPieces(dataSet, nonce, args.PieceData, metadata)
		if err != nil {
			return fmt.Errorf("eip712 sign add pieces: %w", err)
		}
		return res.SetSuccess(authSignatureToModel(sig))
	})
}

// PiecesRemoveSchedule returns the bindexec handler for
// /pdp/sign/pieces/remove/schedule.
func (h *SignHandlers) PiecesRemoveSchedule() execution.HandlerFunc {
	return bindexec.NewHandler(func(
		req *bindexec.Request[*signcaps.PiecesRemoveScheduleArguments],
		res *bindexec.Response[*signcaps.PiecesRemoveScheduleOK],
	) error {
		args := req.Task().Arguments()
		dataSet, err := signcaps.BigIntFromBytes(args.DataSet)
		if err != nil {
			return fmt.Errorf("decoding dataSet: %w", err)
		}
		pieceIds := make([]*big.Int, 0, len(args.Pieces))
		for i, p := range args.Pieces {
			id, err := signcaps.BigIntFromBytes(p)
			if err != nil {
				return fmt.Errorf("decoding pieces[%d]: %w", i, err)
			}
			pieceIds = append(pieceIds, id)
		}
		sig, err := h.signer.SignSchedulePieceRemovals(dataSet, pieceIds)
		if err != nil {
			return fmt.Errorf("eip712 sign schedule piece removals: %w", err)
		}
		return res.SetSuccess(authSignatureToModel(sig))
	})
}
