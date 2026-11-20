package handlers

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fil-forge/filecoin-services/go/eip712"
	"github.com/fil-forge/libforge/commands/pdp/sign"
	"github.com/fil-forge/ucantone/binding"
	logging "github.com/ipfs/go-log/v2"

	"github.com/fil-forge/piri-signing-service/pkg/types"
)

var log = logging.Logger("pkg/server/handlers")

// The signing handlers sign whatever they are handed. Who may invoke them is
// settled by the checks the server puts in front of each route.

// NewDataSetCreateHandler wraps the underlying eip712 signer in a
// binding UCAN handler for /pdp/sign/dataset/create.
func NewDataSetCreateHandler(signer types.OperationSigner) binding.HandlerFunc[*sign.DataSetCreateArguments, *sign.DataSetCreateOK] {
	return func(req *binding.Request[*sign.DataSetCreateArguments], res *binding.Response[*sign.DataSetCreateOK]) error {
		args := req.Task().Arguments()
		inv := req.Invocation()
		log.Infow(
			"handling signing request",
			"command", sign.DataSetCreate.Command,
			"issuer", inv.Issuer(),
			"dataset", args.DataSet.String(),
			"payee", args.Payee,
			"metadata", args.Metadata.Values,
		)
		s, err := signer.SignCreateDataSet(args.DataSet, common.BytesToAddress(args.Payee), toEIP712MetadataEntries(args.Metadata))
		if err != nil {
			return fmt.Errorf("signing create dataset: %w", err)
		}
		ok := toLibforgeAuthSig(s)
		return res.SetSuccess(&ok)
	}
}

// NewDataSetDeleteHandler wraps the underlying eip712 signer in a
// binding UCAN handler for /pdp/sign/dataset/delete.
func NewDataSetDeleteHandler(signer types.OperationSigner) binding.HandlerFunc[*sign.DataSetDeleteArguments, *sign.DataSetDeleteOK] {
	return func(req *binding.Request[*sign.DataSetDeleteArguments], res *binding.Response[*sign.DataSetDeleteOK]) error {
		args := req.Task().Arguments()
		inv := req.Invocation()
		log.Infow(
			"handling signing request",
			"command", sign.DataSetDelete.Command,
			"issuer", inv.Issuer(),
			"dataset", args.DataSet.String(),
		)
		s, err := signer.SignDeleteDataSet(args.DataSet)
		if err != nil {
			return fmt.Errorf("signing delete dataset: %w", err)
		}
		ok := toLibforgeAuthSig(s)
		return res.SetSuccess(&ok)
	}
}

// NewPiecesAddHandler wraps the underlying eip712 signer in a
// binding UCAN handler for /pdp/sign/pieces/add.
func NewPiecesAddHandler(signer types.OperationSigner) binding.HandlerFunc[*sign.PiecesAddArguments, *sign.PiecesAddOK] {
	return func(req *binding.Request[*sign.PiecesAddArguments], res *binding.Response[*sign.PiecesAddOK]) error {
		args := req.Task().Arguments()
		inv := req.Invocation()
		log.Infow(
			"handling signing request",
			"command", sign.PiecesAdd.Command,
			"issuer", inv.Issuer(),
			"dataset", args.DataSet.String(),
			"nonce", args.Nonce.String(),
			"pieces", len(args.PieceData),
		)
		// TODO: validate pieces against the proof container

		metadata := make([][]eip712.MetadataEntry, 0, len(args.Metadata))
		for _, m := range args.Metadata {
			metadata = append(metadata, toEIP712MetadataEntries(m))
		}

		s, err := signer.SignAddPieces(args.DataSet, args.Nonce, args.PieceData, metadata)
		if err != nil {
			return fmt.Errorf("signing add pieces: %w", err)
		}
		ok := toLibforgeAuthSig(s)
		return res.SetSuccess(&ok)
	}
}

// NewPiecesRemoveScheduleHandler wraps the underlying eip712 signer in a
// binding UCAN handler for /pdp/sign/pieces/remove/schedule.
func NewPiecesRemoveScheduleHandler(signer types.OperationSigner) binding.HandlerFunc[*sign.PiecesRemoveScheduleArguments, *sign.PiecesRemoveScheduleOK] {
	return func(req *binding.Request[*sign.PiecesRemoveScheduleArguments],
		res *binding.Response[*sign.PiecesRemoveScheduleOK]) error {
		args := req.Task().Arguments()
		inv := req.Invocation()
		log.Infow(
			"handling signing request",
			"command", sign.PiecesRemoveSchedule.Command,
			"issuer", inv.Issuer(),
			"dataset", args.DataSet.String(),
			"pieces", len(args.Pieces),
		)
		s, err := signer.SignSchedulePieceRemovals(args.DataSet, args.Pieces)
		if err != nil {
			return fmt.Errorf("signing schedule remove pieces: %w", err)
		}
		ok := toLibforgeAuthSig(s)
		return res.SetSuccess(&ok)
	}
}

// toLibforgeAuthSig copies an eip712.AuthSignature into the libforge
// pdp/sign.AuthSignature wire shape (fixed-size address/hash fields become
// raw []byte).
func toLibforgeAuthSig(s *eip712.AuthSignature) sign.AuthSignature {
	return sign.AuthSignature{
		Signature:  s.Signature,
		V:          s.V,
		R:          s.R[:],
		S:          s.S[:],
		SignedData: s.SignedData,
		Signer:     s.Signer.Bytes(),
	}
}

func toEIP712MetadataEntries(m sign.Metadata) []eip712.MetadataEntry {
	meta := make([]eip712.MetadataEntry, 0, len(m.Values))
	for _, k := range m.Keys {
		v := m.Values[k]
		meta = append(meta, eip712.MetadataEntry{Key: k, Value: v})
	}
	return meta
}
