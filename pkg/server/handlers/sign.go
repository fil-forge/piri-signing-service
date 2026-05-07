package handlers

import (
	"context"
	"fmt"

	"github.com/fil-forge/filecoin-services/go/eip712"
	"github.com/fil-forge/go-libstoracha/capabilities/pdp/sign"
	"github.com/fil-forge/go-ucanto/core/invocation"
	"github.com/fil-forge/go-ucanto/core/receipt/fx"
	"github.com/fil-forge/go-ucanto/core/result"
	"github.com/fil-forge/go-ucanto/core/result/failure"
	"github.com/fil-forge/go-ucanto/principal"
	"github.com/fil-forge/go-ucanto/server"
	"github.com/fil-forge/go-ucanto/ucan"
	logging "github.com/ipfs/go-log/v2"

	"github.com/fil-forge/piri-signing-service/pkg/types"
)

var log = logging.Logger("pkg/server/handlers")

func NewDataSetCreateHandler(id principal.Signer, signer types.OperationSigner) server.HandlerFunc[sign.DataSetCreateCaveats, sign.DataSetCreateOk, failure.IPLDBuilderFailure] {
	return func(
		ctx context.Context,
		capability ucan.Capability[sign.DataSetCreateCaveats],
		invocation invocation.Invocation,
		context server.InvocationContext,
	) (result.Result[sign.DataSetCreateOk, failure.IPLDBuilderFailure], fx.Effects, error) {
		nb := capability.Nb()
		log.Infow(
			"handling signing request",
			"ability", sign.DataSetCreateAbility,
			"issuer", invocation.Issuer().DID(),
			"dataset", nb.DataSet.String(),
			"payee", nb.Payee.String(),
			"metadata", nb.Metadata.Values,
		)
		// issuer must have a delegation to use the service (cannot be self signed)
		if capability.With() != id.DID().String() {
			return result.Error[sign.DataSetCreateOk, failure.IPLDBuilderFailure](
				sign.NewInvalidResourceError(id.DID().String(), capability.With()),
			), nil, nil
		}

		s, err := signer.SignCreateDataSet(nb.DataSet, nb.Payee, toEIP712MetadataEntries(nb.Metadata))
		if err != nil {
			return nil, nil, fmt.Errorf("signing create dataset: %w", err)
		}

		return result.Ok[sign.DataSetCreateOk, failure.IPLDBuilderFailure](sign.DataSetCreateOk(*s)), nil, nil
	}
}

func NewDataSetDeleteHandler(id principal.Signer, signer types.OperationSigner) server.HandlerFunc[sign.DataSetDeleteCaveats, sign.DataSetDeleteOk, failure.IPLDBuilderFailure] {
	return func(
		ctx context.Context,
		capability ucan.Capability[sign.DataSetDeleteCaveats],
		invocation invocation.Invocation,
		context server.InvocationContext,
	) (result.Result[sign.DataSetDeleteOk, failure.IPLDBuilderFailure], fx.Effects, error) {
		nb := capability.Nb()
		log.Infow(
			"handling signing request",
			"ability", sign.DataSetDeleteAbility,
			"issuer", invocation.Issuer().DID(),
			"dataset", nb.DataSet.String(),
		)
		// issuer must have a delegation to use the service (cannot be self signed)
		if capability.With() != id.DID().String() {
			return result.Error[sign.DataSetDeleteOk, failure.IPLDBuilderFailure](
				sign.NewInvalidResourceError(id.DID().String(), capability.With()),
			), nil, nil
		}

		s, err := signer.SignDeleteDataSet(nb.DataSet)
		if err != nil {
			return nil, nil, fmt.Errorf("signing delete dataset: %w", err)
		}

		return result.Ok[sign.DataSetDeleteOk, failure.IPLDBuilderFailure](sign.DataSetDeleteOk(*s)), nil, nil
	}
}

func NewPiecesAddHandler(id principal.Signer, signer types.OperationSigner) server.HandlerFunc[sign.PiecesAddCaveats, sign.PiecesAddOk, failure.IPLDBuilderFailure] {
	return func(
		ctx context.Context,
		capability ucan.Capability[sign.PiecesAddCaveats],
		invocation invocation.Invocation,
		context server.InvocationContext,
	) (result.Result[sign.PiecesAddOk, failure.IPLDBuilderFailure], fx.Effects, error) {
		nb := capability.Nb()
		nonce := nb.Nonce

		log.Infow(
			"handling signing request",
			"ability", sign.PiecesAddAbility,
			"issuer", invocation.Issuer().DID(),
			"dataset", nb.DataSet.String(),
			"nonce", nonce.String(),
			"pieces", len(nb.PieceData),
		)
		// issuer must have a delegation to use the service (cannot be self signed)
		if capability.With() != id.DID().String() {
			return result.Error[sign.PiecesAddOk, failure.IPLDBuilderFailure](
				sign.NewInvalidResourceError(id.DID().String(), capability.With()),
			), nil, nil
		}

		// TODO: validate pieces

		metadata := make([][]eip712.MetadataEntry, 0, len(nb.Metadata))
		for _, m := range nb.Metadata {
			metadata = append(metadata, toEIP712MetadataEntries(m))
		}

		s, err := signer.SignAddPieces(nb.DataSet, nonce, nb.PieceData, metadata)
		if err != nil {
			return nil, nil, fmt.Errorf("signing add pieces: %w", err)
		}

		return result.Ok[sign.PiecesAddOk, failure.IPLDBuilderFailure](sign.PiecesAddOk(*s)), nil, nil
	}
}

func NewPiecesRemoveScheduleHandler(id principal.Signer, signer types.OperationSigner) server.HandlerFunc[sign.PiecesRemoveScheduleCaveats, sign.PiecesRemoveScheduleOk, failure.IPLDBuilderFailure] {
	return func(
		ctx context.Context,
		capability ucan.Capability[sign.PiecesRemoveScheduleCaveats],
		invocation invocation.Invocation,
		context server.InvocationContext,
	) (result.Result[sign.PiecesRemoveScheduleOk, failure.IPLDBuilderFailure], fx.Effects, error) {
		nb := capability.Nb()
		log.Infow(
			"handling signing request",
			"ability", sign.PiecesRemoveScheduleAbility,
			"issuer", invocation.Issuer().DID(),
			"dataset", nb.DataSet.String(),
			"pieces", len(nb.Pieces),
		)
		// issuer must have a delegation to use the service (cannot be self signed)
		if capability.With() != id.DID().String() {
			return result.Error[sign.PiecesRemoveScheduleOk, failure.IPLDBuilderFailure](
				sign.NewInvalidResourceError(id.DID().String(), capability.With()),
			), nil, nil
		}

		s, err := signer.SignSchedulePieceRemovals(nb.DataSet, nb.Pieces)
		if err != nil {
			return nil, nil, fmt.Errorf("signing schedule remove pieces: %w", err)
		}

		return result.Ok[sign.PiecesRemoveScheduleOk, failure.IPLDBuilderFailure](sign.PiecesRemoveScheduleOk(*s)), nil, nil
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
