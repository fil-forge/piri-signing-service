// Package handlers binds the libforge /pdp/sign/* capabilities to the
// in-process eip712 signer.
package handlers

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/fil-forge/filecoin-services/go/eip712"
	sdm "github.com/fil-forge/libforge/capabilities/pdp/sign/datamodel"
)

// metadataToEntries converts a wire MetadataModel into the []MetadataEntry
// shape the eip712 signer consumes. The order of `Keys` is the canonical
// iteration order.
func metadataToEntries(m sdm.MetadataModel) []eip712.MetadataEntry {
	out := make([]eip712.MetadataEntry, 0, len(m.Keys))
	for _, k := range m.Keys {
		out = append(out, eip712.MetadataEntry{Key: k, Value: m.Values[k]})
	}
	return out
}

// authSignatureToModel converts an eip712.AuthSignature into the wire model.
func authSignatureToModel(sig *eip712.AuthSignature) *sdm.AuthSignatureModel {
	return &sdm.AuthSignatureModel{
		Signature:  sig.Signature,
		V:          sig.V,
		R:          sig.R.Bytes(),
		S:          sig.S.Bytes(),
		SignedData: sig.SignedData,
		Signer:     sig.Signer.Bytes(),
	}
}

// addressFromBytes parses an Ethereum 20-byte address from its wire form.
// Bytes shorter than 20 are right-padded; longer bytes are right-cropped
// (matching common.BytesToAddress semantics).
func addressFromBytes(b []byte) common.Address {
	return common.BytesToAddress(b)
}
