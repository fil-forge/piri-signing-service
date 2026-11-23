package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	logging "github.com/ipfs/go-log/v2"
	"go.uber.org/zap"
)

var log = logging.Logger("pkg/server")

// rejectionLogMessage is the message of every rejected-invocation log entry.
// Keep it stable: alerts and log queries match on it.
const rejectionLogMessage = "rejected UCAN invocation"

// rejectionLogger logs every invocation the server rejects: a failure receipt,
// whether from validation (an issuer DID that cannot be resolved, a missing
// proof, an unknown command) or from a handler, and an invocation addressed to
// another service, which the server skips without issuing a receipt.
//
// The server's request and response events see one container each, so
// withRequestRecord carries the decoded request from one event to the other in
// the request context.
type rejectionLogger struct {
	serviceDID string
	log        *zap.SugaredLogger
}

type requestRecordKey struct{}

// requestRecord holds the decoded request container of one HTTP request.
type requestRecord struct {
	container ucan.Container
}

// withRequestRecord gives each request a record for the listener to fill in.
func withRequestRecord(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), requestRecordKey{}, &requestRecord{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OnRequestDecode stores the request for OnResponseEncode. It never returns an
// error: an error from a listener fails the whole request.
func (l *rejectionLogger) OnRequestDecode(ctx context.Context, request ucan.Container) error {
	if record, ok := ctx.Value(requestRecordKey{}).(*requestRecord); ok {
		record.container = request
	}
	return nil
}

// OnResponseEncode logs each invocation of the request that has a failure
// receipt or no receipt at all. It never returns an error.
func (l *rejectionLogger) OnResponseEncode(ctx context.Context, response ucan.Container) error {
	record, ok := ctx.Value(requestRecordKey{}).(*requestRecord)
	if !ok || record.container == nil {
		return nil
	}
	for _, inv := range record.container.Invocations() {
		rcpt, ok := response.Receipt(inv.Task().Link())
		if !ok {
			l.log.Warnw(rejectionLogMessage, append(invocationFields(inv),
				"error", "InvalidAudience",
				"reason", "invocation is not addressed to this service "+l.serviceDID,
			)...)
			continue
		}
		_, errBytes := rcpt.Out().Unpack()
		if errBytes == nil {
			continue
		}
		name, reason := decodeFailure(errBytes)
		l.log.Warnw(rejectionLogMessage, append(invocationFields(inv),
			"error", name,
			"reason", reason,
		)...)
	}
	return nil
}

func invocationFields(inv ucan.Invocation) []any {
	fields := []any{
		"command", inv.Command().String(),
		"issuer", inv.Issuer().String(),
		"subject", inv.Subject().String(),
		"task", inv.Task().Link().String(),
	}
	if aud := inv.Audience(); aud.Defined() {
		fields = append(fields, "audience", aud.String())
	}
	return fields
}

// decodeFailure reads the error name and message from a failure receipt. A
// failure that is not a {name, message} map is returned as hex-encoded CBOR so
// the reason is still logged.
func decodeFailure(errBytes []byte) (name, reason string) {
	var model edm.ErrorModel
	if err := model.UnmarshalCBOR(bytes.NewReader(errBytes)); err != nil || model.Message == "" {
		return "UndecodableError", "failure receipt CBOR: " + hex.EncodeToString(errBytes)
	}
	return model.ErrorName, model.Message
}
