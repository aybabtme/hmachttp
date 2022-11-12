package hmachttp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

const HeaderKey = "Authentication"

type ctxPrivateKeyID struct{}

// GetPrivateKeyID returns the authenticated ID of the private key that
// was used to send a request via the hmac http.Handler.
func GetPrivateKeyID(ctx context.Context) string {
	return ctx.Value(ctxPrivateKeyID{}).(string)
}

type hmacEnvelope struct {
	Msg       []byte `json:"m"`
	Signature []byte `json:"s"`
}

type hmacMessage struct {
	KeyID     string `json:"k"`
	UnixMicro int64  `json:"t"`
}

type Keystore interface {
	GetPrivateKeyByID(ctx context.Context, keyID string) ([]byte, bool, error)
}

func Handler(in http.Handler, keystore Keystore, headerKey string, maxClockSkew time.Duration, unauth http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hmacValueb64 := r.Header.Get(headerKey)
		if hmacValueb64 == "" {
			unauth.ServeHTTP(w, r)
			return
		}
		hmacValue, err := base64.URLEncoding.DecodeString(hmacValueb64)
		if err != nil {
			unauth.ServeHTTP(w, r)
			return
		}
		var env hmacEnvelope
		if err := json.Unmarshal(hmacValue, &env); err != nil {
			unauth.ServeHTTP(w, r)
			return
		}
		signedMessage := env.Msg
		var msg hmacMessage
		if err := json.Unmarshal(env.Msg, &msg); err != nil {
			unauth.ServeHTTP(w, r)
			return
		}
		if msg.KeyID == "" {
			unauth.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		privateKey, ok, err := keystore.GetPrivateKeyByID(ctx, msg.KeyID)
		if err != nil || !ok {
			unauth.ServeHTTP(w, r)
			return
		}

		h := hmac.New(sha256.New, privateKey)
		h.Write(signedMessage)
		sig := h.Sum(nil)

		// if signature mismatches
		if !hmac.Equal(env.Signature, sig) {
			unauth.ServeHTTP(w, r)
			return
		}

		// if signature is too old
		signedAt := time.UnixMicro(msg.UnixMicro)
		now := time.Now()
		minSignedAt := now.Add(-maxClockSkew)
		maxSignedAt := now.Add(maxClockSkew)
		if signedAt.Before(minSignedAt) || signedAt.After(maxSignedAt) {
			unauth.ServeHTTP(w, r)
			return
		}
		r = r.WithContext(context.WithValue(ctx, ctxPrivateKeyID{}, msg.KeyID))
		// signature matched, and message isnt too old, accept the request
		in.ServeHTTP(w, r)
	})
}

// RoundTripper add authentication to outgoing requests.
func RoundTripper(in http.RoundTripper, headerKey, keyID string, privateKey []byte) http.RoundTripper {
	return roundtripper(func(r *http.Request) (*http.Response, error) {
		now := time.Now()
		msg := hmacMessage{
			KeyID:     keyID,
			UnixMicro: now.UnixMicro(),
		}
		signedMessage, err := json.Marshal(msg)
		if err != nil {
			return nil, errors.Wrap(err, "marshaling HMAC message")
		}
		h := hmac.New(sha256.New, privateKey)
		h.Write(signedMessage)
		sig := h.Sum(nil)

		hmacValue, err := json.Marshal(hmacEnvelope{
			Msg:       signedMessage,
			Signature: sig,
		})
		if err != nil {
			return nil, errors.Wrap(err, "marshaling HMAC value")
		}

		r.Header.Set(headerKey, base64.URLEncoding.EncodeToString(hmacValue))

		return in.RoundTrip(r)
	})
}

type roundtripper func(*http.Request) (*http.Response, error)

func (fn roundtripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
