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

func Securer(keystore Keystore, headerKey string, maxClockSkew time.Duration, unauth Reject) func(http.Handler) http.Handler {
	return func(in http.Handler) http.Handler {
		return Handler(in, keystore, headerKey, maxClockSkew, unauth)
	}
}

type Reject func(w http.ResponseWriter, r *http.Request, cause string)

func Handler(in http.Handler, keystore Keystore, headerKey string, maxClockSkew time.Duration, unauth Reject) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hmacValueb64 := r.Header.Get(headerKey)
		if hmacValueb64 == "" {
			unauth(w, r, "no-header")
			return
		}
		hmacValue, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(hmacValueb64)
		if err != nil {
			unauth(w, r, "decoding-base-64: "+err.Error())
			return
		}
		var env hmacEnvelope
		if err := json.Unmarshal(hmacValue, &env); err != nil {
			unauth(w, r, "unmarshal-envelope: "+err.Error())
			return
		}
		signedMessage := env.Msg
		var msg hmacMessage
		if err := json.Unmarshal(env.Msg, &msg); err != nil {
			unauth(w, r, "unmarshal-signed-message: "+err.Error())
			return
		}
		if msg.KeyID == "" {
			unauth(w, r, "empty-key-id")
			return
		}
		ctx := r.Context()
		privateKey, ok, err := keystore.GetPrivateKeyByID(ctx, msg.KeyID)
		if err != nil {
			unauth(w, r, "get-private-key: "+err.Error())
			return
		} else if !ok {
			unauth(w, r, "no-matching-key")
			return
		}

		h := hmac.New(sha256.New, privateKey)
		h.Write(signedMessage)
		sig := h.Sum(nil)

		// if signature mismatches
		if !hmac.Equal(env.Signature, sig) {
			unauth(w, r, "signature-mismatch")
			return
		}

		// if signature is too old
		signedAt := time.UnixMicro(msg.UnixMicro)
		now := time.Now()
		minSignedAt := now.Add(-maxClockSkew)
		maxSignedAt := now.Add(maxClockSkew)
		if signedAt.Before(minSignedAt) || signedAt.After(maxSignedAt) {
			unauth(w, r, "signature-too-old")
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
		hmacValue, err := GenerateHeader(keyID, privateKey)
		if err != nil {
			return nil, err
		}
		r.Header.Set(headerKey, hmacValue)

		return in.RoundTrip(r)
	})
}

type roundtripper func(*http.Request) (*http.Response, error)

func (fn roundtripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func GenerateHeader(keyID string, privateKey []byte) (string, error) {
	now := time.Now()
	msg := hmacMessage{
		KeyID:     keyID,
		UnixMicro: now.UnixMicro(),
	}
	signedMessage, err := json.Marshal(msg)
	if err != nil {
		return "", errors.Wrap(err, "marshaling HMAC message")
	}
	h := hmac.New(sha256.New, privateKey)
	h.Write(signedMessage)
	sig := h.Sum(nil)

	hmacValue, err := json.Marshal(hmacEnvelope{
		Msg:       signedMessage,
		Signature: sig,
	})
	if err != nil {
		return "", errors.Wrap(err, "marshaling HMAC value")
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hmacValue), nil
}
