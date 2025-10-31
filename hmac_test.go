package hmachttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aybabtme/hmachttp"
	"github.com/stretchr/testify/require"
)

func TestAuthHMAC(t *testing.T) {
	keystore := &stubKeystore{keyID: "hello", key: []byte("world")}
	client := http.Client{
		Transport: hmachttp.RoundTripper(
			http.DefaultTransport,
			hmachttp.HeaderKey,
			keystore.keyID,
			keystore.key,
		),
	}
	wantCode := http.StatusOK
	reachedAuthedEndpoint := false
	srv := httptest.NewServer(hmachttp.Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reachedAuthedEndpoint = true
			gotKeyID := hmachttp.GetPrivateKeyID(r.Context())
			require.Equal(t, keystore.keyID, gotKeyID)
			w.WriteHeader(wantCode)
		}),
		keystore,
		hmachttp.HeaderKey,
		100*time.Millisecond,
		func(w http.ResponseWriter, r *http.Request, cause string) {
			t.Error("should have been authed")
			w.WriteHeader(http.StatusUnauthorized)
		},
	))
	defer srv.Close()

	res, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	require.Equal(t, wantCode, res.StatusCode)
	require.True(t, reachedAuthedEndpoint)
}

func TestUnauthHMAC_BadKey(t *testing.T) {
	keyID := "hello"
	client := http.Client{
		Transport: hmachttp.RoundTripper(
			http.DefaultTransport,
			hmachttp.HeaderKey,
			keyID,
			[]byte("le monde"),
		),
	}
	wantCode := http.StatusUnauthorized
	reachedUnauthedEndpoint := false
	keystore := &stubKeystore{keyID: keyID, key: []byte("world")}
	srv := httptest.NewServer(hmachttp.Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("shouldn't have been authed")
			w.WriteHeader(http.StatusOK)
		}),
		keystore,
		hmachttp.HeaderKey,
		100*time.Millisecond,
		func(w http.ResponseWriter, r *http.Request, cause string) {
			reachedUnauthedEndpoint = true
			w.WriteHeader(wantCode)
		},
	))
	defer srv.Close()

	res, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	require.Equal(t, wantCode, res.StatusCode)
	require.True(t, reachedUnauthedEndpoint)
}

func TestUnauthHMAC_BadKeyID(t *testing.T) {
	client := http.Client{
		Transport: hmachttp.RoundTripper(
			http.DefaultTransport,
			hmachttp.HeaderKey,
			"salut",
			[]byte("world"),
		),
	}
	wantCode := http.StatusUnauthorized
	reachedUnauthedEndpoint := false
	keystore := &stubKeystore{keyID: "hello", key: []byte("world")}
	srv := httptest.NewServer(hmachttp.Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("shouldn't have been authed")
			w.WriteHeader(http.StatusOK)
		}),
		keystore,
		hmachttp.HeaderKey,
		100*time.Millisecond,
		func(w http.ResponseWriter, r *http.Request, cause string) {
			reachedUnauthedEndpoint = true
			w.WriteHeader(wantCode)
		},
	))
	defer srv.Close()

	res, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	require.Equal(t, wantCode, res.StatusCode)
	require.True(t, reachedUnauthedEndpoint)
}

func TestUnauthHMAC_WrongHeader(t *testing.T) {
	client := http.Client{
		Transport: hmachttp.RoundTripper(
			http.DefaultTransport,
			hmachttp.HeaderKey+"junk",
			"hello",
			[]byte("world"),
		),
	}
	wantCode := http.StatusUnauthorized
	reachedUnauthedEndpoint := false
	keystore := &stubKeystore{keyID: "hello", key: []byte("world")}
	srv := httptest.NewServer(hmachttp.Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("shouldn't have been authed")
			w.WriteHeader(http.StatusOK)
		}),
		keystore,
		hmachttp.HeaderKey,
		100*time.Millisecond,
		func(w http.ResponseWriter, r *http.Request, cause string) {
			reachedUnauthedEndpoint = true
			w.WriteHeader(wantCode)
		},
	))
	defer srv.Close()

	res, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	require.Equal(t, wantCode, res.StatusCode)
	require.True(t, reachedUnauthedEndpoint)
}

func TestUnauthHMAC_NoSignature(t *testing.T) {
	client := http.Client{}
	wantCode := http.StatusUnauthorized
	reachedUnauthedEndpoint := false
	keystore := &stubKeystore{keyID: "hello", key: []byte("world")}
	srv := httptest.NewServer(hmachttp.Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("shouldn't have been authed")
			w.WriteHeader(http.StatusOK)
		}),
		keystore,
		hmachttp.HeaderKey,
		100*time.Millisecond,
		func(w http.ResponseWriter, r *http.Request, cause string) {
			reachedUnauthedEndpoint = true
			w.WriteHeader(wantCode)
		},
	))
	defer srv.Close()

	res, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	require.Equal(t, wantCode, res.StatusCode)
	require.True(t, reachedUnauthedEndpoint)
}

type stubKeystore struct {
	keyID string
	key   []byte
}

func (ks *stubKeystore) GetPrivateKeyByID(ctx context.Context, keyID string) ([]byte, bool, error) {
	if keyID != ks.keyID {
		return nil, false, nil
	}
	return ks.key, true, nil
}
