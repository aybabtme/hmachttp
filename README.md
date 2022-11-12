# hmachttp

This package provides HMAC authentication for HTTP client and servers. The authentication only verifies that a request was sent with a header containing a timestamp and a key ID signed by a private key matching the key ID, for a given allowed clock skew. The content of the HTTP body isn't signed itself.

This method of authenticating requests is subject to replay attacks for the duration of the clock time skew. Any HTTP request sent with the same header will be seen as authenticated for the duration of the clock skew, even if the HTTP body is entirely different.

There are probably many other security problems with this package. Don't use it.

I repeat: **the only thing that is signed in all this is a timestamp and key ID!!!** and it's probably not even doing this properly.

# audit

This package wasn't audited and is most likely not safe to use. I'm not a security or cryptography expert.

# usage

If you decide to use this, first make sure it's over HTTPS (TLS/SSL). The API looks like:

Client side:

```go
client := http.Client{
    Transport: hmachttp.RoundTripper(
        http.DefaultTransport,
        hmachttp.HeaderKey,
        "admin-user",
        []byte("super-secret-key"),
    ),
}

client.Do(...) // any request of your choice
```

Server side

```go
var privateHandler http.Handler // your private handler routes

handler := hmachttp.Handler(
    privateHandler,
    keystore,
    hmachttp.HeaderKey,
    100*time.Millisecond,
    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusUnauthorized)
    }),
))
srv := http.Server{Handler: handler} // whatever server setup you use
```

The `keystore` allows you to support multiple keys, identified by an ID of your choice.
