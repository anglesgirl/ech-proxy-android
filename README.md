# ech-proxy-android

A reusable Go/gomobile ECH proxy library for Android apps.

## Non-negotiable routing rule

The caller must resolve a requested hostname through configured DoH and route it
through this proxy **only when every returned A/AAAA address belongs to
Cloudflare AS13335**. `IsAs13335(doh, host)` implements that check without a
system-DNS fallback.

The proxy repeats the same check before connecting. It then queries the target
hostname's HTTPS record through DoH and uses only that hostname's `ech=`
ConfigList. There is no unrelated, hard-coded fallback ECH configuration.

If any resolved address is not AS13335, a lookup fails, or no `ech=` record is
published, the proxy rejects the request. The Android app must leave that
request on its ordinary networking path.

## Configuration

Apps provide:

- ordered HTTPS DoH endpoints;
- optional remote TXT domain for distributing those public endpoints/settings;
- optional Cloudflare AS13335 edge-IP candidates.

Configured IP candidates are accepted only when they are AS13335 and are used
only after the target hostname itself has passed the AS13335 test.

## gomobile API

- `IsAs13335(doh, host) bool`
- `Start(listen, target, echB64, doh, ipList, cachePath, insecure) error`
- `Stop() error`
- `LastStatus() string`
- `FetchTxt(doh, name) (string, error)`

Requests sent to the loopback HTTP proxy supply the validated hostname through
`X-Ech-Target`. Invalid hosts are rejected.

## Build

```sh
gofmt -w .
go test ./...
gomobile init
gomobile bind -target=android/arm64 -androidapi 24 -o echproxy.aar .
```
