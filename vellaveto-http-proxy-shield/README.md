# vellaveto-http-proxy-shield

Consumer shield HTTP proxy layer for [Vellaveto](https://vellaveto.online).

## Overview

Privacy-enhancing transport layer for the consumer shield:

- **Header stripping** — withholds correlation and tracing headers from upstream
  requests. **Integrated** into `vellaveto-http-proxy` behind
  `shield.strip_privacy_headers`. `PRIVACY_STRIP_HEADERS` is the authoritative
  list; the proxy consults it rather than restating header names.
- **Traffic padding** — fixed-size buckets to blunt content-length
  fingerprinting. **Integrated, opt-in per client** — see the wire format below.

## Traffic padding: wire format and negotiation

`pad_content` produces a framed message:

```
[4-byte little-endian content length][content][zero padding to bucket size]
```

The receiver strips it with `unpad_content`. A padded body is therefore **not
valid JSON**, so it can only be sent to a client that knows to unframe it.
Padding is consequently negotiated per request, and off unless both sides agree:

| | |
|---|---|
| **Client opts in** | sends `X-Vellaveto-Padding: v1` on the request |
| **Proxy confirms** | responds with `X-Vellaveto-Padding-Applied: v1` and a padded body |
| **Operator enables** | `shield.traffic_padding = true` |

Both the operator setting and the client header are required. A client that does
not send the header — which is every standard MCP client — gets the unpadded body
byte for byte, unchanged. Unknown framing versions are refused rather than
guessed at, since sending v1 bytes to a client expecting something else would
corrupt its response just as surely as padding an unaware one.

Bodies larger than the biggest bucket (128 KB) are sent unpadded: framing them
would break the client for no gain, as the size already falls outside every
bucket.

### What padding is worth

Against a network observer watching TLS ciphertext lengths, bucketing removes the
fine-grained size signal that distinguishes one request from another. It does not
hide timing, request counts, or destination, and HTTP/2 framing and transport
compression already obscure part of the same signal. It is one input to a
fingerprint, not a cloak.

### Honest note on adoption

No shipped client negotiates this yet, and standard MCP clients never will. What
exists is a documented, opt-in protocol extension with a round-trip test as its
only in-tree consumer. That is deliberate — the alternative was leaving
`shield.traffic_padding` as a config key that silently did nothing — but it means
enabling the setting changes nothing until a client is built that asks for it.

## Usage

```toml
[dependencies]
vellaveto-http-proxy-shield = "7"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
