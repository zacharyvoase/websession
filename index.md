---
layout: default.njk
---

# WebSession

## A Protocol for Secure Browser Sessions {.subtitle}

by Zachary Voase &lt;<a href="mailto:zack@meat.io">zack@meat.io</a>&gt;
{#author}

Last update: <time datetime="2023-06-14">2023-06-14</time>
{#date}

This is a work in progress, based on my talk at Identiverse 2023. It's intended
to be a starting point for discussion, not a complete or unambiguous spec.
Please get in touch if you have questions, comments, or suggestions; I'll
update this page once I find a good locus for further discussion.
{.note}

WebSession is a proposed replacement for cookies when establishing and
maintaining user sessions in a Web browser. Its goals are to be more secure,
offer more user control, and protect privacy better than cookies, while
remaining fast and easy to implement.

WebSession is separate from authentication protocols like usernames and
passwords, [WebAuthn][], and [OpenID Connect][]. Those *prove* who you are;
WebSession is a way for the server to *remember* who you are across multiple
HTTP requests. WebSession also allows for existing unauthenticated use cases
supported by cookies, where you may not have a user account (or want to log
in), but still need to maintain state across requests. Examples include
anonymous shopping carts and 'guest' checkout, personalization without creating
a user account, A/B testing, analytics, and more.

### What's wrong with cookies?

#### Security

Currently when you log into a website, the server generates a unique session
ID and stores it in your browser as a **cookie**. On every subsequent request,
your browser sends this cookie to the server to prove that it's you making the
request. This cookie, whether a [JWT][] or opaque session identifier, is called
a **bearer token**, because it grants the holder the right to skip a full
authentication ceremony on every request, and no additional 'proof' is required
other than knowledge of the token.

If someone steals this cookie, they can impersonate you. Stolen cookie attacks
have happened in the past [with disastrous effect][cookie-theft-1], and there
is [a thriving trade in stolen cookies on the dark web][cookie-theft-2].

Cookies have a large surface area of attack, and little room for error. Secure
use of cookies for tracking a browser session includes, but is not limited to:

* Setting the `Secure` flag so they are only sent over secure connections;
* Setting the `SameSite` flag to prevent <abbr title="Cross-Site Request
  Forgery">CSRF</abbr> attacks;
* Setting the `HttpOnly` flag to stop them from being read in JavaScript and/or
  stolen in <abbr title="Cross-Site Scripting">XSS</abbr> attacks;
* Setting a reasonable expiry, and enforcing it on the server;
* Correctly scoping the domain and path so that only the endpoints that are
  authorized to use the session receive the session cookie;
* Ensuring your server does not have any application code that may
  inadvertently reflect a Cookie header back to a client (which would break the
  protection given by `HttpOnly`);
* Ensuring cookies are not inadvertently logged or stored unsafely.

Even with all of these, a compromised client, an unsecured application log, or
an eavesdropper on the connection after TLS termination could result in a
cookie being stolen. It is difficult to distinguish an attacker using a stolen
cookie from the legitimate user to whom it was originally issued.

#### Privacy, User Control, and User Experience

Cookies were invented in 1994, and started out as a generic
mechanism for persistent key-value state which were quickly
adopted to provide authentication too. However as an ad hoc K/V
store, there is nothing reliably distinguishing 'essential'
(i.e. authentication) cookies from analytics, tracking,
advertising, or preference cookies. As a result of increasingly
strict privacy laws across the world, users are now beset with
[cookie banners][] across the Web, with no standard way to
either consent to or reject non-essential cookies.

We need a protocol that is dedicated to session maintenance, that gives control
back to the user either through prior browser configuration or a
consent-on-first-visit model. Browsers could use system-native, accessible UIs
that don't interrupt content loading or page layout.

It's also very common that a website wants credentials to be cleared when the
user is inactive for a certain amount of time. This is important for sensitive
applications such as banking and healthcare. Currently there's no way to
enforce that a cookie is cleared on device lock or user inactivity,
*especially* because security requires that such cookies not be visible to
JavaScript. A native session management solution should be able to request that
the browser clear a session in the case of device lock, the user navigating
away, etc.

### How would WebSession solve these problems?

#### Security

WebSession does not rely on bearer tokens. Instead, the browser and server
agree on a shared secret at the beginning of the session, using [Diffie-Hellman
key exchange (DHKE)][dh]. This secret is never sent over the network, and it
cannot be computed by an eavesdropper, even with full observation of requests
and responses, thanks to the security guarantees of DHKE.

For every request, the browser generates a unique string (aka a 'nonce'), which
it *signs* with the shared secret. The nonce and signature are sent with the
request, and the server can then verify that signature, while also checking to
make sure that nonce has not been used before.

WebSession does not treat security as optional, so there are no flags like
`Secure`, `SameSite`, or `HttpOnly` to forget. An endpoint that inadvertently
reflects headers would be useless if the server is tracking nonces properly. A
server-side expiry mechanism is still needed, and domain/path scoping may be
necessary. Even so, if a 'bad' endpoint receives a valid WebSession header, it
is limited to forging a single request, rather than having a reusable session
cookie that may allow an unbounded number of impersonated requests.

#### Privacy

WebSession tokens are opaque identifiers, unlinkable back to real-world user
identities. Without extra work, they only identify the browser instance
between requests, not the user.

Because WebSession is dedicated to session maintenance and nothing else, a
client could theoretically reject *all* cookies on any supporting site, ideally
skipping the jarring cookie banner experience.

Furthermore, the browser-native integration could include things like a request
to clear a session on inactivity, device lock, navigation away from the page,
etc. This is best done via a browser-integrated, purposeful protocol for
session management rather than ad hoc JavaScript on every site.

### What else could WebSession provide?

Typically a browser session is identified with a particular human user, and one
of the most exciting new standards on the web today is [WebAuthn][], which
allows for cryptographically secure user verification. In theory, WebSession
could be extended with options asking the client to use the WebSession derived
secret as the challenge for a WebAuthn assertion. This would provide strong
proof to the server that the session has been established by the authenticated
user, thwarting even active MITM attacks.

## Protocol Description

### 1) Initial Request

The browser makes a standard GET request to the website. In this case we'll
assume the URL is `https://example.com/`.

### 2) Server Challenge

The server generates and stores an ephemeral keypair for DHKE, hereby referred
to as `Spub` and `Spriv`. This will most likely be a point on the NIST P-256 or
X25519 elliptic curves.

The server then responds to the initial request with a `WWW-Authenticate`
header with the auth scheme `WebSession`, followed by a **challenge** as
unpadded [base64url][]-encoded [CBOR][]. These parameters include:

* `alg`: an indication of the DHKE algorithm and other parameters.
  For example:
  * `P256`, `P384`, `P521` etc.: ECDH over the corresponding NIST prime curves;
  * `X25519`, `X448`: ECDH over Curve25519 and Curve448.
  At a minimum, implementations should support `P256` and `X25519`, since these
  are compact, widely available, and provide 128 bits of security.
* `exp`: the session expiry, as a UNIX timestamp (seconds since the epoch in
  UTC);
* `h`: which hashing algorithm to use for signatures. Must be one of `SHA-256`,
  `SHA-384`, or `SHA-512`.
* `s`: the encoding of `Spub`, specific to `alg`. Weierstrass curves like
  the NIST prime curves should use the compressed point format; Curve25519 and
  Curve448 points are usually only expressed in compressed form anyway. Since
  we're using CBOR, these can be included in the object as a raw byte string.
* Any as-yet undefined options.

#### Example

The following challenge:

```json
{
    "alg": "X25519",
    "exp": 1685370900, // 2023-05-29T14:35:00Z
    "h": "SHA-256",
    "s": 0x52e1a650620c196f029930d8be54efac7cb4a47ffcc04b0c7799b4bee5f028c8 // binary
}
```

Would result in this HTTP response:

```text
200 OK
WWW-Authenticate: WebSession pGNhbGdmWDI1NTE5Y2V4cBpkdLgUYWhnU0hBLTI1NmFzWCBS4aZQYgwZbwKZMNi-VO-sfLSkf_zASwx3mbS-5fAoyA
```

### 3) Client Response

At this point the browser can decide whether to initiate a session or not,
either based on interactive user feedback, previous behavior, or prior
configuration. If no session is desired, the client simply doesn't respond to
the challenge, and continues making requests as usual. The rest of this
document assumes a session is desired.

* The client generates its own keypair, scoped to the origin (hereafter `Cpub`
  and `Cpriv`);
* It derives a shared secret, using DH between `Spub` and `Cpriv`, and then
  applying [HKDF][] on the resulting bytes (with the hashing algorithm `h`
  requested by the server earlier);
* It chooses a 32-byte secure random nonce;
* It builds a token **body** as a CBOR object containing:
  * `s`: the server public key;
  * `c`: the client public key;
  * `o`: the origin;
  * `n`: the nonce.
* It produces a **signature** by [HMAC][]ing the token body using the shared secret
  as the key;
* Finally, it constructs an ASCII token by unpadded base64url-encoding the
  signature and body and then concatenating them with a '.' character.

In Python pseudocode:

```python
c_pub, c_priv = gen_keypair()
shared_secret = hkdf(dh(c_priv, s_pub))
nonce = secrets.token_bytes(32)
body = cbor.encode({
    's': s_pub,
    'c': c_pub,
    'o': 'https://example.com',
    'n': nonce
})
signature = hmac(shared_secret, body)
return base64url(signature) + '.' + base64url(body)
```

This token is then included in the next client request in the `Authorization`
header, with an auth scheme of `WebSession`. For example:

```text
GET / HTTP/1.1
Authorization: WebSession 8qbsNWTO9bWTSSKPy6anrZ0wFS_OCLpBU6z8sMCYIXc.pGFjWCECti-THEz2E5V2GVho6BlS4hYCc2iSIQM3OAigEOIPqrRhc1ghAtuVyC-gkXNvLDiI3EX3vsoKr3LouSNokIwh2kbEr636YW9zaHR0cHM6Ly9leGFtcGxlLmNvbWFuWCCOCJPacqTehDoux9VHjkZW_1r9lqV2gWIjK81uhqCOqg
```

### 4) Server Validation

The server validates an incoming request by:

* Splitting the token signature and body at the '.' character and base64url-decoding them;
* CBOR-parsing the body to extract `Cpub`, `Spub`, `origin` and `nonce`;
* Looking up the corresponding `Spriv` for the session;
* Deriving the same shared secret, using `Cpub` and `Spriv` and HKDF;
  * The shared secret may be cached for subsequent requests against the same
    `Spub` and `Spriv`; if it is not cached, the server MUST validate that the
    included `Cpub` does not change across requests.
* Validating that the nonce has not been used already for this session.
  **Important:** at this point, the nonce should be added to the 'seen' set,
  because nonces should be invalidated whether the signature validation passes
  or fails. Failure to do so can allow attackers to brute-force a valid
  signature for a single nonce.
* (Recommended) validating the origin is as expected;
* Computing the HMAC over the provided token body and checking the signature.
  **Note**: it's important to use a constant-time comparison function for the
  signature checking. Many crypto libraries have a 'verify' function which will
  do this, rather than computing the signature as a string and checking for
  equality.

In Python pseudocode:

```python
sig_b64, body_b64 = token.split('.')
sig_bytes, body_bytes = base64url_decode(sig_b64), base64url_decode(body_b64)
body = CBOR.decode(body_bytes)
s_pub, c_pub, origin, nonce = body['s'], body['c'], body['o'], body['n']
check(body['o'] == 'https://example.com')  # Recommended
shared_secret = lookup_secret(s_pub)
if not shared_secret:
    s_priv = lookup_s_priv(s_pub)
    shared_secret = hkdf(dh(s_priv, c_pub))
    cache_shared_secret(s_pub, shared_secret)
check_nonce_reuse(s_pub, nonce)  # nonces can safely be scoped to sessions
mark_nonce_as_seen(s_pub, nonce)
expected_signature = hmac(shared_secret, body_bytes)
# Return True if successful, False if failed
return constant_time_equal(sig_bytes, expected_signature)
```

In the case of failure, the server should return a 403 Forbidden (which is
often used for bad `Authorization` header values).

### TBD

* Option to request a WebAuthn assertion if discoverable credentials are present
* Option to request expiry on device lock/user inactivity.

[base64url]: https://datatracker.ietf.org/doc/html/rfc4648#section-5
[cbor]: https://cbor.io/
[cookie banners]: https://cookieinformation.com/cookie-banner/
[cookie-theft-1]: https://www.vice.com/en/article/7kvkqb/how-ea-games-was-hacked-slack
[cookie-theft-2]: https://www.reuters.com/world/uk/operation-cookie-monster-international-police-action-seizes-dark-web-market-2023-04-05/
[dh]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
[hkdf]: https://en.wikipedia.org/wiki/HKDF
[hmac]: https://en.wikipedia.org/wiki/HMAC
[jwt]: https://jwt.io/
[openid connect]: https://openid.net/connect/
[webauthn]: https://webauthn.guide/
