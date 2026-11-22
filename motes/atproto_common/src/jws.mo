// The pure atproto/OAuth core: no browser types, no IO, so `monad test` can
// build and run all of it natively (the same discipline as `src/game.mo`).
//
// This mirrors what `plans/library-ideas/atproto.md` calls the target-neutral
// core. It is NOT the planned `motes/atproto`: that mote does not exist yet,
// and this app needs the flow now. The shape is deliberately the same, so the
// logic can be lifted into the mote when it lands.
//
// Everything here is a pure function over strings and bytes. The two impure
// halves -- signing (WebCrypto) and transport (Fetch) -- are split out at the
// `signing_input`/`assemble` seam, because on web both are asynchronous
// begin/poll operations (`web-wasm-crypto.md`).

use std::base64 {B64Url.encode, B64Url.decode}
use std::sha256 {Sha256.hash_bytes}

/// A JWS is `base64url(header) "." base64url(payload) "." base64url(sig)`,
/// with no padding anywhere (RFC 7515 §3 / RFC 4648 §5).
///
/// The split matters for DPoP specifically: the ES256 signature must be
/// produced over `signing_input` while the signature itself cannot be known
/// until after that, so the caller signs between the two steps.
pub def Atp.signing_input (header : String) (payload : String) : String :=
    String.concat_list [B64Url.encode (String.to_list header), ".",
        B64Url.encode (String.to_list payload)]

/// Append the raw 64-byte `r ‖ s` ES256 signature.
///
/// WebCrypto's ECDSA output is already IEEE P1363 `r ‖ s`, which IS the JWS
/// form, so no DER conversion is needed on this path.
pub def Atp.assemble (input : String) (sig_raw : List U8) : Result String String :=
    if I64.beq (List.length sig_raw) 64i64
    then Result.ok (String.concat_list [input, ".", B64Url.encode sig_raw])
    else Result.err "atproto: signature is not 64 bytes (ES256 r||s)"

/// `base64url(SHA-256(token))`, the DPoP `ath` claim (RFC 9449 §4.2).
///
/// `std::sha256` is pure Monad, so this needs no crypto host and works in
/// native tests.
pub def Atp.ath (access_token : String) : String :=
    B64Url.encode (Sha256.hash_bytes (String.to_list access_token))

/// The SHA-256 PKCE challenge helper the pure tests can assert on.
pub def Atp.s256 (verifier : String) : String :=
    B64Url.encode (Sha256.hash_bytes (String.to_list verifier))
