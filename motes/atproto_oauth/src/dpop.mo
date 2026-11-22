// DPoP (RFC 9449) proof construction and nonce handling: pure, no IO.
//
// The proof is split around the signature, because the two runtimes that need
// it obtain a signature differently: the browser signs through WebCrypto's
// begin/poll interface (`WebKey.sign_begin`), which cannot be called from a
// pure function. So the caller builds `signing_input`, signs it by whatever
// means it has, and `assemble`s the result -- exactly the seam
// `plans/library-ideas/oauth-dpop-par.md` specifies.
//
// The claim shape is fixed by the atproto authorization server and was ported
// from todo-app's working implementation, including the one non-obvious rule:
// an absent optional claim is OMITTED, never `null`. A null `nonce` is
// rejected with `invalid_dpop_proof`.

use atproto_common::jws {Atp.signing_input, Atp.assemble, Atp.ath}
use atproto_common::jsonx {Atp.json_str, Atp.json_opt_str}

/// The DPoP proof's payload claims. `nonce` and `ath` are optional for
/// different reasons: `nonce` is absent until the server has issued one, and
/// `ath` is absent on any request that carries no access token (PAR, the
/// token exchange itself, `getSession` before a token exists).
pub struct Atp.DpopClaims {
    htm : String,
    htu : String,
    iat : I64,
    jti : String,
    iss : String,
    nonce : Option String := Option.none,
    ath : Option String := Option.none,
}

/// Every field is `Copy` (`String` is an immutable pointer), so the claims can
/// be read repeatedly while the payload is assembled.
pub instance Copy Atp.DpopClaims {
    def copy (c : Atp.DpopClaims) : Pair Atp.DpopClaims Atp.DpopClaims :=
        Pair.pair c c
}

/// The JOSE header. `jwk` is the public half, already serialised -- the
/// private scalar never reaches this module (on web it is a host-side handle).
pub def Atp.dpop_header (jwk_json : String) : String :=
    String.concat_list ["{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":",
        jwk_json, "}"]

/// The payload. Field order is fixed here (not because JWS requires it, but so
/// a test can assert the exact bytes the server will see).
pub def Atp.dpop_payload (c : Atp.DpopClaims) : String :=
    String.concat_list [
        "{\"iss\":", Atp.json_str c.iss,
        ",\"iat\":", I64.to_string c.iat,
        ",\"jti\":", Atp.json_str c.jti,
        ",\"htm\":", Atp.json_str c.htm,
        ",\"htu\":", Atp.json_str c.htu,
        Atp.json_opt_str "nonce" c.nonce,
        Atp.json_opt_str "ath" c.ath,
        "}",
    ]

/// `base64url(header) "." base64url(payload)`, the bytes to sign.
pub def Atp.dpop_signing_input (jwk_json : String) (c : Atp.DpopClaims) : String :=
    Atp.signing_input (Atp.dpop_header jwk_json) (Atp.dpop_payload c)

/// `htu` is the request URI WITHOUT query or fragment (RFC 9449 §4.2).
///
/// `String.byte_index_of` is the offset `slice` expects, and `?`/`#` are
/// single bytes, so this is a byte-accurate cut. A `?` inside a fragment is
/// not a query, which is why the lower of the two offsets wins.
pub def Atp.htu (url : String) : String :=
    let q : Option I64 := String.byte_index_of url "?" in
    let f : Option I64 := String.byte_index_of url "#" in
    match q {
        Option.some qi => match f {
            Option.some fi => if I64.lt fi qi then String.slice url 0i64 fi else String.slice url 0i64 qi,
            Option.none => String.slice url 0i64 qi,
        },
        Option.none => match f {
            Option.some fi => String.slice url 0i64 fi,
            Option.none => url,
        },
    }

/// `base64url(SHA-256(access_token))`, the `ath` claim that binds a proof to
/// the token it presents.
pub def Atp.dpop_ath (access_token : String) : String := Atp.ath access_token
