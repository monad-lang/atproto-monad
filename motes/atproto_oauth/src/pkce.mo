// PKCE (RFC 7636), S256 only, and the form/query encoders the OAuth flow
// needs. Pure: the verifier's entropy is a caller-supplied string, so this
// module is native-testable and the driver owns the CSPRNG call.
//
// `plain` is deliberately absent -- OAuth 2.1 requires S256, and a `plain`
// branch would only exist to be misconfigured into. `motes/oauth`'s
// `pkce.mo` makes the same choice, but cannot be reused here: it imports
// `moose::form` and `crypto::random` (OpenSSL), so it has no wasm target.

use atproto_common::jws {Atp.s256}

pub def Atp.pkce_method : String := "S256"

/// `base64url(SHA-256(verifier))`. Verified against RFC 7636 Appendix B in the
/// tests below.
pub def Atp.pkce_challenge (verifier : String) : String := Atp.s256 verifier

/// RFC 7636 §4.1: 43..128 characters, all in the unreserved set
/// `A-Z a-z 0-9 - . _ ~`. A malicious or truncated stored verifier fails here
/// rather than at the token endpoint.
#[terminating]
def Atp.pkce_valid_go (bytes : List U8) (bounded : Bool) (ok : Bool) : Bool :=
    match bytes {
        List.empty => ok && bounded,
        List.cons b rest =>
            let c : I64 := U8.to_i64 b in
            let in_set : Bool :=
                (I64.gt c 64i64 && I64.lt c 91i64)        // A-Z
                    || (I64.gt c 96i64 && I64.lt c 123i64) // a-z
                    || (I64.gt c 47i64 && I64.lt c 58i64)  // 0-9
                    || I64.beq c 45i64 || I64.beq c 46i64  // - .
                    || I64.beq c 95i64 || I64.beq c 126i64 in // _ ~
            Atp.pkce_valid_go rest (I64.gt c 0i64) (ok && in_set),
    }

pub def Atp.pkce_valid_verifier (verifier : String) : Bool :=
    let n : I64 := String.length verifier in
    I64.lt 42i64 n && I64.lt n 129i64
        && Atp.pkce_valid_go (String.to_list verifier) true true

// ── Form and query encoding ─────────────────────────────────────────────
//
// `application/x-www-form-urlencoded` (RFC 6749 §4.1.3 / RFC 9126): everything
// outside the unreserved set is percent-encoded, and a space is `+`. This is
// stricter than `encodeURIComponent` on one point and looser on another, so it
// is written out rather than approximated.

def Atp.unreserved (c : I64) : Bool :=
    (I64.gt c 64i64 && I64.lt c 91i64)        // A-Z
        || (I64.gt c 96i64 && I64.lt c 123i64) // a-z
        || (I64.gt c 47i64 && I64.lt c 58i64)  // 0-9
        || I64.beq c 45i64 || I64.beq c 46i64 || I64.beq c 95i64 || I64.beq c 126i64

def Atp.hex_digit (n : I64) : String :=
    if I64.lt n 10i64
    then I64.to_string n
    else if I64.beq n 10i64 then "A"
    else if I64.beq n 11i64 then "B"
    else if I64.beq n 12i64 then "C"
    else if I64.beq n 13i64 then "D"
    else if I64.beq n 14i64 then "E"
    else "F"

/// One percent-escape: `%XY`, uppercase hex, from a byte value.
def Atp.pct (c : I64) : String :=
    String.concat "%" (String.concat (Atp.hex_digit (I64.div c 16i64))
        (Atp.hex_digit (I64.mod c 16i64)))

#[terminating]
def Atp.url_encode_go (bytes : List U8) (acc : String) : String :=
    match bytes {
        List.empty => acc,
        List.cons b rest =>
            let c : I64 := U8.to_i64 b in
            let piece : String :=
                if I64.beq c 32i64 then "+"
                else if Atp.unreserved c then String.from_list [b]
                else Atp.pct c in
            Atp.url_encode_go rest (String.concat acc piece),
    }

pub def Atp.url_encode (s : String) : String :=
    Atp.url_encode_go (String.to_list s) ""

/// `name=value`, both encoded.
pub def Atp.form_pair (name : String) (value : String) : String :=
    String.concat_list [Atp.url_encode name, "=", Atp.url_encode value]

/// A `&`-joined form body from ordered pairs. Order is preserved (it is the
/// caller's list), which matters only for reproducible test vectors.
#[terminating]
def Atp.form_body_go (ps : List (Pair String String)) (acc : String) : String :=
    match ps {
        List.empty => acc,
        List.cons p rest =>
            match p {
                Pair.pair k v =>
                    let piece : String := Atp.form_pair k v in
                    let next : String :=
                        if String.is_empty acc then piece
                        else String.concat acc (String.concat "&" piece) in
                    Atp.form_body_go rest next,
            },
    }

pub def Atp.form_body (ps : List (Pair String String)) : String :=
    Atp.form_body_go ps ""
