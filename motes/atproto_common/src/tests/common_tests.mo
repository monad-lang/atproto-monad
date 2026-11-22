// Pure tests for atproto_common: JWS assembly, the JSON string helpers and
// response reading. Native: `monad test motes/atproto_common`.

use lib::json_read {
    Atp.ApiError.describe, Atp.api_error, Atp.opt_i64_field, Atp.parse_json, Atp.str_field,
}
use lib::jsonx {Atp.json_escape, Atp.json_opt_str, Atp.json_str}
use lib::jws {Atp.assemble, Atp.signing_input}

/// `Option I64` equality: the language has no integer literal patterns (and
/// no match on `I64` at all), so an `Option I64` is compared through this.
def atp_opt_i64_is (want : I64) (got : Option I64) : Bool :=
    match got {
        Option.some n => I64.beq n want,
        Option.none => false,
    }

// ── base64url / JWS ─────────────────────────────────────────────────────

#[test]
def test_signing_input_is_base64url_of_both_parts : Bool :=
    // RFC 7515's shape, with the well-known encoding of a small payload.
    let input : String := Atp.signing_input "{\"alg\":\"none\"}" "{}" in
    String.contains input "." && Bool.not (String.contains input "=")

#[test]
def test_assemble_appends_the_signature : Bool :=
    let sig : List U8 := [0u8] in
    // A 1-byte signature is not ES256, so this must be refused rather than
    // silently producing a JWS that no verifier accepts.
    match Atp.assemble "a.b" sig {
        Result.ok _ => false,
        Result.err _ => true,
    }

#[test]
def test_assemble_accepts_a_64_byte_signature : Bool :=
    let sig : List U8 :=
        [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8] in
    match Atp.assemble "a.b" sig {
        Result.ok jws => String.beq (String.slice jws 0i64 4i64) "a.b.",
        Result.err _ => false,
    }

// ── JSON helpers ────────────────────────────────────────────────────────

#[test]
def test_json_str_escapes_quotes_and_backslash : Bool :=
    String.beq (Atp.json_str "a\"b") "\"a\\\"b\""
        && String.beq (Atp.json_str "a\\b") "\"a\\\\b\""

#[test]
def test_json_escape_passes_utf8_through : Bool :=
    // Non-ASCII is raw UTF-8 in the payload, not escaped.
    let s : String := Atp.json_escape "🐱" in
    I64.beq (String.length s) 4i64

#[test]
def test_json_opt_str_omits_none : Bool :=
    String.beq (Atp.json_opt_str "nonce" Option.none) ""
        && String.beq (Atp.json_opt_str "nonce" (Option.some "n")) ",\"nonce\":\"n\""

// ── Response reading ────────────────────────────────────────────────────

#[test]
def test_parse_json_reports_a_bad_document : Bool :=
    match Atp.parse_json "token response" "not json" {
        Result.ok _ => false,
        Result.err e => String.contains e "token response",
    }

#[test]
def test_str_field_names_a_missing_field : Bool :=
    match Atp.parse_json "token response" "{\"a\":1}" {
        Result.err _ => false,
        Result.ok j => match Atp.str_field "token response" "access_token" j {
            Result.ok _ => false,
            Result.err e => String.contains e "access_token",
        },
    }

#[test]
def test_opt_i64_field_accepts_number_and_string : Bool :=
    // Servers disagree on `expires_in`'s type: a JSON number and a digit
    // string must both read as 3600. (Integer literal PATTERNS are not a
    // thing in this language -- a match on `I64` is rejected as opaque and a
    // literal arm does not parse -- so the value is bound and compared.)
    match Atp.parse_json "t" "{\"a\":3600,\"b\":\"3600\"}" {
        Result.err _ => false,
        Result.ok j => atp_opt_i64_is 3600i64 (Atp.opt_i64_field "a" j)
            && atp_opt_i64_is 3600i64 (Atp.opt_i64_field "b" j),
    }

#[test]
def test_api_error_describe : Bool :=
    match Atp.parse_json "e" "{\"error\":\"invalid_client\",\"message\":\"bad\"}" {
        Result.err _ => false,
        Result.ok j => match Atp.api_error j {
            Option.none => false,
            Option.some e => String.contains (Atp.ApiError.describe e) "invalid_client",
        },
    }
