// Reading an incoming JSON document: the shape every OAuth/atproto response
// arrives in (AS metadata, the PAR response, the token response, the DID
// document, `getSession`).
//
// Pure, and deliberately thin. There is no derive-based deserializer here: the
// `json` mote's own header records that its generic `Deserializer` instances
// do not resolve through an annotation-only call site, so a hand-written
// accessor per field is both simpler and the supported shape.
//
// Every accessor answers `Result String A` with a message a user can act on,
// and every miss names the field. A response that fails validation fails with
// a sentence, not a default.

use std::parse {Parse.i64}
use json::json {
    Json, Json.parse, Json.get_object, Json.get_str, Json.object_get,
    Json.get_num, Json.get_num_i64,
}

/// Parse, or a message naming the document.
pub def Atp.parse_json (what : String) (body : String) : Result String Json :=
    match Json.parse body {
        Result.ok j => Result.ok j,
        Result.err e =>
            Result.err (String.concat_list [what, ": not JSON (",
                Json.ParseError.to_string e, ")"]),
    }

/// The object's field, or an error naming it. `what` names the document so the
/// message reads "as metadata: no `authorization_endpoint`".
pub def Atp.field (what : String) (key : String) (j : Json) : Result String Json :=
    match Json.get_object j {
        Result.ok o => match Json.object_get key o {
            Option.some v => Result.ok v,
            Option.none => Result.err (String.concat_list [what, ": no `", key, "`"]),
        },
        Result.err e => Result.err (String.concat_list [what, ": ", e]),
    }

/// A required string field.
pub def Atp.str_field (what : String) (key : String) (j : Json)
    : Result String String :=
    match Atp.field what key j {
        Result.err e => Result.err e,
        Result.ok v => match Json.get_str v {
            Result.ok s => Result.ok s,
            Result.err _ =>
                Result.err (String.concat_list [what, ": `", key, "` is not a string"]),
        },
    }

/// An optional string field: `none` when absent OR when present but not a
/// string. Being lenient about the type is deliberate -- a server that sends
/// `"expires_in": null` should not fail a login.
pub def Atp.opt_str_field (key : String) (j : Json) : Option String :=
    match Json.get_object j {
        Result.err _ => Option.none,
        Result.ok o => match Json.object_get key o {
            Option.none => Option.none,
            Option.some v => match Json.get_str v {
                Result.ok s => Option.some s,
                Result.err _ => Option.none,
            },
        },
    }

/// An optional integer field. OAuth servers disagree on whether `expires_in`
/// is a number or a digit string, so both are accepted.
pub def Atp.opt_i64_field (key : String) (j : Json) : Option I64 :=
    match Json.get_object j {
        Result.err _ => Option.none,
        Result.ok o => match Json.object_get key o {
            Option.none => Option.none,
            Option.some v => match Json.get_num_i64 (Json.get_num v) {
                Result.ok n => Option.some n,
                Result.err _ => match Json.get_str v {
                    Result.ok s => match Parse.i64 s {
                        Option.some n => Option.some n,
                        Option.none => Option.none,
                    },
                    Result.err _ => Option.none,
                },
            },
        },
    }

/// An optional array field.
pub def Atp.opt_array_field (key : String) (j : Json) : List Json :=
    match Json.get_object j {
        Result.err _ => List.empty,
        Result.ok o => match Json.object_get key o {
            Option.none => List.empty,
            Option.some v => match v {
                Json.array a => a,
                _ => List.empty,
            },
        },
    }

/// Does the array contain this string?
#[terminating]
def Atp.array_has_str_go (xs : List Json) (want : String) : Bool :=
    match xs {
        List.empty => false,
        List.cons x rest => match Json.get_str x {
            Result.ok s => String.beq s want || Atp.array_has_str_go rest want,
            Result.err _ => Atp.array_has_str_go rest want,
        },
    }

pub def Atp.array_has_str (xs : List Json) (want : String) : Bool :=
    Atp.array_has_str_go xs want

/// The error envelope every XRPC/OAuth error response uses: `{error, message}`.
/// `error` is the machine-readable code a caller branches on.
pub struct Atp.ApiError {
    code : String,
    message : Option String,
}

pub def Atp.api_error (j : Json) : Option Atp.ApiError :=
    match Atp.opt_str_field "error" j {
        Option.none => Option.none,
        Option.some code =>
            Option.some { code := code, message := Atp.opt_str_field "message" j },
    }

pub def Atp.ApiError.describe (e : Atp.ApiError) : String :=
    match e.message {
        Option.none => e.code,
        Option.some m => String.concat_list [e.code, ": ", m],
    }
