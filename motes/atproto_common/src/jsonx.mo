// Small pure JSON helpers the atproto core needs and the stdlib does not
// provide: a string escaper, and the "omit, never null" optional-claim rule.
//
// No IO and no browser types, so this is native-testable.
//
// Scanning helpers were deliberately NOT written here: `String.byte_index_of`
// (the offset `slice`/`drop` expect) and `String.starts_with` already exist,
// and a second implementation would only be a thing to get wrong.

// ── JSON strings ────────────────────────────────────────────────────────

/// A JSON string literal for the ASCII/UTF-8 text we interpolate.
///
/// Escapes the two characters that would break out of the literal (`"` and
/// `\`) plus the C0 controls, so a hostile issuer, nonce or handle cannot
/// inject claims into a DPoP payload. Non-ASCII text is passed through: the
/// payload is a Monad `String` of UTF-8 bytes and JSON accepts raw UTF-8, so
/// escaping it would be wrong, not merely unnecessary.
#[terminating]
def Atp.json_escape_go (bytes : List U8) (acc : String) : String :=
    match bytes {
        List.empty => acc,
        List.cons b rest =>
            let code : I64 := U8.to_i64 b in
            let piece : String :=
                if I64.beq code 34i64 then "\\\""
                else if I64.beq code 92i64 then "\\\\"
                else if I64.beq code 8i64 then "\\b"
                else if I64.beq code 12i64 then "\\f"
                else if I64.beq code 10i64 then "\\n"
                else if I64.beq code 13i64 then "\\r"
                else if I64.beq code 9i64 then "\\t"
                else if I64.lt code 32i64 then "\\u0000"
                else String.from_list [b] in
            Atp.json_escape_go rest (String.concat acc piece),
    }

pub def Atp.json_escape (s : String) : String :=
    Atp.json_escape_go (String.to_list s) ""

/// `"<escaped>"`, including the quotes.
pub def Atp.json_str (s : String) : String :=
    String.concat "\"" (String.concat (Atp.json_escape s) "\"")

/// An optional claim: the WHOLE `,"name":value` fragment, or `""` when the
/// claim is absent.
///
/// This is the "absent means omitted, never null" rule in one place. It is
/// load-bearing: the atproto authorization server rejects a null `nonce` with
/// `invalid_dpop_proof` ("Invalid DPoP \"nonce\" type").
pub def Atp.json_opt_str (name : String) (v : Option String) : String :=
    match v {
        Option.none => "",
        Option.some s => String.concat_list [",\"", name, "\":", Atp.json_str s],
    }
