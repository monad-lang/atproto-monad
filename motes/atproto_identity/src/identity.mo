// Identity: turning a typed handle or DID into the PDS endpoint the flow
// talks to, and verifying a handle the way the spec requires.
//
// Pure. The two transports (well-known fetch, `resolveHandle` XRPC) and the
// DNS path are the driver's; everything here is validation and extraction, so
// every rule below is testable without a network.
//
// Two facts shape the web driver, and are recorded rather than hidden:
//
// - There is no DNS API in a browser, so the `_atproto.<handle>` TXT record is
//   read over DNS-over-HTTPS (Cloudflare's JSON API, which allows CORS). That
//   works the same for a handle on any PDS. Then `/.well-known/atproto-did`
//   (which CORS may block on a custom domain), and last bsky.social's
//   `com.atproto.identity.resolveHandle`.
// - A `did:web` document is fetched from the DID's own host, and `did:plc`
//   from plc.directory.

use json::json {Json}
use atproto_common::json_read {
    Atp.parse_json, Atp.str_field, Atp.opt_str_field, Atp.opt_array_field,
    Atp.opt_i64_field,
}

// ── Input normalisation ─────────────────────────────────────────────────

/// What the user typed, classified. A leading `@` is stripped (people paste
/// handles that way), and a bare domain is a handle.
///
/// The distinction matters because a DID is NOT resolved through DNS or the
/// well-known endpoint -- it names its own document -- so misclassifying one
/// as a handle would send the login to the wrong place.
pub type Atp.Identity {
    adk_id_did (did : String),
    adk_id_handle (handle : String),
    adk_id_empty,
}

/// Strip a leading `@` and surrounding whitespace.
def Atp.trim_handle (s : String) : String :=
    let t : String := String.trim s in
    if String.starts_with "@" t then String.drop 1i64 t else t

pub def Atp.classify (input : String) : Atp.Identity :=
    let t : String := Atp.trim_handle input in
    if String.is_empty t then Atp.Identity.adk_id_empty
    else if String.starts_with "did:" t then Atp.Identity.adk_id_did t
    // Handles are case-insensitive and normalised to lowercase (atproto
    // handle spec); a DID is case-sensitive, so only the handle is folded.
    else Atp.Identity.adk_id_handle (String.to_lowercase t)

/// A DID, checked structurally: `did:<method>:<identifier>`, with a non-empty
/// method and identifier and no whitespace. The method-specific rules are the
/// DID method's; this only rejects things that are not DIDs at all.
pub def Atp.is_did (s : String) : Bool :=
    if Bool.not (String.starts_with "did:" s) then false
    else match String.byte_index_of (String.drop 4i64 s) ":" {
        Option.none => false,
        Option.some i =>
            I64.gt i 0i64
                && I64.gt (String.length s) (I64.add i 5i64)
                && Bool.not (String.contains s " "),
    }

/// `did:web`'s document is at the DID's own host; everything else (in
/// practice `did:plc`) is looked up through plc.directory.
pub def Atp.is_did_web (did : String) : Bool := String.starts_with "did:web:" did

/// The URL a DID's document must be fetched from.
///
/// A `did:web` identifier encodes host and path with `:` as the separator, and
/// the host is percent-decoded for a port (`did:web:example.com%3A8443`).
/// `String.split` is the stdlib's; the rejoin is explicit because the first
/// segment is the host and the rest are path segments.
pub def Atp.did_document_url (did : String) : String :=
    if Atp.is_did_web did
    then
        let rest : String := String.drop 8i64 did in
        String.concat "https://" (String.concat (Atp.did_web_host rest) "/.well-known/did.json")
    else String.concat "https://plc.directory/" did

/// The host half of a `did:web` identifier, with `%3A` back to `:`.
def Atp.did_web_host (rest : String) : String :=
    let segments : List String := String.split rest ":" in
    match segments {
        List.empty => rest,
        List.cons host _ => Atp.pct_decode host,
    }

/// Percent-decode a `did:web` host.
///
/// The only escape a `did:web` identifier carries is `%3A` for the port colon,
/// but this decodes any `%XY` hex pair so a hand-written identifier with a
/// different (still valid) escape behaves the same. A malformed escape is
/// passed through literally rather than dropped, so nothing silently vanishes.
def Atp.hex_value (b : U8) : Option I64 :=
    let c : I64 := U8.to_i64 b in
    if I64.gt c 47i64 && I64.lt c 58i64 then Option.some (I64.sub c 48i64)
    else if I64.gt c 64i64 && I64.lt c 71i64 then Option.some (I64.sub c 55i64)
    else if I64.gt c 96i64 && I64.lt c 103i64 then Option.some (I64.sub c 87i64)
    else Option.none

#[terminating]
def Atp.pct_decode_go (bytes : List U8) (acc : String) : String :=
    match bytes {
        List.empty => acc,
        List.cons a rest =>
            if I64.beq (U8.to_i64 a) 37i64
            then match rest {
                List.cons h1 more => match more {
                    List.cons h2 tail => match Atp.hex_value h1 {
                        Option.none =>
                            Atp.pct_decode_go rest (String.concat acc "%"),
                        Option.some hi => match Atp.hex_value h2 {
                            Option.none =>
                                Atp.pct_decode_go rest (String.concat acc "%"),
                            Option.some lo =>
                                let code : I64 := I64.add (I64.mul hi 16i64) lo in
                                Atp.pct_decode_go tail
                                    (String.concat acc (String.from_list [U32.to_u8 (I64.to_u32 code)])),
                        },
                    },
                    List.empty => Atp.pct_decode_go rest (String.concat acc "%"),
                },
                List.empty => String.concat acc "%",
            }
            else Atp.pct_decode_go rest (String.concat acc (String.from_list [a])),
    }

pub def Atp.pct_decode (s : String) : String :=
    Atp.pct_decode_go (String.to_list s) ""

// ── The DID document ────────────────────────────────────────────────────

/// The PDS service endpoint and the handles the DID claims.
pub struct Atp.DidDocument {
    id : String,
    pds : Option String,
    also_known_as : List String,
}

/// Extract the service/alias fields.
///
/// `id` MUST equal the DID that was resolved: a document served for another
/// DID would otherwise let a host claim someone else's endpoint.
pub def Atp.did_document (did : String) (body : String)
    : Result String Atp.DidDocument :=
    match Atp.parse_json "DID document" body {
        Result.err e => Result.err e,
        Result.ok j => match Atp.str_field "DID document" "id" j {
            Result.err e => Result.err e,
            Result.ok id =>
                if Bool.not (String.beq id did)
                then Result.err (String.concat_list [
                    "DID document: `id` ", id, " is not the DID that was resolved (", did, ")"])
                else
                    let doc : Atp.DidDocument := {
                        id := id,
                        pds := Atp.pds_from_services j,
                        also_known_as := Atp.aliases j,
                    } in
                    Result.ok doc,
        },
    }

/// The `#atproto_pds` service's `serviceEndpoint`.
///
/// This is the only service the login needs; the document may list others
/// (a feed generator, a labeler), so the list is filtered rather than
/// indexed.
#[terminating]
def Atp.pds_service_go (services : List Json) : Option String :=
    match services {
        List.empty => Option.none,
        List.cons s rest => match Atp.opt_str_field "id" s {
            Option.some id =>
                if String.beq id "#atproto_pds"
                then Atp.opt_str_field "serviceEndpoint" s
                else Atp.pds_service_go rest,
            Option.none => Atp.pds_service_go rest,
        },
    }

def Atp.pds_from_services (j : Json) : Option String :=
    Atp.pds_service_go (Atp.opt_array_field "service" j)

/// The `alsoKnownAs` list, as strings.
def Atp.aliases (j : Json) : List String :=
    Atp.aliases_go (Atp.opt_array_field "alsoKnownAs" j)

#[terminating]
def Atp.aliases_go (xs : List Json) : List String :=
    match xs {
        List.empty => List.empty,
        List.cons x rest => match x {
            Json.str s => List.cons s (Atp.aliases_go rest),
            _ => Atp.aliases_go rest,
        },
    }

/// The bidirectional handle check: the document must claim `at://<handle>`.
///
/// Without this a hostile PDS could answer a handle lookup with a DID it does
/// not control, and the login would proceed as that account. The spec requires
/// the check in BOTH directions, and the other direction (DID -> handle) is
/// the `alsoKnownAs` list here.
pub def Atp.claims_handle (doc : Atp.DidDocument) (handle : String) : Bool :=
    let want : String := String.concat "at://" (String.to_lowercase handle) in
    Atp.claims_handle_go doc.also_known_as want

#[terminating]
def Atp.claims_handle_go (aliases : List String) (want : String) : Bool :=
    match aliases {
        List.empty => false,
        // `want` is already lowercase (`Atp.classify`); the document may not be.
        List.cons a rest =>
            String.beq (String.to_lowercase a) want || Atp.claims_handle_go rest want,
    }

// ── Handle syntax ───────────────────────────────────────────────────────

/// A handle: at least two dot-separated labels, each 1..63 characters of
/// `a-z 0-9 -` and not starting or ending with `-`, and the last label not all
/// digits (a bare IPv4 address is not a handle).
pub def Atp.is_handle (s : String) : Bool :=
    let t : String := Atp.trim_handle s in
    if I64.gt (String.length t) 253i64 then false
    else if I64.lt (String.length t) 3i64 then false
    else if Bool.not (String.contains t ".") then false
    else Atp.label_list_ok (String.split t ".")

def Atp.label_list_ok (labels : List String) : Bool :=
    // Fewer than two labels is not a handle (no dot).
    if I64.lt (List.length labels) 2i64 then false
    else
        // NOTE: `String.split` returns the labels IN ORDER, so the LAST label
        // is at the END of the list, not the head. The IP rule ("a bare IPv4
        // address is not a handle") tests that last label, which is why it is
        // walked to rather than pattern-matched off the head.
        Atp.labels_ok labels && Bool.not (Atp.all_digits (Atp.last_str labels))

/// The final element, or `""` for an empty list (callers guard against that).
#[terminating]
def Atp.last_str_go (xs : List String) (acc : String) : String :=
    match xs {
        List.empty => acc,
        List.cons x rest => Atp.last_str_go rest x,
    }

def Atp.last_str (xs : List String) : String := Atp.last_str_go xs ""

#[terminating]
def Atp.labels_ok (labels : List String) : Bool :=
    match labels {
        List.empty => true,
        List.cons l rest => Atp.label_ok l && Atp.labels_ok rest,
    }

/// 1..63 characters, every one of `a-z 0-9 -`, and neither the first nor the
/// last a hyphen. The hyphen rule is a spec requirement, not a nicety: a
/// leading hyphen would make the label look like a CLI flag to downstream
/// tooling, which is exactly the confusion the spec forbids.
def Atp.label_ok (l : String) : Bool :=
    let n : I64 := String.length l in
    if I64.lt n 1i64 || I64.gt n 63i64 then false
    else
        let bytes : List U8 := String.to_list l in
        Atp.not_hyphen (Atp.first_byte bytes)
            && Atp.not_hyphen (Atp.last_byte bytes)
            && Atp.label_chars_ok bytes

/// The character set, with NO early accept: each byte is checked and the rest
/// of the list still has to pass. (An `a || b || (c && rest)` shape would
/// return true on the first letter and skip the tail.)
#[terminating]
def Atp.label_chars_ok (bytes : List U8) : Bool :=
    match bytes {
        List.empty => true,
        List.cons b rest =>
            let c : I64 := U8.to_i64 b in
            ((I64.gt c 96i64 && I64.lt c 123i64)     // a-z
                    || (I64.gt c 47i64 && I64.lt c 58i64) // 0-9
                    || I64.beq c 45i64)                   // -
                && Atp.label_chars_ok rest,
    }

def Atp.first_byte (bytes : List U8) : Option U8 :=
    match bytes {
        List.empty => Option.none,
        List.cons b _ => Option.some b,
    }

#[terminating]
def Atp.last_byte_go (bytes : List U8) (acc : Option U8) : Option U8 :=
    match bytes {
        List.empty => acc,
        List.cons b rest => Atp.last_byte_go rest (Option.some b),
    }

def Atp.last_byte (bytes : List U8) : Option U8 := Atp.last_byte_go bytes Option.none

def Atp.not_hyphen (b : Option U8) : Bool :=
    match b {
        Option.none => false,
        Option.some x => Bool.not (I64.beq (U8.to_i64 x) 45i64),
    }

#[terminating]
def Atp.all_digits_go (bytes : List U8) : Bool :=
    match bytes {
        List.empty => true,
        List.cons b rest =>
            I64.gt (U8.to_i64 b) 47i64 && I64.lt (U8.to_i64 b) 58i64
                && Atp.all_digits_go rest,
    }

/// An all-digit label in the last position means the input was an IP address.
pub def Atp.all_digits (s : String) : Bool :=
    Bool.not (String.is_empty s) && Atp.all_digits_go (String.to_list s)

// ── resolveHandle ───────────────────────────────────────────────────────

/// The DID from a `com.atproto.identity.resolveHandle` response.
pub def Atp.resolve_handle_response (body : String) : Result String String :=
    match Atp.parse_json "resolveHandle response" body {
        Result.err e => Result.err e,
        Result.ok j => Atp.str_field "resolveHandle response" "did" j,
    }

/// The DID from a `/.well-known/atproto-did` response, which is a bare line of
/// text rather than JSON (and is whitespace-trimmed, because servers end the
/// body with a newline).
pub def Atp.well_known_did (body : String) : Result String String :=
    let t : String := String.trim body in
    if String.is_empty t then Result.err "the well-known endpoint returned nothing"
    else if Atp.is_did t then Result.ok t
    else Result.err (String.concat_list ["the well-known endpoint returned `", t,
        "`, which is not a DID"])

// ── DNS over HTTPS ──────────────────────────────────────────────────────

/// The DoH query for a handle's `_atproto` TXT record. The handle has passed
/// `Atp.is_handle` (only `a-z 0-9 - .`), so it needs no escaping.
pub def Atp.doh_txt_url (handle : String) : String :=
    String.concat_list ["https://cloudflare-dns.com/dns-query?name=_atproto.", handle, "&type=TXT"]

/// The `Accept` value that selects the JSON answer format.
pub def Atp.doh_accept : String := "application/dns-json"

/// A TXT record's data with its quoting removed. The JSON API returns each
/// character-string quoted (`"did=did:plc:x"`), and a long record as several
/// (`"did=did:pl" "c:x"`); dropping every quote and space rejoins them, which
/// is safe because a DID contains neither.
#[terminating]
def Atp.txt_unquote_go (bytes : List U8) (acc : List U8) : List U8 :=
    match bytes {
        List.empty => List.reverse acc,
        List.cons b rest =>
            let c : I64 := U8.to_i64 b in
            if I64.beq c 34i64 || I64.beq c 32i64
            then Atp.txt_unquote_go rest acc
            else Atp.txt_unquote_go rest (List.cons b acc),
    }

def Atp.txt_unquote (data : String) : String :=
    String.from_list (Atp.txt_unquote_go (String.to_list data) List.empty)

/// The `did=` values among the answer's TXT records (type 16). Other records
/// (a CNAME on the way, an unrelated TXT) are skipped.
#[terminating]
def Atp.doh_dids_go (answers : List Json) : List String :=
    match answers {
        List.empty => List.empty,
        List.cons a rest =>
            let is_txt : Bool :=
                match Atp.opt_i64_field "type" a {
                    Option.some t => I64.beq t 16i64,
                    Option.none => false,
                } in
            let value : String :=
                match Atp.opt_str_field "data" a {
                    Option.some d => Atp.txt_unquote d,
                    Option.none => "",
                } in
            if is_txt && String.starts_with "did=" value
            then List.cons (String.drop 4i64 value) (Atp.doh_dids_go rest)
            else Atp.doh_dids_go rest,
    }

/// The DID from a DoH TXT answer.
///
/// The spec requires exactly one `did=` record: several is a misconfigured
/// domain, and picking one would be a guess. No record (NXDOMAIN, or a name
/// with no `_atproto` TXT) is an error too, so the caller falls through to the
/// well-known endpoint.
pub def Atp.doh_txt_did (body : String) : Result String String :=
    match Atp.parse_json "DNS answer" body {
        Result.err e => Result.err e,
        Result.ok j =>
            let status : I64 :=
                match Atp.opt_i64_field "Status" j {
                    Option.some n => n,
                    Option.none => -1i64,
                } in
            if Bool.not (I64.beq status 0i64)
            then Result.err (String.concat "DNS answer: status " (I64.to_string status))
            else match Atp.doh_dids_go (Atp.opt_array_field "Answer" j) {
                List.empty => Result.err "DNS answer: no did= TXT record",
                List.cons did more => match more {
                    List.cons _ _ => Result.err "DNS answer: more than one did= TXT record",
                    List.empty =>
                        if Atp.is_did did then Result.ok did
                        else Result.err (String.concat_list [
                            "DNS answer: `", did, "` is not a DID"]),
                },
            },
    }
