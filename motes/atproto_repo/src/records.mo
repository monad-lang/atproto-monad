// com.atproto.repo records: the request URLs and bodies for `getRecord` and
// `putRecord`, the `swapRecord` compare-and-swap, the XRPC error classifiers,
// and the RFC 3339 timestamp records conventionally carry.
//
// PURE, and schema-free: a record is a `Json` value the app encodes and
// decodes. A fetched record is UNTRUSTED input (anyone can write anything into
// their own repo), so decoding it, and deciding what a garbled one means, is
// the app's job.

use json::json {Json, Json.to_string, Json.make_object_pairs, Json.make_str}
use atproto_common::json_read {Atp.parse_json, Atp.field, Atp.opt_str_field}

/// A `getRecord` answer: the record's value and its CID (for `swapRecord`).
///
/// `value` is the raw record, still UNTRUSTED: anyone can write anything into
/// their own repo, so the app decodes it leniently.
pub struct Atp.Fetched {
    value : Json,
    cid : String,
}

/// Parse a `com.atproto.repo.getRecord` response body. Only the envelope is
/// required (`value` must be present and `cid` a string); decoding the value
/// is the app's.
pub def Atp.fetched_of_body (body : String) : Result String Atp.Fetched :=
    match Atp.parse_json "getRecord response" body {
        Result.err e => Result.err e,
        Result.ok j => match Atp.field "getRecord response" "value" j {
            Result.err e => Result.err e,
            Result.ok v => match Atp.opt_str_field "cid" j {
                Option.none => Result.err "getRecord response: no `cid`",
                Option.some cid =>
                    let f : Atp.Fetched := { value := v, cid := cid } in
                    Result.ok f,
            },
        },
    }

/// Is a failed `getRecord` the ordinary "no record yet"? The PDS answers
/// 400 with `"error":"RecordNotFound"`.
pub def Atp.is_record_not_found (status : I64) (body : String) : Bool :=
    I64.beq status 400i64 && String.contains body "RecordNotFound"

/// Is a failed `putRecord` a lost compare-and-swap? (`InvalidSwap`.)
pub def Atp.is_invalid_swap (status : I64) (body : String) : Bool :=
    I64.beq status 400i64 && String.contains body "InvalidSwap"

/// The `putRecord` request body. `swap` is the CID the merge was based on;
/// with none (no record seen yet) the field is omitted, which some PDS
/// implementations handle better than an explicit null.
pub def Atp.put_record_body (did : String) (collection : String) (rkey : String)
    (record : Json) (swap : Option String) : String :=
    let base : List (Pair String Json) := [
        Pair.pair "repo" (Json.make_str did),
        Pair.pair "collection" (Json.make_str collection),
        Pair.pair "rkey" (Json.make_str rkey),
        Pair.pair "record" record,
    ] in
    let fields : List (Pair String Json) :=
        match swap {
            Option.some cid => List.append base [Pair.pair "swapRecord" (Json.make_str cid)],
            Option.none => base,
        } in
    Json.to_string (Json.make_object_pairs fields)

/// The new CID from a `putRecord` response, or `none`.
pub def Atp.put_record_cid (body : String) : Option String :=
    match Atp.parse_json "putRecord response" body {
        Result.err _ => Option.none,
        Result.ok j => Atp.opt_str_field "cid" j,
    }

/// The `getRecord` URL for one record of a DID's repo on its PDS.
pub def Atp.get_record_url (pds : String) (did : String) (collection : String) (rkey : String)
    : String :=
    String.concat_list [pds, "/xrpc/com.atproto.repo.getRecord?repo=", did,
        "&collection=", collection, "&rkey=", rkey]

pub def Atp.put_record_url (pds : String) : String :=
    String.concat pds "/xrpc/com.atproto.repo.putRecord"

// ── RFC 3339 from epoch milliseconds ────────────────────────────────────

#[terminating]
def atp_pad_go (k : I64) (s : String) : String :=
    if I64.lt k 1i64 then s else atp_pad_go (I64.sub k 1i64) (String.concat "0" s)

def atp_pad (width : I64) (n : I64) : String :=
    let s : String := I64.to_string n in
    if I64.lt (String.length s) width
    then atp_pad_go (I64.sub width (String.length s)) s
    else s

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for a non-negative epoch time in ms. The date
/// is Howard Hinnant's `civil_from_days`, valid for every date after 1970.
pub def Atp.iso_datetime (ms_in : I64) : String :=
    let ms : I64 := if I64.lt ms_in 0i64 then 0i64 else ms_in in
    let days : I64 := I64.div ms 86400000i64 in
    let in_day : I64 := I64.rem ms 86400000i64 in
    let z : I64 := I64.add days 719468i64 in
    let era : I64 := I64.div z 146097i64 in
    let doe : I64 := I64.sub z (I64.mul era 146097i64) in
    let yoe : I64 := I64.div
        (I64.sub (I64.add (I64.sub doe (I64.div doe 1460i64)) (I64.div doe 36524i64))
            (I64.div doe 146096i64))
        365i64 in
    let doy : I64 := I64.sub doe
        (I64.sub (I64.add (I64.mul 365i64 yoe) (I64.div yoe 4i64)) (I64.div yoe 100i64)) in
    let mp : I64 := I64.div (I64.add (I64.mul 5i64 doy) 2i64) 153i64 in
    let d : I64 := I64.add (I64.sub doy (I64.div (I64.add (I64.mul 153i64 mp) 2i64) 5i64)) 1i64 in
    let m : I64 := if I64.lt mp 10i64 then I64.add mp 3i64 else I64.sub mp 9i64 in
    let y0 : I64 := I64.add yoe (I64.mul era 400i64) in
    let y : I64 := if I64.lt m 3i64 then I64.add y0 1i64 else y0 in
    String.concat_list [
        atp_pad 4i64 y, "-", atp_pad 2i64 m, "-", atp_pad 2i64 d,
        "T", atp_pad 2i64 (I64.div in_day 3600000i64),
        ":", atp_pad 2i64 (I64.rem (I64.div in_day 60000i64) 60i64),
        ":", atp_pad 2i64 (I64.rem (I64.div in_day 1000i64) 60i64),
        ".", atp_pad 3i64 (I64.rem in_day 1000i64), "Z",
    ]
