// Pure tests for atproto_repo: the getRecord/putRecord envelopes, URLs, the
// XRPC error classifiers and RFC 3339 timestamps.

use json::json {Json, Json.make_num_int, Json.make_object_pairs, Json.make_str}
use atproto_common::json_read {Atp.opt_i64_field}
use lib::records {
    Atp.fetched_of_body, Atp.get_record_url, Atp.is_invalid_swap, Atp.is_record_not_found,
    Atp.iso_datetime, Atp.put_record_body, Atp.put_record_cid,
}

/// `Option I64` equality: the language has no integer literal patterns (and
/// no match on `I64` at all), so an `Option I64` is compared through this.
def atp_opt_i64_is (want : I64) (got : Option I64) : Bool :=
    match got {
        Option.some n => I64.beq n want,
        Option.none => false,
    }

// ── Records ─────────────────────────────────────────────────────────────

#[test]
def test_fetched_reads_value_and_cid : Bool :=
    let body : String :=
        "{\"uri\":\"at://did:plc:a/com.example.game.progress/self\",\"cid\":\"bafy1\",\"value\":{\"$type\":\"com.example.game.progress\",\"totalSolved\":12,\"bestScore\":4400,\"hints\":3,\"reveals\":1,\"updatedAt\":\"2026-11-21T10:00:00.000Z\"}}" in
    match Atp.fetched_of_body body {
        Result.err _ => false,
        Result.ok f => String.beq f.cid "bafy1"
            && atp_opt_i64_is 12i64 (Atp.opt_i64_field "totalSolved" f.value)
            && atp_opt_i64_is 4400i64 (Atp.opt_i64_field "bestScore" f.value),
    }

#[test]
def test_fetched_needs_the_envelope : Bool :=
    (match Atp.fetched_of_body "{\"value\":{}}" { Result.ok _ => false, Result.err _ => true })
        && (match Atp.fetched_of_body "{\"cid\":\"c\"}" { Result.ok _ => false, Result.err _ => true })
        && (match Atp.fetched_of_body "not json" { Result.ok _ => false, Result.err _ => true })

#[test]
def test_xrpc_error_classifiers : Bool :=
    Atp.is_record_not_found 400i64 "{\"error\":\"RecordNotFound\",\"message\":\"x\"}"
        && Bool.not (Atp.is_record_not_found 500i64 "RecordNotFound")
        && Atp.is_invalid_swap 400i64 "{\"error\":\"InvalidSwap\"}"
        && Bool.not (Atp.is_invalid_swap 401i64 "InvalidSwap")

#[test]
def test_put_record_body_swaps_only_with_a_cid : Bool :=
    let rec : Json := Json.make_object_pairs [
        Pair.pair "$type" (Json.make_str "com.example.game.progress"),
        Pair.pair "totalSolved" (Json.make_num_int 2i64),
    ] in
    let col : String := "com.example.game.progress" in
    let with_swap : String := Atp.put_record_body "did:plc:a" col "self" rec (Option.some "bafy9") in
    let without : String := Atp.put_record_body "did:plc:a" col "self" rec Option.none in
    String.contains with_swap "\"swapRecord\":\"bafy9\""
        && String.contains with_swap "\"collection\":\"com.example.game.progress\""
        && String.contains with_swap "\"rkey\":\"self\""
        && String.contains with_swap "\"$type\":\"com.example.game.progress\""
        && String.contains with_swap "\"totalSolved\":2"
        && Bool.not (String.contains without "swapRecord")

#[test]
def test_put_record_cid_and_urls : Bool :=
    (match Atp.put_record_cid "{\"uri\":\"at://x\",\"cid\":\"bafy2\"}" {
        Option.some c => String.beq c "bafy2",
        Option.none => false,
    })
        && String.beq (Atp.get_record_url "https://pds.example" "did:plc:a"
            "com.example.game.progress" "self")
            "https://pds.example/xrpc/com.atproto.repo.getRecord?repo=did:plc:a&collection=com.example.game.progress&rkey=self"

#[test]
def test_iso_datetime : Bool :=
    String.beq (Atp.iso_datetime 0i64) "1970-01-01T00:00:00.000Z"
        // 2000-02-29 (a leap day in a century leap year), 12:34:56.789
        && String.beq (Atp.iso_datetime 951827696789i64) "2000-02-29T12:34:56.789Z"
        // 2026-11-21T00:00:00Z
        && String.beq (Atp.iso_datetime 1795219200000i64) "2026-11-21T00:00:00.000Z"
