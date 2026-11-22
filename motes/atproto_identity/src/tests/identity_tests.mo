// Pure tests for atproto_identity: input classification, DID and handle
// syntax, DID documents and the resolution response parsers. No network.

use lib::identity {
    Atp.DidDocument, Atp.Identity, Atp.claims_handle, Atp.classify, Atp.did_document,
    Atp.did_document_url, Atp.doh_txt_did, Atp.doh_txt_url, Atp.is_did, Atp.is_did_web,
    Atp.is_handle, Atp.pct_decode, Atp.resolve_handle_response, Atp.well_known_did,
}

// ── Identity ────────────────────────────────────────────────────────────

#[test]
def test_classify_strips_at_and_splits_did : Bool :=
    (match Atp.classify "@alice.example" {
        Atp.Identity.adk_id_handle h => String.beq h "alice.example",
        _ => false,
    })
        && (match Atp.classify "did:plc:abc" {
            Atp.Identity.adk_id_did d => String.beq d "did:plc:abc",
            _ => false,
        })
        && (match Atp.classify "  " { Atp.Identity.adk_id_empty => true, _ => false })

#[test]
def test_classify_lowercases_handles_but_not_dids : Bool :=
    (match Atp.classify "@Alice.Example" {
        Atp.Identity.adk_id_handle h => String.beq h "alice.example" && Atp.is_handle h,
        _ => false,
    })
        && (match Atp.classify "did:plc:AbC" {
            Atp.Identity.adk_id_did d => String.beq d "did:plc:AbC",
            _ => false,
        })

#[test]
def test_claims_handle_ignores_case : Bool :=
    let doc : Atp.DidDocument := {
        id := "did:plc:abc",
        pds := Option.none,
        also_known_as := ["at://Alice.Example"],
    } in
    Atp.claims_handle doc "alice.example" && Atp.claims_handle doc "ALICE.example"

#[test]
def test_is_did : Bool :=
    Atp.is_did "did:plc:abc123"
        && Atp.is_did "did:web:example.com"
        && Bool.not (Atp.is_did "did:plc")
        && Bool.not (Atp.is_did "alice.example")

#[test]
def test_did_document_url : Bool :=
    String.beq (Atp.did_document_url "did:plc:abc123")
        "https://plc.directory/did:plc:abc123"
        && String.beq (Atp.did_document_url "did:web:example.com")
            "https://example.com/.well-known/did.json"
        && Atp.is_did_web "did:web:example.com"

#[test]
def test_pct_decode_port_escape : Bool :=
    String.beq (Atp.pct_decode "example.com%3A8443") "example.com:8443"

#[test]
def test_is_handle_accepts_a_normal_handle : Bool :=
    Atp.is_handle "alice.example.com"
        && Atp.is_handle "@alice.example.com"
        && Atp.is_handle "a-b.c-d"

#[test]
def test_is_handle_rejects_bad_shapes : Bool :=
    Bool.not (Atp.is_handle "nodots")
        && Bool.not (Atp.is_handle "-alice.example")
        && Bool.not (Atp.is_handle "alice-.example")
        && Bool.not (Atp.is_handle "alice.123")       // last label all digits (IP)
        && Bool.not (Atp.is_handle "alice.BAD.example") // uppercase is not allowed
        && Bool.not (Atp.is_handle "a..b")

#[test]
def test_did_document_extracts_pds_and_aliases : Bool :=
    let body : String :=
        "{\"id\":\"did:plc:abc\",\"alsoKnownAs\":[\"at://alice.example\"],\"service\":[{\"id\":\"#atproto_pds\",\"type\":\"AtprotoPersonalDataServer\",\"serviceEndpoint\":\"https://pds.example\"}]}" in
    match Atp.did_document "did:plc:abc" body {
        Result.err _ => false,
        Result.ok doc =>
            (match doc.pds { Option.some p => String.beq p "https://pds.example", Option.none => false })
                && Atp.claims_handle doc "alice.example",
    }

#[test]
def test_did_document_rejects_a_different_id : Bool :=
    let body : String :=
        "{\"id\":\"did:plc:other\",\"service\":[{\"id\":\"#atproto_pds\",\"serviceEndpoint\":\"https://pds.example\"}]}" in
    match Atp.did_document "did:plc:abc" body {
        Result.ok _ => false,
        Result.err e => String.contains e "did:plc:other",
    }

#[test]
def test_claims_handle_rejects_an_unclaimed_handle : Bool :=
    let doc : Atp.DidDocument := {
        id := "did:plc:abc",
        pds := Option.none,
        also_known_as := ["at://someone-else.example"],
    } in
    Bool.not (Atp.claims_handle doc "alice.example")

#[test]
def test_doh_txt_url_names_the_atproto_record : Bool :=
    String.beq (Atp.doh_txt_url "alice.eurosky.social")
        "https://cloudflare-dns.com/dns-query?name=_atproto.alice.eurosky.social&type=TXT"

#[test]
def test_doh_txt_did_reads_the_record : Bool :=
    // The shape cloudflare-dns.com returns, with a CNAME on the way and an
    // unrelated TXT alongside.
    let body : String :=
        "{\"Status\":0,\"Answer\":[{\"name\":\"_atproto.a.example\",\"type\":5,\"data\":\"x.example.\"},{\"name\":\"x.example\",\"type\":16,\"data\":\"\\\"v=spf1 -all\\\"\"},{\"name\":\"x.example\",\"type\":16,\"data\":\"\\\"did=did:plc:ooensn4mr5mhznzypvxelfa3\\\"\"}]}" in
    match Atp.doh_txt_did body {
        Result.ok d => String.beq d "did:plc:ooensn4mr5mhznzypvxelfa3",
        Result.err _ => false,
    }

#[test]
def test_doh_txt_did_rejoins_split_strings : Bool :=
    let body : String :=
        "{\"Status\":0,\"Answer\":[{\"type\":16,\"data\":\"\\\"did=did:pl\\\" \\\"c:abc\\\"\"}]}" in
    match Atp.doh_txt_did body {
        Result.ok d => String.beq d "did:plc:abc",
        Result.err _ => false,
    }

#[test]
def test_doh_txt_did_refuses_missing_ambiguous_and_nxdomain : Bool :=
    let none : String := "{\"Status\":0,\"Answer\":[]}" in
    let nx : String := "{\"Status\":3}" in
    let two : String :=
        "{\"Status\":0,\"Answer\":[{\"type\":16,\"data\":\"\\\"did=did:plc:a\\\"\"},{\"type\":16,\"data\":\"\\\"did=did:plc:b\\\"\"}]}" in
    let junk : String :=
        "{\"Status\":0,\"Answer\":[{\"type\":16,\"data\":\"\\\"did=nope\\\"\"}]}" in
    (match Atp.doh_txt_did none { Result.ok _ => false, Result.err _ => true })
        && (match Atp.doh_txt_did nx { Result.ok _ => false, Result.err e => String.contains e "3" })
        && (match Atp.doh_txt_did two { Result.ok _ => false, Result.err e => String.contains e "more than one" })
        && (match Atp.doh_txt_did junk { Result.ok _ => false, Result.err _ => true })

#[test]
def test_resolve_handle_and_well_known : Bool :=
    (match Atp.resolve_handle_response "{\"did\":\"did:plc:abc\"}" {
        Result.ok d => String.beq d "did:plc:abc",
        Result.err _ => false,
    })
        && (match Atp.well_known_did "did:plc:abc\n" {
            Result.ok d => String.beq d "did:plc:abc",
            Result.err _ => false,
        })
        && (match Atp.well_known_did "not-a-did" {
            Result.ok _ => false,
            Result.err _ => true,
        })
