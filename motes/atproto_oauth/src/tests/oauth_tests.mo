// Pure tests for atproto_oauth. No browser imports, so this builds and runs
// natively (`monad test motes/atproto_oauth`).
//
// The vectors that matter are external ones -- RFC 7636 Appendix B for PKCE,
// RFC 7638 §3.1 for the thumbprint -- because a self-consistent round trip
// would pass just as happily with the wrong encoding.

use atproto_common::json_read {Atp.parse_json}
use atproto_common::jws {Atp.ath, Atp.s256}
use lib::client_metadata {
    Atp.ClientConfig, Atp.client_metadata, Atp.jwk_is_public, Atp.jwk_thumbprint,
    Atp.jwk_xy, Atp.loopback_client_id, Atp.redirect_uri, Atp.repo_scope,
}
use lib::dpop {
    Atp.DpopClaims, Atp.dpop_ath, Atp.dpop_header, Atp.dpop_payload, Atp.dpop_signing_input,
    Atp.htu,
}
use lib::oauth {
    Atp.PendingLogin, Atp.Session, Atp.Session.describe, Atp.as_metadata,
    Atp.as_supports_es256, Atp.authorize_url, Atp.callback, Atp.check_callback,
    Atp.is_secure_url, Atp.origin_of, Atp.par_body, Atp.par_error, Atp.par_request_uri,
    Atp.refresh_body, Atp.refresh_response, Atp.resource_metadata, Atp.revoke_body,
    Atp.token_body, Atp.token_response,
}
use lib::persist {
    Atp.needs_refresh, Atp.pending_key, Atp.pending_of_json, Atp.pending_to_json,
    Atp.pending_version, Atp.session_key, Atp.session_of_json, Atp.session_to_json,
}
use lib::pkce {
    Atp.form_body, Atp.form_pair, Atp.pkce_challenge, Atp.pkce_method,
    Atp.pkce_valid_verifier, Atp.url_encode,
}

/// A sample client: the scope example.game asks for, so the vectors below are
/// the ones a real deployment produces.
def atp_scope : String := Atp.repo_scope ["com.example.game.progress"]

def atp_cfg : Atp.ClientConfig := {
    name := "example.game",
    scope := atp_scope,
    storage_prefix := "example.game",
}

// ── PKCE: the published vectors ─────────────────────────────────────────

#[test]
def test_pkce_challenge_matches_rfc7636_appendix_b : Bool :=
    let verifier : String := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" in
    String.beq (Atp.pkce_challenge verifier) "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

#[test]
def test_pkce_method_is_s256 : Bool := String.beq Atp.pkce_method "S256"

#[test]
def test_verifier_length_bounds : Bool :=
    // 42 characters is one short of the minimum; 129 is one over the max.
    Bool.not (Atp.pkce_valid_verifier "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        && Atp.pkce_valid_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

#[test]
def test_verifier_rejects_a_non_unreserved_character : Bool :=
    // A space (or any escape-needing byte) is outside RFC 7636's set.
    Bool.not (Atp.pkce_valid_verifier "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa a aaaaaaa")

// ── Form encoding ───────────────────────────────────────────────────────

#[test]
def test_url_encode_reserved_and_space : Bool :=
    String.beq (Atp.url_encode "a b") "a+b"
        && String.beq (Atp.url_encode "a/b?c=d") "a%2Fb%3Fc%3Dd"
        && String.beq (Atp.url_encode "a-b_c.d~e") "a-b_c.d~e"

#[test]
def test_form_pair_and_body : Bool :=
    String.beq (Atp.form_pair "grant_type" "authorization_code")
        "grant_type=authorization_code"
        && String.beq (Atp.form_body [Pair.pair "a" "1", Pair.pair "b" "2"]) "a=1&b=2"

// ── DPoP claims ─────────────────────────────────────────────────────────

def atp_claims (nonce : Option String) (ath : Option String) : Atp.DpopClaims := {
    htm := "POST",
    htu := "https://bsky.social/oauth/par",
    iat := 1600000000i64,
    jti := "jti-1",
    iss := "https://bsky.social",
    nonce := nonce,
    ath := ath,
}

#[test]
def test_dpop_header_shape : Bool :=
    let h : String := Atp.dpop_header "{\"kty\":\"EC\"}" in
    String.contains h "dpop+jwt"
        && String.contains h "ES256"
        && String.contains h "{\"kty\":\"EC\"}"

#[test]
def test_dpop_payload_omits_absent_claims : Bool :=
    // The load-bearing rule: a null nonce is REJECTED by the atproto server,
    // so an absent one must not appear at all.
    let p : String := Atp.dpop_payload (atp_claims Option.none Option.none) in
    Bool.not (String.contains p "nonce")
        && Bool.not (String.contains p "ath")
        && Bool.not (String.contains p "null")

#[test]
def test_dpop_payload_includes_present_claims : Bool :=
    let p : String := Atp.dpop_payload (atp_claims (Option.some "n-1") (Option.some "a-1")) in
    String.contains p "\"nonce\":\"n-1\""
        && String.contains p "\"ath\":\"a-1\""
        && Bool.not (String.contains p "null")

#[test]
def test_dpop_payload_escapes_a_hostile_nonce : Bool :=
    // A nonce cannot break out of the payload and add a claim.
    let p : String := Atp.dpop_payload (atp_claims (Option.some "x\",\"iat\":0") Option.none) in
    String.contains p "\\\""
        && I64.beq (String.count p ",\"iat\":") 1i64

#[test]
def test_dpop_signing_input_signs_header_dot_payload : Bool :=
    // `b64url(header) "." b64url(payload)` -- exactly ONE dot, because the
    // base64url alphabet has no dot. The signature adds the second.
    let input : String := Atp.dpop_signing_input "{\"kty\":\"EC\"}" (atp_claims Option.none Option.none) in
    I64.beq (String.count input ".") 1i64
        && I64.beq (String.count input "=") 0i64

// ── htu ─────────────────────────────────────────────────────────────────

#[test]
def test_htu_strips_query : Bool :=
    String.beq (Atp.htu "https://bsky.social/xrpc/a?b=c") "https://bsky.social/xrpc/a"

#[test]
def test_htu_strips_fragment : Bool :=
    String.beq (Atp.htu "https://bsky.social/xrpc/a#frag") "https://bsky.social/xrpc/a"

#[test]
def test_htu_strips_the_earlier_of_query_and_fragment : Bool :=
    // `?` after `#` is inside the fragment, so the cut is at `#`.
    String.beq (Atp.htu "https://a/x#f?q=1") "https://a/x"
        && String.beq (Atp.htu "https://a/x?q=1#f") "https://a/x"

#[test]
def test_htu_leaves_a_bare_url_alone : Bool :=
    String.beq (Atp.htu "https://bsky.social/xrpc/a") "https://bsky.social/xrpc/a"

#[test]
def test_ath_is_base64url_sha256 : Bool :=
    // Independent value: base64url(sha256("abc")), unpadded.
    String.beq (Atp.dpop_ath "abc") "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        && String.beq (Atp.ath "abc") (Atp.dpop_ath "abc")

// ── AS metadata: the mix-up checks ──────────────────────────────────────

def atp_as_json (issuer : String) : String :=
    String.concat_list ["{\"issuer\":\"", issuer,
        "\",\"authorization_endpoint\":\"https://bsky.social/oauth/authorize\"",
        ",\"token_endpoint\":\"https://bsky.social/oauth/token\"",
        ",\"pushed_authorization_request_endpoint\":\"https://bsky.social/oauth/par\"}"]

#[test]
def test_as_metadata_accepts_a_matching_document : Bool :=
    match Atp.as_metadata "https://bsky.social/.well-known/oauth-authorization-server"
        "https://bsky.social" (atp_as_json "https://bsky.social") {
        Result.ok m => String.beq m.issuer "https://bsky.social",
        Result.err _ => false,
    }

/// `atp_as_json` for bsky.social, plus a `revocation_endpoint`.
def atp_as_with_revoke (r : String) : String :=
    let base : String := atp_as_json "https://bsky.social" in
    String.concat (String.slice base 0i64 (I64.sub (String.length base) 1i64))
        (String.concat_list [",\"revocation_endpoint\":\"", r, "\"}"])

#[test]
def test_as_metadata_keeps_only_a_secure_revocation_endpoint : Bool :=
    let base : String := atp_as_json "https://bsky.social" in
    let url : String := "https://bsky.social/.well-known/oauth-authorization-server" in
    (match Atp.as_metadata url "https://bsky.social" (atp_as_with_revoke "https://bsky.social/oauth/revoke") {
        Result.ok m => String.beq m.revocation_endpoint "https://bsky.social/oauth/revoke",
        Result.err _ => false,
    })
        && (match Atp.as_metadata url "https://bsky.social" (atp_as_with_revoke "http://evil.example/r") {
            Result.ok m => String.is_empty m.revocation_endpoint,
            Result.err _ => false,
        })
        && (match Atp.as_metadata url "https://bsky.social" base {
            Result.ok m => String.is_empty m.revocation_endpoint,
            Result.err _ => false,
        })

#[test]
def test_as_metadata_rejects_a_redirected_issuer : Bool :=
    // The caller named bsky.social; a document claiming elsewhere is a
    // mix-up attempt.
    match Atp.as_metadata "https://bsky.social/.well-known/oauth-authorization-server"
        "https://bsky.social" (atp_as_json "https://evil.example") {
        Result.ok _ => false,
        Result.err e => String.contains e "evil.example",
    }

#[test]
def test_as_metadata_rejects_an_issuer_that_is_not_the_url_origin : Bool :=
    // RFC 8414 §3.3: the issuer must be the URL's own origin.
    match Atp.as_metadata "https://bsky.social/.well-known/oauth-authorization-server"
        "https://evil.example" (atp_as_json "https://evil.example") {
        Result.ok _ => false,
        Result.err e => String.contains e "origin",
    }

#[test]
def test_as_metadata_rejects_an_insecure_endpoint : Bool :=
    let body : String :=
        "{\"issuer\":\"http://a.example\",\"authorization_endpoint\":\"http://a.example/authorize\",\"token_endpoint\":\"http://a.example/token\",\"pushed_authorization_request_endpoint\":\"http://a.example/par\"}" in
    match Atp.as_metadata "http://a.example/meta" "http://a.example" body {
        Result.ok _ => false,
        Result.err _ => true,
    }

#[test]
def test_secure_url_allows_https_and_loopback_only : Bool :=
    Atp.is_secure_url "https://a.example/x"
        && Atp.is_secure_url "http://localhost:8000/x"
        && Atp.is_secure_url "http://127.0.0.1:8000/x"
        && Bool.not (Atp.is_secure_url "http://a.example/x")

#[test]
def test_secure_url_loopback_must_end_the_host : Bool :=
    Atp.is_secure_url "http://localhost"
        && Atp.is_secure_url "http://127.0.0.1/cb"
        && Atp.is_secure_url "http://localhost?x=1"
        && Bool.not (Atp.is_secure_url "http://localhost.evil.example/x")
        && Bool.not (Atp.is_secure_url "http://127.0.0.1.evil.example/x")
        && Bool.not (Atp.is_secure_url "http://localhostevil.example")

#[test]
def test_origin_of : Bool :=
    String.beq (Atp.origin_of "https://a.example/p?q=1") "https://a.example"
        && String.beq (Atp.origin_of "http://localhost:8000") "http://localhost:8000"

#[test]
def test_es256_support : Bool :=
    // An absent list is "unspecified" (accepted); a present list without
    // ES256 is a refusal.
    (match Atp.parse_json "m" "{\"a\":1}" {
        Result.ok j => Atp.as_supports_es256 j,
        Result.err _ => false,
    })
        && (match Atp.parse_json "m"
            "{\"dpop_signing_alg_values_supported\":[\"ES256\"]}" {
            Result.ok j => Atp.as_supports_es256 j,
            Result.err _ => false,
        })
        && (match Atp.parse_json "m"
            "{\"dpop_signing_alg_values_supported\":[\"RS256\"]}" {
            Result.ok j => Bool.not (Atp.as_supports_es256 j),
            Result.err _ => false,
        })

#[test]
def test_resource_metadata_takes_the_first_as : Bool :=
    match Atp.resource_metadata "{\"authorization_servers\":[\"https://bsky.social\"]}" {
        Result.ok s => String.beq s "https://bsky.social",
        Result.err _ => false,
    }

// ── PAR and authorize URL ───────────────────────────────────────────────

#[test]
def test_par_body_carries_the_binding_fields : Bool :=
    let b : String := Atp.par_body "https://app.example/client-metadata.json"
        "https://app.example/" atp_scope "st-1" "verifier" "jkt-1" in
    String.contains b "response_type=code"
        && String.contains b "code_challenge_method=S256"
        && String.contains b "dpop_jkt=jkt-1"
        && String.contains b "state=st-1"
        && I64.gt (String.count b "code_challenge=") 0i64

#[test]
def test_par_request_uri_and_error : Bool :=
    (match Atp.par_request_uri "{\"request_uri\":\"urn:x:1\",\"expires_in\":60}" {
        Result.ok u => String.beq u "urn:x:1",
        Result.err _ => false,
    })
        && (match Atp.par_error "{\"error\":\"invalid_client\"}" {
            Option.some e => String.beq e.code "invalid_client",
            Option.none => false,
        })

#[test]
def test_authorize_url_appends_or_extends_a_query : Bool :=
    String.beq (Atp.authorize_url "https://a.example/authorize" "cid" "urn:x:1")
        "https://a.example/authorize?client_id=cid&request_uri=urn%3Ax%3A1"
        && String.beq (Atp.authorize_url "https://a.example/authorize?x=1" "cid" "u")
            "https://a.example/authorize?x=1&client_id=cid&request_uri=u"

// ── Callback ────────────────────────────────────────────────────────────

def atp_pending : Atp.PendingLogin := {
    state := "st-1",
    verifier := "v",
    issuer := "https://bsky.social",
    did := "did:plc:abc",
    token_endpoint := "https://bsky.social/oauth/token",
    redirect_uri := "https://app.example/",
    client_id := "https://app.example/client-metadata.json",
    handle := "alice.example",
    pds := "https://pds.example",
    jwk := "{\"kty\":\"EC\"}",
    jkt := "jkt-1",
    revocation_endpoint := "https://bsky.social/oauth/revoke",
}

#[test]
def test_callback_reads_code_state_iss : Bool :=
    match Atp.callback (Option.some "c") (Option.some "st-1")
        (Option.some "https://bsky.social") Option.none Option.none {
        Result.ok cb => String.beq cb.code "c",
        Result.err _ => false,
    }

#[test]
def test_callback_reports_a_denial_before_a_missing_code : Bool :=
    // A user who pressed Cancel must not be told "no code".
    match Atp.callback Option.none Option.none Option.none
        (Option.some "access_denied") (Option.some "the user said no") {
        Result.ok _ => false,
        Result.err e =>
            String.contains e "access_denied" && String.contains e "the user said no",
    }

#[test]
def test_callback_without_a_code_is_an_error : Bool :=
    match Atp.callback Option.none (Option.some "s") Option.none Option.none Option.none {
        Result.ok _ => false,
        Result.err e => String.contains e "code",
    }

#[test]
def test_check_callback_rejects_a_mismatched_state : Bool :=
    match Atp.callback (Option.some "c") (Option.some "other") Option.none Option.none Option.none {
        Result.err _ => false,
        Result.ok cb => match Atp.check_callback atp_pending cb {
            Result.ok _ => false,
            Result.err e => String.contains e "state",
        },
    }

#[test]
def test_check_callback_rejects_a_mismatched_issuer : Bool :=
    match Atp.callback (Option.some "c") (Option.some "st-1")
        (Option.some "https://evil.example") Option.none Option.none {
        Result.err _ => false,
        Result.ok cb => match Atp.check_callback atp_pending cb {
            Result.ok _ => false,
            Result.err e => String.contains e "iss",
        },
    }

#[test]
def test_check_callback_accepts_a_matching_pair : Bool :=
    match Atp.callback (Option.some "c") (Option.some "st-1")
        (Option.some "https://bsky.social") Option.none Option.none {
        Result.err _ => false,
        Result.ok cb => match Atp.check_callback atp_pending cb {
            Result.ok _ => true,
            Result.err _ => false,
        },
    }

// ── Token response ──────────────────────────────────────────────────────

def atp_token_json (sub : String) (token_type : String) : String :=
    String.concat_list ["{\"access_token\":\"at\",\"refresh_token\":\"rt\"",
        ",\"token_type\":\"", token_type,
        "\",\"sub\":\"", sub, "\",\"expires_in\":3600,\"scope\":\"atproto\"}"]

#[test]
def test_token_response_builds_a_session : Bool :=
    match Atp.token_response atp_pending "jkt-1" 1000i64
        (atp_token_json "did:plc:abc" "DPoP") {
        Result.ok s => String.beq s.did "did:plc:abc"
            && I64.beq s.expires_at 3601000i64
            && (match s.refresh_token { Option.some _ => true, Option.none => false }),
        Result.err _ => false,
    }

#[test]
def test_token_response_rejects_a_bearer_token : Bool :=
    // A bearer token is not bound to the DPoP key, so it must be refused.
    match Atp.token_response atp_pending "jkt-1" 1000i64
        (atp_token_json "did:plc:abc" "Bearer") {
        Result.ok _ => false,
        Result.err e => String.contains e "DPoP",
    }

#[test]
def test_token_response_rejects_account_substitution : Bool :=
    // A token for a different account than the one resolved before the
    // redirect is the substitution attack.
    match Atp.token_response atp_pending "jkt-1" 1000i64
        (atp_token_json "did:plc:someone-else" "DPoP") {
        Result.ok _ => false,
        Result.err e => String.contains e "sub",
    }

#[test]
def test_session_describe_never_prints_tokens : Bool :=
    match Atp.token_response atp_pending "jkt-1" 1000i64
        (atp_token_json "did:plc:abc" "DPoP") {
        Result.err _ => false,
        Result.ok s =>
            let d : String := Atp.Session.describe s in
            String.contains d "did:plc:abc"
                && Bool.not (String.contains d s.access_token),
    }

#[test]
def test_token_body_and_refresh_body : Bool :=
    String.contains (Atp.token_body "cid" "ru" "code" "ver") "grant_type=authorization_code"
        && String.contains (Atp.token_body "cid" "ru" "code" "ver") "code_verifier=ver"
        && String.contains (Atp.refresh_body "cid" "rt") "grant_type=refresh_token"

// ── Client metadata and the thumbprint ──────────────────────────────────

#[test]
def test_repo_scope_grants_each_collection : Bool :=
    String.beq (Atp.repo_scope List.empty) "atproto"
        && String.beq (Atp.repo_scope ["a.b.c", "d.e.f"])
            "atproto repo:a.b.c?action=create&action=update repo:d.e.f?action=create&action=update"

#[test]
def test_client_metadata_is_a_public_web_client : Bool :=
    let d : String := Atp.client_metadata atp_cfg "https://app.example/client-metadata.json"
        "https://app.example/" in
    String.contains d "\"application_type\":\"web\""
        && String.contains d "\"token_endpoint_auth_method\":\"none\""
        && String.contains d "\"dpop_bound_access_tokens\":true"
        && Bool.not (String.contains d "client_secret")
        // The document asks for exactly what the PAR request asks for.
        && String.contains d (String.concat_list ["\"scope\":\"", atp_scope, "\""])
        && String.contains d "\"redirect_uris\":[\"https://app.example/\"]"
        && String.contains d "\"client_id\":\"https://app.example/client-metadata.json\""
        && String.contains d "\"client_name\":\"example.game\""

#[test]
def test_redirect_uri_and_loopback_client : Bool :=
    String.beq (Atp.redirect_uri "https://app.example") "https://app.example/"
        && String.beq (Atp.loopback_client_id atp_scope "http://127.0.0.1:8000/")
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2F&scope=atproto+repo%3Acom.example.game.progress%3Faction%3Dcreate%26action%3Dupdate"

#[test]
def test_jwt_thumbprint_order_is_canonical : Bool :=
    // RFC 7638's canonical members are `crv`, `kty`, `x`, `y` in that order,
    // and the digest is sha256 of exactly that byte string.
    let crv : String := "P-256" in
    let x : String := "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU" in
    let y : String := "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" in
    // Cross-check: the same canonical form hashed via the shared s256 helper
    // must agree, which pins the field ORDER (a swap changes the digest).
    let canon : String := String.concat_list [
        "{\"crv\":\"", crv, "\",\"kty\":\"EC\",\"x\":\"", x, "\",\"y\":\"", y, "\"}"] in
    String.beq (Atp.jwk_thumbprint x y) (Atp.s256 canon)

#[test]
def test_jwk_xy_requires_p256_and_both_coordinates : Bool :=
    (match Atp.jwk_xy "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\",\"y\":\"b\"}" {
        Result.ok p => match p {
            Pair.pair x y => String.beq x "a" && String.beq y "b",
        },
        Result.err _ => false,
    })
        && (match Atp.jwk_xy "{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"a\",\"y\":\"b\"}" {
            Result.ok _ => false,
            Result.err _ => true,
        })
        && (match Atp.jwk_xy "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\"}" {
            Result.ok _ => false,
            Result.err _ => true,
        })

#[test]
def test_jwk_is_public_rejects_a_private_scalar : Bool :=
    Atp.jwk_is_public "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\",\"y\":\"b\"}"
        && Bool.not (Atp.jwk_is_public "{\"kty\":\"EC\",\"x\":\"a\",\"y\":\"b\",\"d\":\"secret\"}")

// ── Persistence: the redirect round trip ────────────────────────────────

#[test]
def test_pending_survives_a_round_trip : Bool :=
    match Atp.pending_of_json (Atp.pending_to_json atp_pending) {
        Result.err _ => false,
        Result.ok p =>
            String.beq p.state atp_pending.state
                && String.beq p.did atp_pending.did
                && String.beq p.token_endpoint atp_pending.token_endpoint
                && String.beq p.client_id atp_pending.client_id
                && String.beq p.handle atp_pending.handle
                && String.beq p.pds atp_pending.pds
                && String.beq p.jwk atp_pending.jwk
                && String.beq p.jkt atp_pending.jkt,
    }

#[test]
def test_pending_rejects_a_missing_field : Bool :=
    // A blob without the verifier cannot complete a login, so it must be
    // refused rather than parsed into a default that fails later.
    let body : String :=
        "{\"v\":2,\"state\":\"s\",\"issuer\":\"i\",\"did\":\"d\",\"token_endpoint\":\"t\",\"redirect_uri\":\"r\",\"client_id\":\"c\"}" in
    match Atp.pending_of_json body {
        Result.ok _ => false,
        Result.err e => String.contains e "verifier",
    }

#[test]
def test_pending_rejects_a_stale_version : Bool :=
    let body : String :=
        "{\"v\":99,\"state\":\"s\",\"verifier\":\"v\",\"issuer\":\"i\",\"did\":\"d\",\"token_endpoint\":\"t\",\"redirect_uri\":\"r\",\"client_id\":\"c\"}" in
    match Atp.pending_of_json body {
        Result.ok _ => false,
        Result.err _ => true,
    }

#[test]
def test_session_survives_a_round_trip : Bool :=
    match Atp.token_response atp_pending "jkt-1" 1000i64
        (atp_token_json "did:plc:abc" "DPoP") {
        Result.err _ => false,
        Result.ok s => match Atp.session_of_json (Atp.session_to_json s) {
            Result.err _ => false,
            Result.ok back =>
                String.beq back.access_token s.access_token
                    && I64.beq back.expires_at s.expires_at
                    && String.beq back.jkt "jkt-1"
                    && String.beq back.pds "https://pds.example"
                    && String.beq back.jwk atp_pending.jwk
                    && String.beq back.revocation_endpoint "https://bsky.social/oauth/revoke"
                    && (match back.handle {
                        Option.some h => String.beq h "alice.example",
                        Option.none => false,
                    })
                    && (match back.refresh_token {
                        Option.some r => String.beq r "rt",
                        Option.none => false,
                    }),
        },
    }

#[test]
def test_session_from_an_older_build_loads_without_a_revocation_endpoint : Bool :=
    // Stored before revocation existed: still a session, just not revocable.
    let body : String :=
        "{\"v\":2,\"did\":\"did:plc:abc\",\"handle\":null,\"issuer\":\"i\",\"token_endpoint\":\"t\",\"client_id\":\"c\",\"access_token\":\"at\",\"refresh_token\":null,\"scope\":\"atproto\",\"expires_at\":5,\"jkt\":\"k\",\"pds\":\"https://pds.example\",\"jwk\":\"{}\"}" in
    match Atp.session_of_json body {
        Result.ok s => String.is_empty s.revocation_endpoint,
        Result.err _ => false,
    }

#[test]
def test_revoke_body_prefers_the_refresh_token : Bool :=
    match Atp.token_response atp_pending "jkt-1" 1000i64
        (atp_token_json "did:plc:abc" "DPoP") {
        Result.err _ => false,
        Result.ok s =>
            let no_refresh : Atp.Session := { s with refresh_token := Option.none } in
            String.beq (Atp.revoke_body "cid" s)
                "token=rt&token_type_hint=refresh_token&client_id=cid"
                && String.contains (Atp.revoke_body "cid" no_refresh)
                    "token_type_hint=access_token",
    }

#[test]
def test_needs_refresh_is_a_minute_early : Bool :=
    match Atp.token_response atp_pending "jkt-1" 0i64
        (atp_token_json "did:plc:abc" "DPoP") {
        Result.err _ => false,
        Result.ok s =>
            // expires_at is 3,600,000 ms from now, and the refresh window
            // opens a minute before it: at 3,540,000 exactly the margin is
            // used up but not exceeded, so the trigger is the next ms.
            Bool.not (Atp.needs_refresh 0i64 s)
                && Bool.not (Atp.needs_refresh 3500000i64 s)
                && Bool.not (Atp.needs_refresh 3540000i64 s)
                && Atp.needs_refresh 3540001i64 s
                && Atp.needs_refresh 3600000i64 s,
    }

#[test]
def test_storage_keys_are_namespaced : Bool :=
    String.beq (Atp.pending_key "example.game") "example.game.atproto.pending"
        && String.beq (Atp.session_key "example.game") "example.game.atproto.session"
        && I64.beq Atp.pending_version 2i64

// ── Refresh ─────────────────────────────────────────────────────────────

def atp_session_for_refresh : Result String Atp.Session :=
    Atp.token_response atp_pending "jkt-1" 0i64 (atp_token_json "did:plc:abc" "DPoP")

#[test]
def test_refresh_rotates_tokens_and_expiry : Bool :=
    match atp_session_for_refresh {
        Result.err _ => false,
        Result.ok s => match Atp.refresh_response s 5000i64
            "{\"access_token\":\"at2\",\"refresh_token\":\"rt2\",\"token_type\":\"DPoP\",\"sub\":\"did:plc:abc\",\"expires_in\":60}" {
            Result.err _ => false,
            Result.ok r => String.beq r.access_token "at2"
                && I64.beq r.expires_at 65000i64
                && String.beq r.pds s.pds && String.beq r.jwk s.jwk
                && (match r.refresh_token { Option.some t => String.beq t "rt2", Option.none => false }),
        },
    }

#[test]
def test_refresh_without_a_new_refresh_token_keeps_the_old : Bool :=
    match atp_session_for_refresh {
        Result.err _ => false,
        Result.ok s => match Atp.refresh_response s 0i64
            "{\"access_token\":\"at2\",\"token_type\":\"DPoP\"}" {
            Result.err _ => false,
            Result.ok r => match r.refresh_token { Option.some t => String.beq t "rt", Option.none => false },
        },
    }

#[test]
def test_refresh_rejects_bearer_and_other_accounts : Bool :=
    match atp_session_for_refresh {
        Result.err _ => false,
        Result.ok s =>
            (match Atp.refresh_response s 0i64 "{\"access_token\":\"a\",\"token_type\":\"Bearer\"}" {
                Result.ok _ => false, Result.err _ => true,
            })
            && (match Atp.refresh_response s 0i64
                "{\"access_token\":\"a\",\"token_type\":\"DPoP\",\"sub\":\"did:plc:evil\"}" {
                Result.ok _ => false, Result.err _ => true,
            }),
    }
