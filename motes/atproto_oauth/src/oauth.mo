// The OAuth half of the atproto login: authorization-server discovery, the
// pushed authorization request (PAR, RFC 9126), and the authorization-code
// exchange. Pure: every function takes a parsed document or builds a request
// description, and the driver owns the transport.
//
// The checks here are the ones that stop a login being stolen rather than
// merely failing, so each is written where it can be tested without a network:
//
// - MIX-UP: the AS issuer must equal the origin the metadata was fetched from,
//   and the callback `iss` must equal the issuer stored before the redirect.
// - ACCOUNT SUBSTITUTION: the token `sub` must equal the DID resolved before
//   the redirect.
// - TOKEN BINDING: `token_type` must be `DPoP`, since a bearer token would not
//   be bound to the key that signed the proof.

use json::json {Json}
use atproto_common::json_read {
    Atp.parse_json, Atp.str_field, Atp.opt_str_field, Atp.opt_i64_field,
    Atp.opt_array_field, Atp.array_has_str, Atp.ApiError, Atp.api_error,
}
use lib::pkce {Atp.pkce_challenge, Atp.url_encode, Atp.form_body}
use atproto_common::jsonx {Atp.json_str}

// ── Authorization-server metadata ───────────────────────────────────────

/// The endpoints the flow uses, after validation.
pub struct Atp.AsMetadata {
    issuer : String,
    authorization_endpoint : String,
    token_endpoint : String,
    pushed_authorization_request_endpoint : String,
    /// RFC 7009 token revocation, used at sign-out. Optional in the metadata,
    /// so `""` when the server names none (or names an insecure one): sign-out
    /// then only forgets the session locally.
    revocation_endpoint : String,
}

/// All-`Copy` fields, so the metadata can be read while endpoints are built.
pub instance Copy Atp.AsMetadata {
    def copy (m : Atp.AsMetadata) : Pair Atp.AsMetadata Atp.AsMetadata :=
        Pair.pair m m
}

/// Is this URL https, or http on a loopback host (the dev exception the
/// atproto spec allows and nothing else does)?
pub def Atp.is_secure_url (url : String) : Bool :=
    String.starts_with "https://" url
        || Atp.is_loopback_url "http://localhost" url
        || Atp.is_loopback_url "http://127.0.0.1" url

/// `url` is `prefix` followed by the end of the host: nothing, a port, a path,
/// a query or a fragment. A bare prefix test would also accept
/// `http://localhost.evil.example` and `http://127.0.0.1.evil.example`.
def Atp.is_loopback_url (prefix : String) (url : String) : Bool :=
    if Bool.not (String.starts_with prefix url) then false
    else
        let rest : String := String.drop (String.length prefix) url in
        String.is_empty rest
            || String.starts_with ":" rest || String.starts_with "/" rest
            || String.starts_with "?" rest || String.starts_with "#" rest

/// The origin (`scheme://host[:port]`) of a URL, for the mix-up check.
pub def Atp.origin_of (url : String) : String :=
    let scheme_end : I64 :=
        match String.byte_index_of url "://" {
            Option.some i => I64.add i 3i64,
            Option.none => 0i64,
        } in
    let rest : String := String.drop scheme_end url in
    let host_end : I64 :=
        match String.byte_index_of rest "/" {
            Option.some i => i,
            Option.none => String.length rest,
        } in
    String.slice url 0i64 (I64.add scheme_end host_end)

/// Validate the AS metadata document against the URL it was fetched from.
///
/// `expected_issuer` is the protected-resource metadata's
/// `authorization_servers[0]`, so a server cannot redirect a login to an
/// authorization server the caller did not name. The issuer field must also
/// equal the metadata URL's OWN origin (RFC 8414 §3.3), which is what makes a
/// mix-up attack detectable.
pub def Atp.as_metadata (metadata_url : String) (expected_issuer : String)
    (body : String) : Result String Atp.AsMetadata :=
    match Atp.parse_json "authorization server metadata" body {
        Result.err e => Result.err e,
        Result.ok j =>
            match Atp.str_field "authorization server metadata" "issuer" j {
                Result.err e => Result.err e,
                Result.ok issuer =>
                    if Bool.not (String.beq issuer expected_issuer)
                    then Result.err (String.concat_list [
                        "authorization server metadata: issuer `", issuer,
                        "` is not the expected `", expected_issuer, "`"])
                    else if Bool.not (String.beq (Atp.origin_of metadata_url) issuer)
                    then Result.err (String.concat_list [
                        "authorization server metadata: issuer `", issuer,
                        "` does not match the metadata URL origin `",
                        Atp.origin_of metadata_url, "`"])
                    else Atp.as_endpoints j issuer,
            },
    }

/// The endpoint fields, each required and each required to be a secure URL.
def Atp.as_endpoints (j : Json) (issuer : String) : Result String Atp.AsMetadata :=
    match Atp.str_field "authorization server metadata" "authorization_endpoint" j {
        Result.err e => Result.err e,
        Result.ok authz =>
            match Atp.str_field "authorization server metadata" "token_endpoint" j {
                Result.err e => Result.err e,
                Result.ok token =>
                    match Atp.str_field "authorization server metadata"
                        "pushed_authorization_request_endpoint" j {
                        Result.err e => Result.err e,
                        Result.ok par =>
                            if Bool.not (Atp.is_secure_url authz)
                            then Result.err "authorization endpoint is not https"
                            else if Bool.not (Atp.is_secure_url token)
                            then Result.err "token endpoint is not https"
                            else if Bool.not (Atp.is_secure_url par)
                            then Result.err "PAR endpoint is not https"
                            else
                                let revoke : String :=
                                    match Atp.opt_str_field "revocation_endpoint" j {
                                        Option.some r =>
                                            if Atp.is_secure_url r then r else "",
                                        Option.none => "",
                                    } in
                                let m : Atp.AsMetadata := {
                                    issuer := issuer,
                                    authorization_endpoint := authz,
                                    token_endpoint := token,
                                    pushed_authorization_request_endpoint := par,
                                    revocation_endpoint := revoke,
                                } in
                                Result.ok m,
                    },
            },
    }

/// Does the AS advertise ES256 in `dpop_signing_alg_values_supported`?
///
/// An absent list is treated as "unspecified" rather than "no": the spec makes
/// the field optional, and atproto requires ES256 anyway, so refusing an
/// unlisted-but-working server would only break real logins. A list that is
/// present and lacks ES256 IS a refusal, because the DPoP proof we can make is
/// ES256 and nothing else.
pub def Atp.as_supports_es256 (j : Json) : Bool :=
    let listed : List Json := Atp.opt_array_field "dpop_signing_alg_values_supported" j in
    match listed {
        List.empty => true,
        _ => Atp.array_has_str listed "ES256",
    }

// ── Protected-resource metadata ─────────────────────────────────────────

/// `authorization_servers[0]` from the protected-resource metadata document.
pub def Atp.resource_metadata (body : String) : Result String String :=
    match Atp.parse_json "protected resource metadata" body {
        Result.err e => Result.err e,
        Result.ok j =>
            match Atp.opt_array_field "authorization_servers" j {
                List.empty =>
                    Result.err "protected resource metadata: no authorization_servers",
                List.cons first _ => match first {
                    Json.str s => Result.ok s,
                    _ => Result.err "protected resource metadata: authorization_servers[0] is not a string",
                },
            },
    }

// ── PAR ─────────────────────────────────────────────────────────────────

/// Everything the callback needs that must survive the redirect. The DPoP key
/// is NOT in here: it lives in IndexedDB instead (`KeyStore`), because it is a
/// non-extractable handle rather than a string.
pub struct Atp.PendingLogin {
    state : String,
    verifier : String,
    issuer : String,
    did : String,
    token_endpoint : String,
    redirect_uri : String,
    client_id : String,
    /// The handle the user typed ("" for a DID), for display after login.
    handle : String,
    /// The PDS from the DID document: where the repo calls go.
    pds : String,
    /// The DPoP key's public JWK and its thumbprint. Public, so they travel
    /// in localStorage; the private half stays in IndexedDB.
    jwk : String,
    jkt : String,
    /// The AS's revocation endpoint (`""` if none), carried into the session.
    revocation_endpoint : String,
}

/// All-`Copy` fields (`Option String` is Copy too).
pub instance Copy Atp.PendingLogin {
    def copy (p : Atp.PendingLogin) : Pair Atp.PendingLogin Atp.PendingLogin :=
        Pair.pair p p
}

/// The PAR request body.
///
/// `dpop_jkt` binds the authorization code to the DPoP key: the token endpoint
/// then refuses a code presented with a proof from a different key, so a code
/// stolen from the redirect URL is useless without the key.
pub def Atp.par_body (client_id : String) (redirect_uri : String) (scope : String)
    (state : String) (verifier : String) (jkt : String) : String :=
    Atp.form_body [
        Pair.pair "response_type" "code",
        Pair.pair "client_id" client_id,
        Pair.pair "redirect_uri" redirect_uri,
        Pair.pair "scope" scope,
        Pair.pair "state" state,
        Pair.pair "code_challenge" (Atp.pkce_challenge verifier),
        Pair.pair "code_challenge_method" "S256",
        Pair.pair "dpop_jkt" jkt,
    ]

/// The `request_uri` a PAR response hands back.
pub def Atp.par_request_uri (body : String) : Result String String :=
    match Atp.parse_json "PAR response" body {
        Result.err e => Result.err e,
        Result.ok j => Atp.str_field "PAR response" "request_uri" j,
    }

/// A PAR error, if the body carries one (`{"error":"invalid_client",...}`).
pub def Atp.par_error (body : String) : Option Atp.ApiError :=
    match Atp.parse_json "PAR response" body {
        Result.err _ => Option.none,
        Result.ok j => Atp.api_error j,
    }

/// Where to send the user: the authorization endpoint with `client_id` and
/// the PAR `request_uri` (RFC 9126 §4).
pub def Atp.authorize_url (authorization_endpoint : String) (client_id : String)
    (request_uri : String) : String :=
    String.concat_list [authorization_endpoint,
        (match String.byte_index_of authorization_endpoint "?" {
            Option.some _ => "&",
            Option.none => "?",
        }),
        "client_id=", Atp.url_encode client_id,
        "&request_uri=", Atp.url_encode request_uri]

// ── The callback ────────────────────────────────────────────────────────

/// The authorization code and its `state`/`iss`, read out of the callback URL.
/// `iss` is optional here only because an older server may omit it; when it is
/// present it MUST match (checked by `Atp.check_callback`).
pub struct Atp.Callback {
    code : String,
    state : String,
    iss : Option String,
}

/// The callback query parameters, or an error describing what was wrong.
///
/// The `error`/`error_description` pair is checked FIRST, because a denial
/// arrives as `?error=access_denied` with no `code` at all, and reporting
/// "missing code" for a user who pressed Cancel would be misleading.
pub def Atp.callback (code : Option String) (state : Option String)
    (iss : Option String) (error : Option String) (desc : Option String)
    : Result String Atp.Callback :=
    match error {
        Option.some e => Result.err (match desc {
            Option.some d => String.concat_list ["the authorization server refused: ", e, " (", d, ")"],
            Option.none => String.concat_list ["the authorization server refused: ", e],
        }),
        Option.none => match code {
            Option.none => Result.err "the callback URL carried no `code`",
            Option.some c => match state {
                Option.none => Result.err "the callback URL carried no `state`",
                Option.some s => Result.ok { code := c, state := s, iss := iss },
            },
        },
    }

pub instance Copy Atp.Callback {
    def copy (c : Atp.Callback) : Pair Atp.Callback Atp.Callback := Pair.pair c c
}

/// Check a callback against the pending login: login-CSRF `state` and, when
/// present, the mix-up `iss`.
pub def Atp.check_callback (pending : Atp.PendingLogin) (cb : Atp.Callback)
    : Result String Unit :=
    if Bool.not (String.beq pending.state cb.state)
    then Result.err "the callback `state` does not match this login (possible CSRF)"
    else match cb.iss {
        Option.none => Result.ok Unit.unit,
        Option.some i =>
            if String.beq i pending.issuer
            then Result.ok Unit.unit
            else Result.err (String.concat_list [
                "the callback `iss` `", i, "` is not the issuer this login started with `",
                pending.issuer, "`"]),
    }

// ── The token exchange ──────────────────────────────────────────────────

/// A completed session. `access_token`/`refresh_token` are secrets: they are
/// never logged, and `Atp.Session.describe` deliberately does not print them.
pub struct Atp.Session {
    did : String,
    handle : Option String,
    issuer : String,
    token_endpoint : String,
    client_id : String,
    access_token : String,
    refresh_token : Option String,
    scope : String,
    expires_at : I64,
    jkt : String,
    /// The PDS and the public JWK, for every authenticated repo call.
    pds : String,
    jwk : String,
    /// Where sign-out revokes the grant (RFC 7009); `""` when the AS has none.
    revocation_endpoint : String,
}

pub instance Copy Atp.Session {
    def copy (s : Atp.Session) : Pair Atp.Session Atp.Session := Pair.pair s s
}

pub def Atp.Session.describe (s : Atp.Session) : String :=
    match s.handle {
        Option.some h => String.concat_list ["@", h, " (", s.did, ")"],
        Option.none => s.did,
    }

/// The token request body (`authorization_code` grant).
pub def Atp.token_body (client_id : String) (redirect_uri : String) (code : String)
    (verifier : String) : String :=
    Atp.form_body [
        Pair.pair "grant_type" "authorization_code",
        Pair.pair "code" code,
        Pair.pair "redirect_uri" redirect_uri,
        Pair.pair "client_id" client_id,
        Pair.pair "code_verifier" verifier,
    ]

/// The refresh request body. DPoP-bound with the SAME key, so the new access
/// token is bound to it too.
pub def Atp.refresh_body (client_id : String) (refresh_token : String) : String :=
    Atp.form_body [
        Pair.pair "grant_type" "refresh_token",
        Pair.pair "refresh_token" refresh_token,
        Pair.pair "client_id" client_id,
    ]

/// The revocation request body (RFC 7009 §2.1). Revoking the refresh token
/// ends the whole grant, so the access token issued with it dies too; with no
/// refresh token, the access token is revoked instead.
pub def Atp.revoke_body (client_id : String) (s : Atp.Session) : String :=
    match s.refresh_token {
        Option.some rt => Atp.form_body [
            Pair.pair "token" rt,
            Pair.pair "token_type_hint" "refresh_token",
            Pair.pair "client_id" client_id,
        ],
        Option.none => Atp.form_body [
            Pair.pair "token" s.access_token,
            Pair.pair "token_type_hint" "access_token",
            Pair.pair "client_id" client_id,
        ],
    }

/// Validate the token response and build the session.
///
/// `expected_sub` is the DID resolved before the redirect: a token for a
/// different account is the account-substitution attack, and it is refused
/// here rather than at the first API call.
pub def Atp.token_response (pending : Atp.PendingLogin) (jkt : String)
    (now_ms : I64) (body : String) : Result String Atp.Session :=
    match Atp.parse_json "token response" body {
        Result.err e => Result.err e,
        Result.ok j => Atp.token_fields pending jkt now_ms j,
    }

def Atp.token_fields (pending : Atp.PendingLogin) (jkt : String) (now_ms : I64)
    (j : Json) : Result String Atp.Session :=
    match Atp.str_field "token response" "access_token" j {
        Result.err e => Result.err e,
        Result.ok access =>
            match Atp.str_field "token response" "token_type" j {
                Result.err e => Result.err e,
                Result.ok token_type =>
                    if Bool.not (String.beq token_type "DPoP")
                    then Result.err (String.concat_list [
                        "token response: token_type `", token_type,
                        "` is not DPoP; a bearer token would not be bound to this key"])
                    else match Atp.str_field "token response" "sub" j {
                        Result.err e => Result.err e,
                        Result.ok sub =>
                            if Bool.not (String.beq sub pending.did)
                            then Result.err (String.concat_list [
                                "token response: `sub` ", sub,
                                " is not the account this login started with (", pending.did, ")"])
                            else Atp.token_session pending jkt now_ms access j,
                    },
            },
    }

/// The optional fields, then the session. `expires_in` is seconds from now;
/// an absent one is treated as 3600 (the atproto default is short-lived
/// anyway, and a refresh is cheap).
def Atp.token_session (pending : Atp.PendingLogin) (jkt : String) (now_ms : I64)
    (access : String) (j : Json) : Result String Atp.Session :=
    let expires_in : I64 :=
        match Atp.opt_i64_field "expires_in" j {
            Option.some n => if I64.lt n 1i64 then 1i64 else n,
            Option.none => 3600i64,
        } in
    let scope : String :=
        match Atp.opt_str_field "scope" j {
            Option.some s => s,
            Option.none => "atproto",
        } in
    let handle : Option String :=
        if String.is_empty pending.handle then Option.none else Option.some pending.handle in
    let s : Atp.Session := {
        did := pending.did,
        handle := handle,
        issuer := pending.issuer,
        token_endpoint := pending.token_endpoint,
        client_id := pending.client_id,
        access_token := access,
        refresh_token := Atp.opt_str_field "refresh_token" j,
        scope := scope,
        expires_at := I64.add now_ms (I64.mul expires_in 1000i64),
        jkt := jkt,
        pds := pending.pds,
        jwk := pending.jwk,
        revocation_endpoint := pending.revocation_endpoint,
    } in
    Result.ok s

/// Apply a refresh-token grant's response to the session it refreshed.
///
/// The same checks as the code exchange: a DPoP token, for the same account.
/// atproto rotates refresh tokens, so a new one replaces the old; a response
/// without one keeps the old (some servers only rotate occasionally).
pub def Atp.refresh_response (s : Atp.Session) (now_ms : I64) (body : String)
    : Result String Atp.Session :=
    match Atp.parse_json "refresh response" body {
        Result.err e => Result.err e,
        Result.ok j => match Atp.str_field "refresh response" "access_token" j {
            Result.err e => Result.err e,
            Result.ok access => match Atp.str_field "refresh response" "token_type" j {
                Result.err e => Result.err e,
                Result.ok token_type =>
                    if Bool.not (String.beq token_type "DPoP")
                    then Result.err "refresh response: the token is not DPoP-bound"
                    else match Atp.opt_str_field "sub" j {
                        Option.some sub =>
                            if Bool.not (String.beq sub s.did)
                            then Result.err "refresh response: the token is for another account"
                            else Atp.refreshed s now_ms access j,
                        Option.none => Atp.refreshed s now_ms access j,
                    },
            },
        },
    }

def Atp.refreshed (s : Atp.Session) (now_ms : I64) (access : String) (j : Json)
    : Result String Atp.Session :=
    let expires_in : I64 :=
        match Atp.opt_i64_field "expires_in" j {
            Option.some n => if I64.lt n 1i64 then 1i64 else n,
            Option.none => 3600i64,
        } in
    let refresh : Option String :=
        match Atp.opt_str_field "refresh_token" j {
            Option.some r => Option.some r,
            Option.none => s.refresh_token,
        } in
    let next : Atp.Session := {
        s with access_token := access,
            refresh_token := refresh,
            expires_at := I64.add now_ms (I64.mul expires_in 1000i64),
    } in
    Result.ok next
