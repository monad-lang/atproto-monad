// Serialising the login state so it survives the OAuth redirect.
//
// The page UNLOADS between the PAR request and the callback, so two things
// have to outlive it:
//
// - `PendingLogin` (state, PKCE verifier, issuer, DID, endpoints) -- in
//   `localStorage`, because it is all strings.
// - the DPoP key -- in IndexedDB (`KeyStore`), NOT here: it is a
//   non-extractable `CryptoKey` handle, not a string, and structured clone is
//   the only thing that can carry it. That split is the whole reason the
//   key store exists (`web-wasm-crypto.md` Phase 4).
//
// Pure JSON in and out, so the round trip is native-testable; the driver does
// the `Storage.set`/`Storage.get`.

use json::json {
    Json, Json.parse, Json.to_string, Json.make_object_pairs, Json.make_str,
    Json.object_get, Json.get_str, Json.get_object, Json.make_num_int,
}
use atproto_common::json_read {Atp.opt_str_field, Atp.opt_i64_field, Atp.opt_array_field}
use lib::oauth {
    Atp.PendingLogin, Atp.Session,
}

/// The version tag. A stored blob from an older build is DISCARDED rather than
/// best-effort parsed: a half-understood `PendingLogin` would send the token
/// request to the wrong endpoint or with the wrong verifier, and the failure
/// would surface as an opaque `invalid_grant`.
/// 2: the pending login and the session carry the PDS and the public JWK.
pub def Atp.pending_version : I64 := 2i64

/// A `PendingLogin` with no flow behind it. Every field is a real `String` and
/// no step reads it while the machine is idle, so nothing is fabricated.
pub def atp_no_pending : Atp.PendingLogin := {
    state := "",
    verifier := "",
    issuer := "",
    did := "",
    token_endpoint := "",
    redirect_uri := "",
    client_id := "",
    handle := "",
    pds := "",
    jwk := "",
    jkt := "",
    revocation_endpoint := "",
}

/// A `Session` with nothing behind it, for the machine's idle state.
pub def atp_no_session : Atp.Session := {
    did := "",
    handle := Option.none,
    issuer := "",
    token_endpoint := "",
    client_id := "",
    access_token := "",
    refresh_token := Option.none,
    scope := "",
    expires_at := 0i64,
    jkt := "",
    pds := "",
    jwk := "",
    revocation_endpoint := "",
}

/// The localStorage key for the pending login, under the app's
/// `ClientConfig.storage_prefix`: `<prefix>.atproto.pending`.
pub def Atp.pending_key (prefix : String) : String :=
    String.concat prefix ".atproto.pending"

/// The localStorage key for the session: `<prefix>.atproto.session`.
pub def Atp.session_key (prefix : String) : String :=
    String.concat prefix ".atproto.session"

/// The `PendingLogin` as JSON text.
pub def Atp.pending_to_json (p : Atp.PendingLogin) : String :=
    Json.to_string (Json.make_object_pairs [
        Pair.pair "v" (Atp.json_i64 Atp.pending_version),
        Pair.pair "state" (Json.make_str p.state),
        Pair.pair "verifier" (Json.make_str p.verifier),
        Pair.pair "issuer" (Json.make_str p.issuer),
        Pair.pair "did" (Json.make_str p.did),
        Pair.pair "token_endpoint" (Json.make_str p.token_endpoint),
        Pair.pair "redirect_uri" (Json.make_str p.redirect_uri),
        Pair.pair "client_id" (Json.make_str p.client_id),
        Pair.pair "handle" (Json.make_str p.handle),
        Pair.pair "pds" (Json.make_str p.pds),
        Pair.pair "jwk" (Json.make_str p.jwk),
        Pair.pair "jkt" (Json.make_str p.jkt),
        Pair.pair "revocation_endpoint" (Json.make_str p.revocation_endpoint),
    ])

/// A JSON integer, through the `json` mote's own number constructor.
def Atp.json_i64 (n : I64) : Json := Json.make_num_int n

/// Parse a stored `PendingLogin`. Every field is required; a blob missing one
/// is rejected, because a login cannot proceed without it.
pub def Atp.pending_of_json (body : String) : Result String Atp.PendingLogin :=
    match Json.parse body {
        Result.err e =>
            Result.err (String.concat "the stored login is not JSON: "
                (Json.ParseError.to_string e)),
        Result.ok j =>
            match Atp.opt_i64_field "v" j {
                Option.none => Result.err "the stored login has no version",
                Option.some v =>
                    if Bool.not (I64.beq v Atp.pending_version)
                    then Result.err (String.concat_list [
                        "the stored login is version ", I64.to_string v,
                        ", this build writes ", I64.to_string Atp.pending_version,
                        "; start the sign-in again"])
                    else Atp.pending_fields j,
            },
    }

/// A required string field of the stored blob. Every field a login needs is
/// required; a partial blob would be a wrong-endpoint request, not a degraded
/// one.
def Atp.req (j : Json) (key : String) : Result String String :=
    match Json.get_object j {
        Result.err _ => Result.err "the stored login is not an object",
        Result.ok o => match Json.object_get key o {
            Option.none =>
                Result.err (String.concat_list ["the stored login has no `", key, "`"]),
            Option.some v => match Json.get_str v {
                Result.ok s => Result.ok s,
                Result.err _ =>
                    Result.err (String.concat_list ["the stored login's `", key, "` is not a string"]),
            },
        },
    }

/// Note the ORDER: each field is read only after the previous one succeeded,
/// because the language has no destructuring `let` in this position and a
/// wrong-order read would bind the wrong failure.
def Atp.pending_fields (j : Json) : Result String Atp.PendingLogin :=
    match Atp.req j "state" {
        Result.err e => Result.err e,
        Result.ok state => match Atp.req j "verifier" {
            Result.err e => Result.err e,
            Result.ok verifier => match Atp.req j "issuer" {
                Result.err e => Result.err e,
                Result.ok issuer => match Atp.req j "did" {
                    Result.err e => Result.err e,
                    Result.ok did => match Atp.req j "token_endpoint" {
                        Result.err e => Result.err e,
                        Result.ok token_endpoint => match Atp.req j "redirect_uri" {
                            Result.err e => Result.err e,
                            Result.ok redirect_uri => match Atp.req j "client_id" {
                                Result.err e => Result.err e,
                                Result.ok client_id =>
                                    let p : Atp.PendingLogin := {
                                        state := state,
                                        verifier := verifier,
                                        issuer := issuer,
                                        did := did,
                                        token_endpoint := token_endpoint,
                                        redirect_uri := redirect_uri,
                                        client_id := client_id,
                                        handle := "",
                                        pds := "",
                                        jwk := "",
                                        jkt := "",
                                        revocation_endpoint := "",
                                    } in
                                    Atp.pending_keys p j,
                            },
                        },
                    },
                },
            },
        },
    }

/// The PDS and the key halves: required, because without them the callback
/// cannot sign the token request or find the repo. The handle is optional.
def Atp.pending_keys (p : Atp.PendingLogin) (j : Json) : Result String Atp.PendingLogin :=
    match Atp.req j "pds" {
        Result.err e => Result.err e,
        Result.ok pds => match Atp.req j "jwk" {
            Result.err e => Result.err e,
            Result.ok jwk => match Atp.req j "jkt" {
                Result.err e => Result.err e,
                Result.ok jkt =>
                    let handle : String :=
                        match Atp.opt_str_field "handle" j {
                            Option.some h => h,
                            Option.none => "",
                        } in
                    let full : Atp.PendingLogin := {
                        p with handle := handle, pds := pds, jwk := jwk, jkt := jkt,
                            revocation_endpoint := Atp.opt_str j "revocation_endpoint",
                    } in
                    Result.ok full,
            },
        },
    }

// ── The session ─────────────────────────────────────────────────────────

/// The session as JSON text.
///
/// This DOES put the access and refresh tokens in `localStorage`, which is the
/// documented trade-off of a serverless web client: the alternative is
/// re-authenticating on every page load. The blast radius is bounded by the
/// tokens being DPoP-bound to a key that never leaves IndexedDB -- a stolen
/// `localStorage` is not enough to use them, which is exactly why the key
/// store was built. The tokens are still never *logged*.
pub def Atp.session_to_json (s : Atp.Session) : String :=
    Json.to_string (Json.make_object_pairs [
        Pair.pair "v" (Atp.json_i64 Atp.pending_version),
        Pair.pair "did" (Json.make_str s.did),
        Pair.pair "handle" (Atp.json_opt_str s.handle),
        Pair.pair "issuer" (Json.make_str s.issuer),
        Pair.pair "token_endpoint" (Json.make_str s.token_endpoint),
        Pair.pair "client_id" (Json.make_str s.client_id),
        Pair.pair "access_token" (Json.make_str s.access_token),
        Pair.pair "refresh_token" (Atp.json_opt_str s.refresh_token),
        Pair.pair "scope" (Json.make_str s.scope),
        Pair.pair "expires_at" (Atp.json_i64 s.expires_at),
        Pair.pair "jkt" (Json.make_str s.jkt),
        Pair.pair "pds" (Json.make_str s.pds),
        Pair.pair "jwk" (Json.make_str s.jwk),
        Pair.pair "revocation_endpoint" (Json.make_str s.revocation_endpoint),
    ])

def Atp.json_opt_str (v : Option String) : Json :=
    match v {
        Option.none => Json.null,
        Option.some s => Json.make_str s,
    }

/// Parse a stored session, or a message. `expires_at` is required: a session
/// with no expiry would be refreshed never and used until it 401s.
pub def Atp.session_of_json (body : String) : Result String Atp.Session :=
    match Json.parse body {
        Result.err e =>
            Result.err (String.concat "the stored session is not JSON: "
                (Json.ParseError.to_string e)),
        Result.ok j =>
            match Atp.opt_i64_field "v" j {
                Option.none => Result.err "the stored session has no version",
                Option.some v =>
                    if Bool.not (I64.beq v Atp.pending_version)
                    then Result.err "the stored session is from another build"
                    else Atp.session_fields j,
            },
    }

def Atp.session_fields (j : Json) : Result String Atp.Session :=
    match Atp.req j "did" {
        Result.err e => Result.err e,
        Result.ok did => match Atp.req j "issuer" {
            Result.err e => Result.err e,
            Result.ok issuer => match Atp.req j "token_endpoint" {
                Result.err e => Result.err e,
                Result.ok token_endpoint => match Atp.req j "client_id" {
                    Result.err e => Result.err e,
                    Result.ok client_id => match Atp.req j "access_token" {
                        Result.err e => Result.err e,
                        Result.ok access_token => match Atp.req j "scope" {
                            Result.err e => Result.err e,
                            Result.ok scope => match Atp.req j "jkt" {
                                Result.err e => Result.err e,
                                Result.ok jkt => match Atp.opt_i64_field "expires_at" j {
                                    Option.none =>
                                        Result.err "the stored session has no `expires_at`",
                                    Option.some expires_at =>
                                        let s : Atp.Session := {
                                            did := did,
                                            handle := Atp.opt_str_field "handle" j,
                                            issuer := issuer,
                                            token_endpoint := token_endpoint,
                                            client_id := client_id,
                                            access_token := access_token,
                                            refresh_token := Atp.opt_str_field "refresh_token" j,
                                            scope := scope,
                                            expires_at := expires_at,
                                            jkt := jkt,
                                            pds := "",
                                            jwk := "",
                                            revocation_endpoint := "",
                                        } in
                                        Atp.session_keys s j,
                                },
                            },
                        },
                    },
                },
            },
        },
    }

/// A session without its PDS or JWK cannot make a repo call, so it is
/// refused (and the user is signed out) rather than half-restored.
def Atp.session_keys (s : Atp.Session) (j : Json) : Result String Atp.Session :=
    match Atp.req j "pds" {
        Result.err e => Result.err e,
        Result.ok pds => match Atp.req j "jwk" {
            Result.err e => Result.err e,
            Result.ok jwk =>
                let full : Atp.Session := {
                    s with pds := pds, jwk := jwk,
                        revocation_endpoint := Atp.opt_str j "revocation_endpoint",
                } in
                Result.ok full,
        },
    }

/// An optional string field, `""` when absent. The revocation endpoint is
/// optional so a session stored before it existed still loads; it just signs
/// out without revoking.
def Atp.opt_str (j : Json) (key : String) : String :=
    match Atp.opt_str_field key j {
        Option.some v => v,
        Option.none => "",
    }

/// Is the access token due for a refresh? Refreshed a minute early, so a
/// request in flight when it expires is not the one that discovers it.
pub def Atp.needs_refresh (now_ms : I64) (s : Atp.Session) : Bool :=
    I64.gt (I64.add now_ms 60000i64) s.expires_at
