// The OAuth client-metadata document, and the RFC 7638 JWK thumbprint that
// `dpop_jkt` carries.
//
// Pure: the driver fetches nothing here, it serves the document (a public web
// client) and computes the thumbprint from the exported JWK.
//
// atproto's client-metadata differs from plain OAuth in one way that matters:
// the `client_id` IS the URL the document is served from. A public web client
// therefore needs a hosted `client-metadata.json` whose own URL is its
// `client_id`, which is why the app's build emits one and why `client_id` is derived
// from the page origin rather than invented.

use json::json {Json, Json.parse, Json.to_string}
use atproto_common::json_read {Atp.str_field, Atp.opt_str_field}
use atproto_common::jws {Atp.s256}
use atproto_common::jsonx {Atp.json_str}
use lib::pkce {Atp.url_encode}

/// What a client tells the authorization server and the browser about itself.
/// Every app-specific string the flow needs lives here, so the motes carry none.
///
/// - `name` is `client_name` in the hosted metadata document.
/// - `scope` is the one scope string the PAR request, the loopback client id and
///   the hosted metadata all use. They must agree: a mismatch is an
///   `invalid_scope` at PAR. `Atp.repo_scope` builds the usual value.
/// - `storage_prefix` namespaces the localStorage keys (`Atp.pending_key`,
///   `Atp.session_key`), so two apps on one origin keep separate logins.
pub struct Atp.ClientConfig {
    name : String,
    scope : String,
    storage_prefix : String,
}

pub instance Copy Atp.ClientConfig {
    def copy (c : Atp.ClientConfig) : Pair Atp.ClientConfig Atp.ClientConfig := Pair.pair c c
}

#[terminating]
def Atp.repo_scope_go (cs : List String) (acc : String) : String :=
    match cs {
        List.empty => acc,
        List.cons c rest =>
            Atp.repo_scope_go rest
                (String.concat_list [acc, " repo:", c, "?action=create&action=update"]),
    }

/// `atproto` plus a granular repo scope per collection: the app may create and
/// update records in its own collections and nothing else, without a full-repo
/// grant. `atproto` is required in every atproto scope.
pub def Atp.repo_scope (collections : List String) : String :=
    Atp.repo_scope_go collections "atproto"

/// The `redirect_uris` entry: the page itself. A static host serves
/// `index.html` at `/` with no rewrite rule, and the app reads the callback
/// out of `window.location` at mount, then `Window.replace`s the query away.
pub def Atp.redirect_uri (origin : String) : String :=
    String.concat origin "/"

/// The hosted `client_id` for an origin: the URL of the metadata document.
pub def Atp.hosted_client_id (origin : String) : String :=
    String.concat origin "/client-metadata.json"

/// The client-metadata document, as JSON text.
///
/// `client_id` is passed in rather than derived, because for a public web
/// client it must be the URL this document is served from, and only the caller
/// knows that (it is `window.location.origin`-derived, or a localhost URL in
/// dev).
pub def Atp.client_metadata (cfg : Atp.ClientConfig) (client_id : String) (redirect_uri : String)
    : String :=
    String.concat_list [
        "{\"client_id\":", Atp.json_str client_id,
        ",\"client_name\":", Atp.json_str cfg.name,
        ",\"application_type\":\"web\"",
        ",\"grant_types\":[\"authorization_code\",\"refresh_token\"]",
        ",\"response_types\":[\"code\"]",
        ",\"scope\":", Atp.json_str cfg.scope,
        ",\"redirect_uris\":[", Atp.json_str redirect_uri, "]",
        ",\"dpop_bound_access_tokens\":true",
        ",\"token_endpoint_auth_method\":\"none\"",
        "}",
    ]

/// A loopback client for `monad script dev`, where the page origin is
/// `http://127.0.0.1:<port>` and there is no hosted document. atproto allows
/// the `http://localhost?redirect_uri=...&scope=...` client-id form for
/// exactly this case, and it is deliberately a different function so it cannot
/// be reached in production by accident.
pub def Atp.loopback_client_id (scope : String) (redirect_uri : String) : String :=
    String.concat_list ["http://localhost?redirect_uri=", Atp.url_encode redirect_uri,
        "&scope=", Atp.url_encode scope]

// ── The JWK thumbprint (RFC 7638) ───────────────────────────────────────

/// The canonical JWK: exactly `crv`, `kty`, `x`, `y` in lexicographic order
/// with no whitespace. This byte string is what gets hashed, so any deviation
/// (a extra member, a different order) yields a different `jkt` and the token
/// endpoint refuses the proof.
#[terminating]
def Atp.jwk_thumbprint_go (frags : List String) (acc : String) : String :=
    match frags {
        List.empty => String.concat acc "}",
        List.cons f rest =>
            let next : String :=
                if String.is_empty acc then String.concat "{" f
                else String.concat acc (String.concat "," f) in
            Atp.jwk_thumbprint_go rest next,
    }

/// `base64url(SHA-256(canonical JWK))` from the four members.
///
/// The members are passed separately rather than parsed out of the exported
/// JSON, so the canonical form cannot accidentally inherit key order or
/// whitespace from the host's serialiser.
pub def Atp.jwk_thumbprint (x : String) (y : String) : String :=
    let crv : String := String.concat_list ["\"crv\":", Atp.json_str "P-256"] in
    let kty : String := String.concat_list ["\"kty\":", Atp.json_str "EC"] in
    let xf : String := String.concat_list ["\"x\":", Atp.json_str x] in
    let yf : String := String.concat_list ["\"y\":", Atp.json_str y] in
    Atp.s256 (Atp.jwk_thumbprint_go [crv, kty, xf, yf] "")

/// A JWK parsed out of the host's exported JSON, for callers that have the
/// whole document. An `EC`/`P-256` key must carry both coordinates; a missing
/// one is an error rather than a thumbprint of empty strings, which would
/// silently produce a wrong `jkt`.
pub def Atp.jwk_xy (jwk_json : String) : Result String (Pair String String) :=
    match Json.parse jwk_json {
        Result.err e =>
            Result.err (String.concat "the exported JWK is not JSON: "
                (Json.ParseError.to_string e)),
        Result.ok j =>
            match Atp.str_field "JWK" "crv" j {
                Result.err e => Result.err e,
                Result.ok crv =>
                    if Bool.not (String.beq crv "P-256")
                    then Result.err (String.concat_list [
                        "the exported JWK is on curve `", crv, "`, not P-256"])
                    else match Atp.str_field "JWK" "x" j {
                        Result.err e => Result.err e,
                        Result.ok x => match Atp.str_field "JWK" "y" j {
                            Result.err e => Result.err e,
                            Result.ok y => Result.ok (Pair.pair x y),
                        },
                    },
            },
    }

/// A private scalar must never appear in an exported public JWK. The host
/// exports a non-extractable key as public-only, so this is an assertion about
/// the host rather than a filter: if it ever fails, the key material has
/// escaped into wasm memory and every stored session is compromised.
pub def Atp.jwk_is_public (jwk_json : String) : Bool :=
    match Json.parse jwk_json {
        Result.err _ => false,
        Result.ok j => match Atp.opt_str_field "d" j {
            Option.some _ => false,
            Option.none => true,
        },
    }
