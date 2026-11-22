// The atproto login machine: its types, its state, and its transitions.
//
// PURE, and deliberately so. It imports `web_wasm::types` only for the OPAQUE
// HANDLE DECLARATIONS (`CryptoOp`, `WebKey`, `RequestId`) -- no extern, no IO --
// which is what lets the app's model hold the machine and still build for the
// native test driver. (Verified: a pure module that imports `web_wasm::types`
// and stores those handles in `Option`s is importable from a native `monad
// test` file, because an import is per-declaration and `types.mo` declares no
// extern.)
//
// The machine therefore lives in the MODEL, the Elm-Architecture way, rather
// than in `web_wasm::Keep`. Two reasons that is the right home:
//
//  - `Keep` holds ONE word and the Oak runtime already owns it for its own
//    state slot.
//  - The handles survive across ticks in ordinary wasm memory, so nothing is
//    fabricated and nothing is serialised.
//
// The driver (`atproto_web::web`) is the only module that ADVANCES the
// machine, because advancing needs IO. It is reached from the Oak update loop
// through effects: an effect carries the machine, the host runs one step, and a
// message carries the machine back.

use web_wasm::types {CryptoOp, WebKey, RequestId}
use atproto_oauth::oauth {Atp.PendingLogin, Atp.Session}
use atproto_oauth::persist {atp_no_pending, atp_no_session}
use atproto_repo::records {Atp.Fetched}
use atproto_oauth::client_metadata {Atp.ClientConfig}

/// What an in-flight fetch will do with its body.
pub type Atp.FetchKind {
    /// The `_atproto.<handle>` TXT record over DNS-over-HTTPS.
    adk_fetch_dns_txt (handle : String),
    adk_fetch_well_known (handle : String),
    adk_fetch_resolve_handle (handle : String),
    adk_fetch_did_doc (did : String) (handle : String),
    adk_fetch_resource_meta (did : String) (handle : String),
    adk_fetch_as_meta (did : String) (handle : String) (issuer : String),
    /// The PAR response. `nonce` is the DPoP nonce this attempt carried, so a
    /// retry is distinguishable from the first attempt.
    adk_fetch_par (nonce : String),
    /// The token exchange, first attempt or retry.
    adk_fetch_token (nonce : String),
    /// `com.atproto.repo.getRecord` for one record (no auth).
    adk_fetch_get_record,
    /// `com.atproto.repo.putRecord`, first attempt or the nonce retry.
    adk_fetch_put_record (nonce : String),
    /// A refresh-token grant, first attempt or the nonce retry.
    adk_fetch_refresh (nonce : String),
    /// The sign-out revocation (RFC 7009), first attempt or the nonce retry.
    adk_fetch_revoke (nonce : String),
}

/// What a completed signature is FOR.
pub type Atp.SignKind {
    adk_sign_par (jwk : String) (nonce : String),
    adk_sign_token (nonce : String),
    adk_sign_put (nonce : String),
    adk_sign_refresh (nonce : String),
    adk_sign_revoke (nonce : String),
}

/// Where the machine is. One constructor per host operation being waited on, so
/// the poll function knows which operation to read.
pub type Atp.Step {
    adk_step_idle,
    adk_step_fetching (kind : Atp.FetchKind),
    adk_step_keygen,
    adk_step_export_jwk,
    adk_step_key_store (jwk : String),
    /// Restoring the DPoP key from IndexedDB, on the way to the token exchange.
    adk_step_key_get (code : String) (nonce : String),
    adk_step_signing (kind : Atp.SignKind),
    /// Loading the session's DPoP key from IndexedDB before a repo write.
    adk_step_key_load,
    /// Loading the session's DPoP key to sign the sign-out revocation.
    adk_step_revoke_key_load,
    /// Deleting the session's DPoP key from IndexedDB, the last sign-out step.
    adk_step_key_delete,
}

/// The machine's terminal result.
pub type Atp.Done {
    adk_done_signed_in (session : Atp.Session),
    /// The login did not finish, but the app is still usable.
    adk_done_notice (message : String),
    /// The record was read: `none` when the repo has none yet.
    adk_done_pulled (fetched : Option Atp.Fetched),
    /// The record was written. The session may carry rotated tokens.
    adk_done_pushed (session : Atp.Session) (cid : String),
    /// Another device wrote first (`swapRecord` lost): pull, merge, retry.
    adk_done_conflict (session : Atp.Session),
    /// The session cannot be used any more (refresh refused, key gone).
    adk_done_expired (message : String),
    /// Sign-out finished: the grant was revoked where possible and the key
    /// deleted. Reached even when revocation failed (see `Atp.step`).
    adk_done_signed_out,
}

/// What one step tells the caller to do.
pub type Atp.Outcome {
    adk_out_pending,
    /// The pending login is persisted: navigate here.
    adk_out_redirect (url : String),
    adk_out_done (msg : Atp.Done),
    adk_out_failed (message : String),
}

/// The machine's whole state.
///
/// The accumulators are plain fields rather than being threaded through the
/// step variants: a step is re-entered every tick, and a variant carrying them
/// would have to be rebuilt from the state each time.
pub struct Atp.State {
    /// The app's client configuration (scope, name, storage keys). Set by the
    /// entry points that need it (`Atp.begin_sign_in`, `Atp.finish_auth`) and
    /// carried through every step of that flow.
    config : Atp.ClientConfig,
    step : Atp.Step,
    request : Option RequestId,
    crypto : Option CryptoOp,
    key : Option WebKey,
    /// The DPoP key's slot in `KeyStore`: the DID, so one browser can hold
    /// several accounts' keys.
    slot : String,
    /// The public JWK and its RFC 7638 thumbprint (`dpop_jkt`).
    jwk : String,
    jkt : String,
    /// The DPoP nonce last seen for the endpoint in play.
    nonce : String,
    /// The authorize URL, built at PAR.
    auth_url : String,
    /// The pending login, complete once the endpoints and the key are known.
    pending : Atp.PendingLogin,
    /// The callback code, held between the token attempt and its retry.
    code : String,
    /// The signing input `sign_begin` was called with, so `assemble` appends to
    /// exactly those bytes.
    signing : String,
    /// The PAR endpoint, and the authorization server's issuer.
    par_url : String,
    issuer : String,
    did : String,
    /// The PDS from the DID document: the protected resource, and later the
    /// host every repo call goes to.
    pds : String,
    /// The authorization server's `authorization_endpoint`, for the redirect.
    authorize_endpoint : String,
    /// The signed-in session, for the repo calls (blank during a login).
    session : Atp.Session,
    /// The `putRecord` request body, built when the push began.
    put_body : String,
    /// A 401 has already been answered with a refresh, so a second one ends
    /// the session instead of looping.
    retried : Bool,
    /// This machine is a sign-out: every failure still ends in
    /// `adk_done_signed_out`, after deleting the key.
    revoking : Bool,
}

/// The starting machine.
pub def Atp.blank : Atp.State := {
    config := { name := "", scope := "", storage_prefix := "" },
    step := Atp.Step.adk_step_idle,
    request := Option.none,
    crypto := Option.none,
    key := Option.none,
    slot := "",
    jwk := "",
    jkt := "",
    nonce := "",
    auth_url := "",
    pending := atp_no_pending,
    code := "",
    signing := "",
    par_url := "",
    issuer := "",
    did := "",
    pds := "",
    authorize_endpoint := "",
    session := atp_no_session,
    put_body := "",
    retried := false,
    revoking := false,
}

/// The starting machine for a flow run on behalf of `cfg`.
pub def Atp.fresh (cfg : Atp.ClientConfig) : Atp.State := { Atp.blank with config := cfg }

/// Is a flow in progress?
pub def Atp.busy (st : Atp.State) : Bool :=
    match st.step {
        Atp.Step.adk_step_idle => false,
        _ => true,
    }

/// Is the machine waiting on a fetch? (The alternative is a WebCrypto op.)
pub def Atp.waiting_on_fetch (st : Atp.State) : Bool :=
    match st.step {
        Atp.Step.adk_step_fetching _ => true,
        _ => false,
    }
