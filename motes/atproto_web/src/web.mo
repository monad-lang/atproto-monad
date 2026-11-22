// The atproto login, driven on `web_wasm`: the "web driver" that
// `plans/library-ideas/atproto.md` Phase 2b leaves unwritten.
//
// Everything here is a begin/poll STEP, never a loop. Two reasons:
//
//  1. WebCrypto and `fetch` are promise-based, and a promise callback must not
//     re-enter wasm while a Monad frame is on the stack
//     (`motes/web_wasm/src/fetch.mo`'s header). `Crypto.await_op` exists for a
//     caller with no frame loop, but in a browser its budget can only run out.
//  2. The wasm heap never frees (GAPS.md §10), so a spinning step would
//     allocate its way to the 2 GB wall.
//
// `Atp.step` advances the machine one step per call, driven by the Oak update
// loop. The machine (`Atp.State`) lives in the app's model, NOT in `Keep`: `Keep`
// is one word and the Oak runtime owns it.
//
// Handles are `Option`s and start at `none`. An opaque extern value has no
// source-level constructor (`#[opaque]` witnesses are unreferenceable), so a
// state that has not started an op genuinely has no handle; `Option.none` says
// that, where a fabricated placeholder would lie.
//
// Language notes this file learned the hard way (each reproduced against the
// self-hosted parser, and relevant to anyone writing driver code):
//
//  - Inside `do { ... }`, a `let` takes `;`, NOT `in` (`let x := v in` is a
//    parse error there). Outside `do`, `in` is required.
//  - An integer literal is not a valid match pattern (`0i64 => ...` does not
//    parse), and a match on `I64` is rejected anyway ("opaque type ... no
//    constructor to dispatch on"). Integer dispatch is an `if` chain.
//  - A definition must appear BEFORE its first use: no forward references.

use web_wasm::fetch {
    Fetch.begin_with, Fetch.poll, Fetch.status, Fetch.read, Fetch.response_headers,
}
use web_wasm::crypto {
    Crypto.random_bytes, Crypto.poll, Crypto.result_hex, Crypto.op_key,
    WebCrypto.generate_key_begin, WebCrypto.export_public_jwk_begin,
    WebCrypto.sign_begin,
}
use web_wasm::keystore {KeyStore.put_begin, KeyStore.get_begin, KeyStore.delete_begin}
use web_wasm::storage {Storage.get, Storage.set, Storage.remove}
use web_wasm::window {Window.origin, Window.search_param, Window.replace}
use web_wasm::clock {Clock.now_ms}
use web_wasm::types {CryptoOp, WebKey, RequestId}
use std::bytebuf {ByteBuf, ByteBuf.of_string, ByteBuf.free}
use std::hex {Hex.decode}
use std::base64 {B64Url.encode}
use json::json {Json}

use lib::machine {
    Atp.State, Atp.Step, Atp.FetchKind, Atp.SignKind, Atp.Outcome, Atp.Done,
    Atp.blank, Atp.fresh, Atp.busy, Atp.waiting_on_fetch,
}
use atproto_oauth::oauth {
    Atp.PendingLogin, Atp.Session, Atp.Callback, Atp.AsMetadata,
    Atp.as_metadata, Atp.as_supports_es256, Atp.resource_metadata,
    Atp.par_body, Atp.par_request_uri, Atp.authorize_url, Atp.callback,
    Atp.check_callback, Atp.token_body, Atp.token_response, Atp.refresh_body,
    Atp.refresh_response, Atp.revoke_body,
}
use atproto_repo::records {
    Atp.Fetched, Atp.fetched_of_body, Atp.is_record_not_found,
    Atp.is_invalid_swap, Atp.put_record_body, Atp.put_record_cid, Atp.get_record_url,
    Atp.put_record_url,
}
use atproto_common::json_read {Atp.parse_json}
use atproto_identity::identity {
    Atp.Identity, Atp.classify, Atp.did_document_url, Atp.DidDocument,
    Atp.did_document, Atp.claims_handle, Atp.resolve_handle_response,
    Atp.well_known_did, Atp.is_did, Atp.is_handle, Atp.doh_txt_url, Atp.doh_accept,
    Atp.doh_txt_did,
}
use atproto_oauth::dpop {
    Atp.DpopClaims, Atp.dpop_signing_input, Atp.htu, Atp.dpop_ath,
}
use atproto_common::jws {Atp.assemble}
use atproto_oauth::client_metadata {
    Atp.redirect_uri, Atp.loopback_client_id, Atp.hosted_client_id, Atp.ClientConfig, Atp.jwk_thumbprint, Atp.jwk_xy,
    Atp.jwk_is_public,
}
use atproto_oauth::persist {
    Atp.pending_key, Atp.session_key, Atp.pending_to_json, Atp.pending_of_json,
    Atp.session_to_json, Atp.session_of_json, Atp.needs_refresh,
}

// ── Types ───────────────────────────────────────────────────────────────
//
// The machine's types and state live in `atproto_web::machine`, which is PURE
// so the app's model can hold them. This module only ADVANCES it.

// ── Outcome helpers ─────────────────────────────────────────────────────

def atp_pending_state (st : Atp.State) : Pair Atp.State Atp.Outcome :=
    Pair.pair st Atp.Outcome.adk_out_pending

def atp_failed (st : Atp.State) (message : String) : Pair Atp.State Atp.Outcome :=
    Pair.pair st (Atp.Outcome.adk_out_failed message)

def atp_notice (st : Atp.State) (message : String) : Pair Atp.State Atp.Outcome :=
    Pair.pair st (Atp.Outcome.adk_out_done (Atp.Done.adk_done_notice message))

// ── Small helpers ───────────────────────────────────────────────────────

/// Header names are case-insensitive (RFC 7230 §3.2), and servers are
/// inconsistent about `DPoP-Nonce` vs `dpop-nonce`.
#[terminating]
def atp_find_header_ci (hs : List (Pair String String)) (name : String) : String :=
    match hs {
        List.empty => "",
        List.cons h rest => match h {
            Pair.pair k v =>
                if String.beq (atp_lower k) name then v else atp_find_header_ci rest name,
        },
    }

def atp_lower (s : String) : String :=
    String.from_list (List.map atp_lower_byte (String.to_list s))

def atp_lower_byte (b : U8) : U8 :=
    let c : I64 := U8.to_i64 b in
    if I64.gt c 64i64 && I64.lt c 91i64
    then U32.to_u8 (I64.to_u32 (I64.add c 32i64))
    else b

/// A short, single-line excerpt of a response body for a message. A server
/// error body can be long HTML; the message should stay readable.
def atp_short (body : String) : String :=
    let t : String := String.trim body in
    if I64.gt (String.length t) 160i64
    then String.concat (String.slice t 0i64 160i64) "..."
    else t

/// The `DPoP-Nonce` response header, or `""`.
def atp_nonce_of (hs : List (Pair String String)) : String :=
    atp_find_header_ci hs "dpop-nonce"

/// The DPoP nonce claim: `""` is "no nonce yet", which the pure builder turns
/// into an OMITTED claim (the server rejects a null one).
def atp_opt_nonce (s : String) : Option String :=
    if String.is_empty s then Option.none else Option.some s

/// Loopback is the one place a hosted metadata document does not exist.
/// atproto requires the loopback REDIRECT to name an IP, never `localhost`,
/// so only `127.0.0.1` qualifies; `begin_sign_in` turns a `localhost` page
/// away with a pointer to the right address.
def atp_is_loopback (origin : String) : Bool :=
    String.starts_with "http://127.0.0.1" origin

/// The client id and redirect URI for this page. A public web client's
/// `client_id` IS the URL its metadata document is served from, so on a real
/// origin it is the origin plus the document path; on loopback the
/// `http://localhost?redirect_uri=...` form stands in (atproto allows it for
/// dev, and it cannot be reached on https).
pub struct Atp.Client {
    client_id : String,
    redirect_uri : String,
}

pub def Atp.client_for (cfg : Atp.ClientConfig) (origin : String) : Atp.Client :=
    let redirect : String := Atp.redirect_uri origin in
    if atp_is_loopback origin
    then { client_id := Atp.loopback_client_id cfg.scope redirect, redirect_uri := redirect }
    else {
        client_id := Atp.hosted_client_id origin,
        redirect_uri := redirect,
    }

/// Fresh CSPRNG bytes, base64url, or `""` when the host has no entropy.
///
/// `""` is never acceptable for `state` or `jti` -- a guessable `state` is a
/// login-CSRF hole -- so every caller treats it as a failure.
def atp_random (n : I64) : IO String := do {
    let bytes <- Crypto.random_bytes n;
    match bytes {
        Result.ok bs => IO.pure (B64Url.encode bs),
        Result.err _ => IO.pure "",
    }
}

def atp_get (url : String) : IO RequestId :=
    Fetch.begin_with url 0i64 "" List.empty

/// The request headers a DPoP-authenticated request needs.
def atp_dpop_headers (proof : String) (token : Option String)
    : List (Pair String String) :=
    List.append
        [Pair.pair "Content-Type" "application/x-www-form-urlencoded",
            Pair.pair "DPoP" proof]
        (match token {
            Option.none => List.empty,
            Option.some t => [Pair.pair "Authorization" (String.concat "DPoP " t)],
        })

/// Poll the crypto op in flight, then run `on_done` (which reads the result).
/// A failure answers `what`; a still-pending op stays pending.
///
/// `poll` answers 0 = pending, 1 = done, 2 = failed. The keystore's `get` adds
/// a third completion state (3 = done and empty), so `get` has its own reader
/// elsewhere rather than sharing this one.
def atp_poll_crypto (st : Atp.State)
    (on_done : CryptoOp -> IO (Pair Atp.State Atp.Outcome)) (what : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match st.crypto {
        Option.none => IO.pure (atp_failed st "internal error: no crypto op to poll"),
        Option.some op => do {
            let state <- Crypto.poll op;
            if I64.beq state 0i64
            then IO.pure (atp_pending_state st)
            else if I64.beq state 1i64
            then on_done op
            else IO.pure (atp_notice st what)
        },
    }

// ── Starting a flow ─────────────────────────────────────────────────────

/// Begin sign-in for what the user typed.
///
/// The pending login is persisted later (at PAR): it is incomplete until the
/// DID, the endpoints and the key are known.
pub def Atp.begin_sign_in (cfg : Atp.ClientConfig) (input : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let origin <- Window.origin;
    if String.starts_with "http://localhost" origin
    then IO.pure (atp_failed (Atp.fresh cfg) (String.concat_list [
        "Sign-in needs the page opened at http://127.0.0.1",
        String.drop 16i64 origin, " (atproto does not allow a localhost redirect)"]))
    else Atp.classify_and_begin (Atp.fresh cfg) input
}

/// The handle's `_atproto` TXT record, over DNS-over-HTTPS: the spec's
/// primary resolution method, and the one that does not depend on which PDS
/// hosts the account or on the handle's domain allowing CORS.
def Atp.fetch_dns_txt (st : Atp.State) (handle : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let r <- Fetch.begin_with (Atp.doh_txt_url handle) 0i64 ""
        [Pair.pair "Accept" Atp.doh_accept];
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching (Atp.FetchKind.adk_fetch_dns_txt handle),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

def Atp.classify_and_begin (st : Atp.State) (input : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.classify input {
        Atp.Identity.adk_id_empty =>
            IO.pure (atp_failed st "Type a handle like alice.example"),
        Atp.Identity.adk_id_did did =>
            if Bool.not (Atp.is_did did)
            then IO.pure (atp_failed st
                (String.concat "That does not look like a DID: " did))
            else Atp.fetch_did_doc st did "",
        Atp.Identity.adk_id_handle handle =>
            if Bool.not (Atp.is_handle handle)
            then IO.pure (atp_failed st
                (String.concat "That does not look like a handle: " handle))
            else Atp.fetch_dns_txt st handle,
    }

/// The well-known endpoint, after the DNS record: a handle served over HTTP
/// (every PDS-hosted handle) has no TXT record.
def Atp.fetch_well_known (st : Atp.State) (handle : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let url : String := String.concat "https://"
        (String.concat handle "/.well-known/atproto-did");
    let r <- atp_get url;
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching
            (Atp.FetchKind.adk_fetch_well_known handle),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

def Atp.fetch_did_doc (st : Atp.State) (did : String) (handle : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let r <- atp_get (Atp.did_document_url did);
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching
            (Atp.FetchKind.adk_fetch_did_doc did handle),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

/// `com.atproto.identity.resolveHandle`. Used when the well-known endpoint is
/// unavailable, commonly because CORS blocks it on a custom domain -- the
/// documented limitation of a browser client.
def Atp.fetch_resolve_handle (st : Atp.State) (handle : String) (pds : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let url : String := String.concat_list [pds,
        "/xrpc/com.atproto.identity.resolveHandle?handle=", handle];
    let r <- atp_get url;
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching
            (Atp.FetchKind.adk_fetch_resolve_handle handle),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

def Atp.fetch_resource_meta (st : Atp.State) (did : String) (handle : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let url : String := String.concat st.pds "/.well-known/oauth-protected-resource";
    let r <- atp_get url;
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching
            (Atp.FetchKind.adk_fetch_resource_meta did handle),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

/// The authorization-server metadata, validated against the issuer the
/// protected-resource document named.
def Atp.fetch_as_meta (st : Atp.State) (did : String) (handle : String)
    (issuer : String) : IO (Pair Atp.State Atp.Outcome) := do {
    let r <- atp_get (String.concat issuer "/.well-known/oauth-authorization-server");
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching
            (Atp.FetchKind.adk_fetch_as_meta did handle issuer),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

// ── Key generation, JWK export, the key store ───────────────────────────

/// Generate the DPoP keypair. `state` and the PKCE verifier are drawn here too,
/// from the same CSPRNG, because they share the key's lifetime.
def Atp.start_keygen (st : Atp.State) (as : Atp.AsMetadata) (did : String)
    (handle : String) : IO (Pair Atp.State Atp.Outcome) := do {
    let issuer : String := as.issuer;
    let par_url : String := as.pushed_authorization_request_endpoint;
    let csrf <- atp_random 32i64;
    let verifier <- atp_random 32i64;
    if String.is_empty csrf || String.is_empty verifier
    then IO.pure (atp_notice st
        "This browser refused to generate secure random values, so a safe sign-in is not possible")
    else do {
        let origin <- Window.origin;
        let client : Atp.Client := Atp.client_for st.config origin;
        let pending : Atp.PendingLogin := {
            state := csrf,
            verifier := verifier,
            issuer := issuer,
            did := did,
            token_endpoint := as.token_endpoint,
            redirect_uri := client.redirect_uri,
            client_id := client.client_id,
            handle := handle,
            pds := st.pds,
            // Filled in once the key is exported (`post_par`).
            jwk := "",
            jkt := "",
            revocation_endpoint := as.revocation_endpoint,
        };
        let op <- WebCrypto.generate_key_begin;
        let next : Atp.State := {
            st with step := Atp.Step.adk_step_keygen,
                crypto := Option.some op, pending := pending,
                par_url := par_url, slot := did, issuer := issuer, did := did,
                authorize_endpoint := as.authorization_endpoint,
        };
        IO.pure (atp_pending_state next)
    }
}

/// Poll the keypair; on success export its public JWK.
def Atp.step_keygen (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    atp_poll_crypto st (fn (op : CryptoOp) => do {
        let k <- Crypto.op_key op;
        let eop <- WebCrypto.export_public_jwk_begin k;
        let next : Atp.State := {
            st with step := Atp.Step.adk_step_export_jwk,
                crypto := Option.some eop, key := Option.some k,
        };
        IO.pure (atp_pending_state next)
    }) "The browser could not create a signing key"

/// Poll the JWK export; on success check it is public-only, compute the
/// thumbprint (the `jkt` binding the code to this key) and store the key.
def Atp.step_export_jwk (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    atp_poll_crypto st (fn (op : CryptoOp) => do {
        let jwk_json <- Crypto.result_hex op;
        if Bool.not (Atp.jwk_is_public jwk_json)
        then IO.pure (atp_notice st
            "The exported key carried private material; refusing to continue")
        else
            match Atp.jwk_xy jwk_json {
                Result.err e => IO.pure (atp_notice st e),
                Result.ok xy => match xy {
                    Pair.pair x y => Atp.start_key_store st jwk_json
                        (Atp.jwk_thumbprint x y),
                },
            }
    }) "The browser could not export the public key"

/// Store the DPoP key in IndexedDB under the DID, so it survives the redirect.
///
/// The key is NON-EXTRACTABLE, so structured clone is the only thing that can
/// carry it -- which is why it does not go in `localStorage` with the pending
/// login. A failed put IS fatal: the key would not survive the redirect, and
/// the token exchange would then fail with an opaque `invalid_dpop_proof`.
def Atp.start_key_store (st : Atp.State) (jwk : String) (jkt : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match st.key {
        Option.none => IO.pure (atp_failed st "internal error: no key to store"),
        Option.some k => do {
            let op <- KeyStore.put_begin st.slot k;
            let next : Atp.State := {
                st with step := Atp.Step.adk_step_key_store jwk,
                    crypto := Option.some op, jkt := jkt,
            };
            IO.pure (atp_pending_state next)
        },
    }

/// Poll the key store put, then build and sign the PAR request.
def Atp.step_key_store (st : Atp.State) (jwk : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    atp_poll_crypto st (fn (_op : CryptoOp) => Atp.start_par st jwk "")
        "The browser refused to store the DPoP key, so the sign-in cannot survive the redirect"

// ── Signing ─────────────────────────────────────────────────────────────

/// Build the PAR proof, sign it, and POST the pushed authorization request.
///
/// `nonce` is `""` on the first attempt. A server that requires one answers
/// with an error plus a `DPoP-Nonce` header, and `after_par` retries once.
def Atp.start_par (st : Atp.State) (jwk : String) (nonce : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let jti <- atp_random 16i64;
    if String.is_empty jti
    then IO.pure (atp_notice st
        "This browser refused to generate secure random values, so a safe sign-in is not possible")
    else do {
        let now <- Clock.now_ms;
        let claims : Atp.DpopClaims := {
            htm := "POST",
            htu := Atp.htu st.par_url,
            iat := I64.div now 1000i64,
            jti := jti,
            iss := st.pending.client_id,
            nonce := atp_opt_nonce nonce,
            ath := Option.none,
        };
        Atp.sign_and_send st (Atp.dpop_signing_input jwk claims)
            (Atp.SignKind.adk_sign_par jwk nonce)
    }
}

/// Build the token-exchange proof, sign it, and POST the token request. The
/// proof carries `ath`: `base64url(SHA-256(access_token))` is meaningless here
/// (there is no token yet), so for the CODE exchange it is absent.
def Atp.start_token (st : Atp.State) (code : String) (nonce : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let jti <- atp_random 16i64;
    if String.is_empty jti
    then IO.pure (atp_notice st
        "This browser refused to generate secure random values, so a safe sign-in is not possible")
    else do {
        let now <- Clock.now_ms;
        let claims : Atp.DpopClaims := {
            htm := "POST",
            htu := Atp.htu st.pending.token_endpoint,
            iat := I64.div now 1000i64,
            jti := jti,
            iss := st.pending.client_id,
            nonce := atp_opt_nonce nonce,
            ath := Option.none,
        };
        Atp.sign_and_send st (Atp.dpop_signing_input st.jwk claims)
            (Atp.SignKind.adk_sign_token nonce)
    }
}

/// Sign `input` and remember what to do with the signature.
def Atp.sign_and_send (st : Atp.State) (input : String) (kind : Atp.SignKind)
    : IO (Pair Atp.State Atp.Outcome) :=
    match st.key {
        Option.none => IO.pure (atp_failed st "internal error: no key to sign with"),
        Option.some k => do {
            let buf <- ByteBuf.of_string input;
            let op <- WebCrypto.sign_begin k buf;
            let _ <- ByteBuf.free buf;
            let next : Atp.State := {
                st with step := Atp.Step.adk_step_signing kind,
                    crypto := Option.some op, signing := input,
            };
            IO.pure (atp_pending_state next)
        },
    }

/// Poll a signature, then act on it.
///
/// The signature arrives as hex; `Hex.decode` turns it back into the 64 raw
/// bytes the JWS needs. WebCrypto's ECDSA output is already IEEE P1363
/// `r ‖ s` -- the JWS form -- so no DER conversion is involved.
def Atp.step_sign (st : Atp.State) (kind : Atp.SignKind)
    : IO (Pair Atp.State Atp.Outcome) :=
    atp_poll_crypto st (fn (op : CryptoOp) => do {
        let sig_hex <- Crypto.result_hex op;
        match Hex.decode sig_hex {
            Result.err _ => IO.pure (atp_notice st "The browser produced an unreadable signature"),
            Result.ok sig_bytes => match Atp.assemble st.signing sig_bytes {
                Result.err e => IO.pure (atp_notice st e),
                Result.ok proof => Atp.after_sign st kind proof,
            },
        }
    }) "The browser could not sign the request"

// ── Repo sync: read, refresh, write ─────────────────────────────────────
//
// The same begin/poll shape as the login. Pulling is an unauthenticated GET;
// pushing loads the session's DPoP key from IndexedDB, refreshes the access
// token if it is due, then `putRecord`s with a proof bound to the token
// (`ath`). Merging is NOT done here: the app owns its data, so a get hands
// the remote record back and the app decides what to put.

/// JSON request headers with DPoP auth (the form variant is for OAuth).
def atp_dpop_json_headers (proof : String) (token : String) : List (Pair String String) :=
    [Pair.pair "Content-Type" "application/json",
        Pair.pair "DPoP" proof,
        Pair.pair "Authorization" (String.concat "DPoP " token)]

def atp_expired (st : Atp.State) (message : String) : Pair Atp.State Atp.Outcome :=
    Pair.pair { st with step := Atp.Step.adk_step_idle }
        (Atp.Outcome.adk_out_done (Atp.Done.adk_done_expired message))

def atp_done (st : Atp.State) (d : Atp.Done) : Pair Atp.State Atp.Outcome :=
    Pair.pair { st with step := Atp.Step.adk_step_idle } (Atp.Outcome.adk_out_done d)

/// Read `collection`/`rkey` from the signed-in account's repo. `getRecord` on
/// a public repo needs no auth, so no key is loaded. Ends in
/// `adk_done_pulled` (`none` when there is no such record yet).
pub def Atp.begin_get_record (s : Atp.Session) (collection : String) (rkey : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let r <- atp_get (Atp.get_record_url s.pds s.did collection rkey);
    let st : Atp.State := {
        Atp.blank with step := Atp.Step.adk_step_fetching Atp.FetchKind.adk_fetch_get_record,
            request := Option.some r, session := s, did := s.did, pds := s.pds,
    };
    IO.pure (atp_pending_state st)
}

def Atp.after_get_record (st : Atp.State) (status : I64) (body : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    if I64.beq status 200i64
    then match Atp.fetched_of_body body {
        Result.ok f => IO.pure (atp_done st (Atp.Done.adk_done_pulled (Option.some f))),
        Result.err e => IO.pure (atp_notice st e),
    }
    else if Atp.is_record_not_found status body
    then IO.pure (atp_done st (Atp.Done.adk_done_pulled Option.none))
    else IO.pure (atp_notice st
        (String.concat_list ["Could not read the record (HTTP ", I64.to_string status, ")"]))

/// Write `record` to `collection`/`rkey` in the signed-in account's repo.
/// `swap` is the CID the app last read (`swapRecord`): a write that loses the
/// race ends in `adk_done_conflict`, so the app can re-read, merge and retry.
/// The token is refreshed first when due, and once more on a dead-token 401.
pub def Atp.begin_put_record (s : Atp.Session) (collection : String) (rkey : String)
    (record : Json) (swap : Option String) : IO (Pair Atp.State Atp.Outcome) := do {
    let body : String := Atp.put_record_body s.did collection rkey record swap;
    let op <- KeyStore.get_begin s.did;
    let st : Atp.State := {
        Atp.blank with step := Atp.Step.adk_step_key_load,
            crypto := Option.some op, session := s, did := s.did, pds := s.pds,
            jwk := s.jwk, jkt := s.jkt, slot := s.did, issuer := s.issuer,
            put_body := body,
    };
    IO.pure (atp_pending_state st)
}

/// Build, sign and send the refresh grant's proof.
def Atp.start_refresh (st : Atp.State) (nonce : String) : IO (Pair Atp.State Atp.Outcome) := do {
    let jti <- atp_random 16i64;
    if String.is_empty jti
    then IO.pure (atp_notice st "This browser refused to generate secure random values")
    else do {
        let now <- Clock.now_ms;
        let claims : Atp.DpopClaims := {
            htm := "POST",
            htu := Atp.htu st.session.token_endpoint,
            iat := I64.div now 1000i64,
            jti := jti,
            iss := st.session.client_id,
            nonce := atp_opt_nonce nonce,
            ath := Option.none,
        };
        Atp.sign_and_send st (Atp.dpop_signing_input st.jwk claims)
            (Atp.SignKind.adk_sign_refresh nonce)
    }
}

/// Build, sign and send the `putRecord` proof, bound to the access token.
def Atp.start_put (st : Atp.State) (nonce : String) : IO (Pair Atp.State Atp.Outcome) := do {
    let jti <- atp_random 16i64;
    if String.is_empty jti
    then IO.pure (atp_notice st "This browser refused to generate secure random values")
    else do {
        let now <- Clock.now_ms;
        let claims : Atp.DpopClaims := {
            htm := "POST",
            htu := Atp.htu (Atp.put_record_url st.pds),
            iat := I64.div now 1000i64,
            jti := jti,
            iss := st.session.client_id,
            nonce := atp_opt_nonce nonce,
            ath := Option.some (Atp.dpop_ath st.session.access_token),
        };
        Atp.sign_and_send st (Atp.dpop_signing_input st.jwk claims)
            (Atp.SignKind.adk_sign_put nonce)
    }
}

/// With the key in hand: refresh first if the token is (nearly) expired.
def Atp.continue_push (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) := do {
    let now <- Clock.now_ms;
    if Atp.needs_refresh now st.session
    then Atp.start_refresh st ""
    else Atp.start_put st ""
}

/// Poll the key load. State 3 (an empty slot) means this browser no longer has
/// the key the tokens are bound to, so the session is unusable.
def Atp.step_key_load (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    match st.crypto {
        Option.none => IO.pure (atp_failed st "internal error: no key op to poll"),
        Option.some op => do {
            let state <- Crypto.poll op;
            if I64.beq state 0i64
            then IO.pure (atp_pending_state st)
            else if I64.beq state 1i64
            then do {
                let k <- Crypto.op_key op;
                let with_key : Atp.State := { st with key := Option.some k };
                Atp.continue_push with_key
            }
            else if I64.beq state 3i64
            then IO.pure (atp_expired st
                "Signed out: this browser no longer has the sign-in key. Sign in again to sync.")
            else IO.pure (atp_notice st "The browser refused to read the sign-in key")
        },
    }

def Atp.post_refresh (st : Atp.State) (nonce : String) (proof : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match st.session.refresh_token {
        Option.none => IO.pure (atp_expired st "Signed out: the session expired. Sign in again to sync."),
        Option.some rt => do {
            let body : String := Atp.refresh_body st.session.client_id rt;
            let r <- Fetch.begin_with st.session.token_endpoint 1i64 body
                (atp_dpop_headers proof Option.none);
            let next : Atp.State := {
                st with step := Atp.Step.adk_step_fetching (Atp.FetchKind.adk_fetch_refresh nonce),
                    request := Option.some r, crypto := Option.none,
            };
            IO.pure (atp_pending_state next)
        },
    }

def Atp.post_put (st : Atp.State) (nonce : String) (proof : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let r <- Fetch.begin_with (Atp.put_record_url st.pds) 1i64 st.put_body
        (atp_dpop_json_headers proof st.session.access_token);
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching (Atp.FetchKind.adk_fetch_put_record nonce),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

def Atp.after_refresh (st : Atp.State) (status : I64) (nonce_in : String) (nonce : String)
    (body : String) : IO (Pair Atp.State Atp.Outcome) := do {
    let now <- Clock.now_ms;
    match Atp.refresh_response st.session now body {
        Result.ok s => do {
            let next : Atp.State := { st with session := s };
            Atp.start_put next ""
        },
        Result.err _ =>
            if String.is_empty nonce_in && Bool.not (String.is_empty nonce)
                && String.contains body "use_dpop_nonce"
            then Atp.start_refresh st nonce
            else if I64.beq status 400i64 || I64.beq status 401i64
            then IO.pure (atp_expired st "Signed out: the session expired. Sign in again to sync.")
            else IO.pure (atp_notice st
                (String.concat_list ["Could not refresh the session (HTTP ",
                    I64.to_string status, ")"])),
    }
}

def Atp.after_put (st : Atp.State) (status : I64) (nonce_in : String) (nonce : String)
    (body : String) : IO (Pair Atp.State Atp.Outcome) :=
    if I64.beq status 200i64
    then
        let cid : String :=
            match Atp.put_record_cid body {
                Option.some c => c,
                Option.none => "",
            } in
        IO.pure (atp_done st (Atp.Done.adk_done_pushed st.session cid))
    else if Atp.is_invalid_swap status body
    then IO.pure (atp_done st (Atp.Done.adk_done_conflict st.session))
    else if I64.beq status 401i64
    then
        // A resource server asks for a nonce with 401 + `DPoP-Nonce`; any
        // other 401 is a dead access token, which one refresh may revive.
        if String.is_empty nonce_in && Bool.not (String.is_empty nonce)
        then Atp.start_put st nonce
        else if Bool.not st.retried
        then
            let again : Atp.State := { st with retried := true } in
            Atp.start_refresh again ""
        else IO.pure (atp_expired st "Signed out: the session expired. Sign in again to sync.")
    else IO.pure (atp_notice st
        (String.concat_list ["Could not save the record (HTTP ", I64.to_string status,
            "): ", atp_short body]))

def Atp.after_sign (st : Atp.State) (kind : Atp.SignKind) (proof : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match kind {
        Atp.SignKind.adk_sign_par jwk nonce => Atp.post_par st jwk nonce proof,
        Atp.SignKind.adk_sign_token nonce => Atp.post_token st nonce proof,
        Atp.SignKind.adk_sign_put nonce => Atp.post_put st nonce proof,
        Atp.SignKind.adk_sign_refresh nonce => Atp.post_refresh st nonce proof,
        Atp.SignKind.adk_sign_revoke nonce => Atp.post_revoke st nonce proof,
    }

/// POST the PAR request and wait for its `request_uri`.
def Atp.post_par (st : Atp.State) (jwk : String) (nonce : String) (proof : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let body : String := Atp.par_body st.pending.client_id st.pending.redirect_uri
        st.config.scope st.pending.state st.pending.verifier st.jkt;
    let r <- Fetch.begin_with st.par_url 1i64 body (atp_dpop_headers proof Option.none);
    // Persist the pending login NOW: the next step navigates away, and the
    // callback cannot reconstruct the state, the verifier, the endpoints or
    // the public half of the key.
    let base : Atp.PendingLogin := st.pending;
    let pending : Atp.PendingLogin := { base with jwk := jwk, jkt := st.jkt };
    let _ <- Storage.set (Atp.pending_key st.config.storage_prefix) (Atp.pending_to_json pending);
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching (Atp.FetchKind.adk_fetch_par nonce),
            request := Option.some r, crypto := Option.none, jwk := jwk,
            pending := pending,
    };
    IO.pure (atp_pending_state next)
}

/// POST the token exchange with a DPoP proof.
def Atp.post_token (st : Atp.State) (nonce : String) (proof : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let body : String := Atp.token_body st.pending.client_id st.pending.redirect_uri
        st.code st.pending.verifier;
    let r <- Fetch.begin_with st.pending.token_endpoint 1i64 body
        (atp_dpop_headers proof Option.none);
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching (Atp.FetchKind.adk_fetch_token nonce),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

// ── Sign-out: revoke, then forget the key ───────────────────────────────
//
// The caller has already removed the stored session, so the user is signed
// out locally whatever happens here. This is the server half: revoke the
// grant at the AS's `revocation_endpoint` (RFC 7009, with a DPoP proof, which
// the atproto AS expects on every token-endpoint-family request), then delete
// the DPoP key from IndexedDB. Both are best-effort: `Atp.step` turns any
// failure into "delete the key, then done", so sign-out never shows an error.

/// Start signing out of `s`. With no revocation endpoint (an AS that names
/// none, or a session stored before this existed), only the key is deleted.
pub def Atp.begin_sign_out (s : Atp.Session) : IO (Pair Atp.State Atp.Outcome) := do {
    let base : Atp.State := {
        Atp.blank with session := s, did := s.did, slot := s.did, jwk := s.jwk,
            jkt := s.jkt, issuer := s.issuer, pds := s.pds, revoking := true,
    };
    if String.is_empty s.revocation_endpoint
    then Atp.start_key_delete base
    else do {
        let op <- KeyStore.get_begin s.did;
        let next : Atp.State := {
            base with step := Atp.Step.adk_step_revoke_key_load, crypto := Option.some op,
        };
        IO.pure (atp_pending_state next)
    }
}

/// Delete the session's key. `delete_begin` succeeds on an empty slot too.
def Atp.start_key_delete (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) := do {
    let op <- KeyStore.delete_begin st.slot;
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_key_delete, crypto := Option.some op,
            request := Option.none, key := Option.none,
    };
    IO.pure (atp_pending_state next)
}

/// Poll the delete; done either way (a key the browser refused to delete is
/// still unusable without the revoked tokens).
def Atp.step_key_delete (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    match st.crypto {
        Option.none => IO.pure (atp_signed_out_done),
        Option.some op => do {
            let state <- Crypto.poll op;
            if I64.beq state 0i64
            then IO.pure (atp_pending_state st)
            else IO.pure (atp_signed_out_done)
        },
    }

def atp_signed_out_done : Pair Atp.State Atp.Outcome :=
    Pair.pair Atp.blank (Atp.Outcome.adk_out_done Atp.Done.adk_done_signed_out)

/// Poll the key load for the revocation proof. Without the key (empty slot or
/// a refused read) the grant cannot be revoked from here; delete and finish.
def Atp.step_revoke_key_load (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    match st.crypto {
        Option.none => Atp.start_key_delete st,
        Option.some op => do {
            let state <- Crypto.poll op;
            if I64.beq state 0i64
            then IO.pure (atp_pending_state st)
            else if I64.beq state 1i64
            then do {
                let k <- Crypto.op_key op;
                let with_key : Atp.State := { st with key := Option.some k };
                Atp.start_revoke with_key ""
            }
            else Atp.start_key_delete st
        },
    }

/// Build and sign the revocation proof (no `ath`: the token is in the body,
/// not presented as authorization).
def Atp.start_revoke (st : Atp.State) (nonce : String) : IO (Pair Atp.State Atp.Outcome) := do {
    let jti <- atp_random 16i64;
    if String.is_empty jti
    then Atp.start_key_delete st
    else do {
        let now <- Clock.now_ms;
        let claims : Atp.DpopClaims := {
            htm := "POST",
            htu := Atp.htu st.session.revocation_endpoint,
            iat := I64.div now 1000i64,
            jti := jti,
            iss := st.session.client_id,
            nonce := atp_opt_nonce nonce,
            ath := Option.none,
        };
        Atp.sign_and_send st (Atp.dpop_signing_input st.jwk claims)
            (Atp.SignKind.adk_sign_revoke nonce)
    }
}

def Atp.post_revoke (st : Atp.State) (nonce : String) (proof : String)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let body : String := Atp.revoke_body st.session.client_id st.session;
    let r <- Fetch.begin_with st.session.revocation_endpoint 1i64 body
        (atp_dpop_headers proof Option.none);
    let next : Atp.State := {
        st with step := Atp.Step.adk_step_fetching (Atp.FetchKind.adk_fetch_revoke nonce),
            request := Option.some r, crypto := Option.none,
    };
    IO.pure (atp_pending_state next)
}

/// RFC 7009 answers 200 for a revoked (or already invalid) token. A first
/// attempt refused for a missing DPoP nonce is retried once with it; anything
/// else gives up on the server half and deletes the key.
def Atp.after_revoke (st : Atp.State) (status : I64) (nonce_in : String) (nonce : String)
    (body : String) : IO (Pair Atp.State Atp.Outcome) :=
    if I64.beq status 200i64
    then Atp.start_key_delete st
    else if String.is_empty nonce_in && Bool.not (String.is_empty nonce)
        && String.contains body "use_dpop_nonce"
    then Atp.start_revoke st nonce
    else Atp.start_key_delete st

// ── The step dispatcher ─────────────────────────────────────────────────

/// Advance the machine by one step. Every branch either starts the next
/// operation (answering `pending`) or is terminal, so a caller that keeps
/// polling after completion sees the same result, not a second redirect.
///
/// A sign-out machine (`revoking`) never surfaces a failure: one that fails
/// before the key delete goes on to delete the key, and one that fails at the
/// delete is simply done.
pub def Atp.step (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    if st.revoking then Atp.step_sign_out st else Atp.step_any st

def Atp.step_sign_out (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) := do {
    let pair <- Atp.step_any st;
    match pair {
        Pair.pair next outcome => match outcome {
            Atp.Outcome.adk_out_pending =>
                IO.pure (Pair.pair next Atp.Outcome.adk_out_pending),
            Atp.Outcome.adk_out_done d => match d {
                Atp.Done.adk_done_signed_out => IO.pure atp_signed_out_done,
                _ => Atp.sign_out_failed st,
            },
            _ => Atp.sign_out_failed st,
        },
    }
}

def Atp.sign_out_failed (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    match st.step {
        Atp.Step.adk_step_key_delete => IO.pure atp_signed_out_done,
        _ => Atp.start_key_delete st,
    }

def Atp.step_any (st : Atp.State) : IO (Pair Atp.State Atp.Outcome) :=
    match st.step {
        Atp.Step.adk_step_idle =>
            IO.pure (atp_failed st "No sign-in is in progress"),
        Atp.Step.adk_step_fetching kind => Atp.step_fetch st kind,
        Atp.Step.adk_step_keygen => Atp.step_keygen st,
        Atp.Step.adk_step_export_jwk => Atp.step_export_jwk st,
        Atp.Step.adk_step_key_store jwk => Atp.step_key_store st jwk,
        Atp.Step.adk_step_key_get code nonce => Atp.step_key_get st code nonce,
        Atp.Step.adk_step_signing kind => Atp.step_sign st kind,
        Atp.Step.adk_step_key_load => Atp.step_key_load st,
        Atp.Step.adk_step_revoke_key_load => Atp.step_revoke_key_load st,
        Atp.Step.adk_step_key_delete => Atp.step_key_delete st,
    }

/// A fetch that never produced a response (offline, DNS, or CORS).
///
/// The well-known handle lookup is EXPECTED to fail this way on most custom
/// domains: the browser blocks the cross-origin read, which surfaces as a
/// failed fetch rather than a response. It falls back to `resolveHandle`, the
/// same as a response that is not a DID. Every other request failing this way
/// is a real failure.
def Atp.fetch_failed (st : Atp.State) (kind : Atp.FetchKind)
    : IO (Pair Atp.State Atp.Outcome) :=
    match kind {
        Atp.FetchKind.adk_fetch_dns_txt handle => Atp.fetch_well_known st handle,
        Atp.FetchKind.adk_fetch_well_known handle =>
            Atp.fetch_resolve_handle st handle "https://bsky.social",
        _ => IO.pure (atp_notice st "The request could not be sent (offline, or blocked)"),
    }

/// Poll the in-flight fetch: 0 = pending, 1 = done, 2 = failed.
def Atp.step_fetch (st : Atp.State) (kind : Atp.FetchKind)
    : IO (Pair Atp.State Atp.Outcome) :=
    match st.request {
        Option.none => IO.pure (atp_failed st "internal error: no fetch to poll"),
        Option.some r => do {
            let state <- Fetch.poll r;
            if I64.beq state 0i64
            then IO.pure (atp_pending_state st)
            else if I64.beq state 2i64
            then Atp.fetch_failed st kind
            else do {
                let status <- Fetch.status r;
                let hs <- Fetch.response_headers r;
                let body <- Fetch.read r 65536i64;
                Atp.handle_response st kind status (atp_nonce_of hs) body
            }
        },
    }

def Atp.handle_response (st : Atp.State) (kind : Atp.FetchKind) (status : I64)
    (nonce : String) (body : String) : IO (Pair Atp.State Atp.Outcome) :=
    match kind {
        Atp.FetchKind.adk_fetch_dns_txt handle =>
            Atp.after_dns_txt st handle body,
        Atp.FetchKind.adk_fetch_well_known handle =>
            Atp.after_well_known st handle body,
        Atp.FetchKind.adk_fetch_resolve_handle handle =>
            Atp.after_resolve_handle st handle body,
        Atp.FetchKind.adk_fetch_did_doc did handle =>
            Atp.after_did_doc st did handle body,
        Atp.FetchKind.adk_fetch_resource_meta did handle =>
            Atp.after_resource_meta st did handle body,
        Atp.FetchKind.adk_fetch_as_meta did handle issuer =>
            Atp.after_as_meta st did handle issuer body,
        Atp.FetchKind.adk_fetch_par nonce_in =>
            Atp.after_par st status nonce_in nonce body,
        Atp.FetchKind.adk_fetch_token nonce_in =>
            Atp.after_token st status nonce_in nonce body,
        Atp.FetchKind.adk_fetch_get_record => Atp.after_get_record st status body,
        Atp.FetchKind.adk_fetch_put_record nonce_in =>
            Atp.after_put st status nonce_in nonce body,
        Atp.FetchKind.adk_fetch_refresh nonce_in =>
            Atp.after_refresh st status nonce_in nonce body,
        Atp.FetchKind.adk_fetch_revoke nonce_in =>
            Atp.after_revoke st status nonce_in nonce body,
    }

def Atp.after_dns_txt (st : Atp.State) (handle : String) (body : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.doh_txt_did body {
        Result.ok did => Atp.fetch_did_doc st did handle,
        Result.err _ => Atp.fetch_well_known st handle,
    }

def Atp.after_well_known (st : Atp.State) (handle : String) (body : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.well_known_did body {
        Result.ok did => Atp.fetch_did_doc st did handle,
        // CORS, or no such file. The public entryway is the only host left
        // before the DID is known; the README names it as trusted.
        Result.err _ => Atp.fetch_resolve_handle st handle "https://bsky.social",
    }

def Atp.after_resolve_handle (st : Atp.State) (handle : String) (body : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.resolve_handle_response body {
        Result.ok did => Atp.fetch_did_doc st did handle,
        Result.err e => IO.pure (atp_notice st
            (String.concat_list ["Could not resolve ", handle, ": ", e])),
    }

/// The DID document arrived: take the PDS endpoint and verify the handle.
def Atp.after_did_doc (st : Atp.State) (did : String) (handle : String) (body : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.did_document did body {
        Result.err e => IO.pure (atp_notice st e),
        Result.ok doc => match doc.pds {
            Option.none => IO.pure (atp_notice st
                (String.concat_list ["The DID document for ", did,
                    " has no #atproto_pds service"])),
            Option.some pds =>
                // The bidirectional handle check, skipped when the user typed a
                // DID (there is no handle to check, so it may be "").
                if Bool.not (String.is_empty handle)
                    && Bool.not (Atp.claims_handle doc handle)
                then IO.pure (atp_notice st
                    (String.concat_list [did, " does not claim ", handle,
                        "; refusing to sign in (handle/DID mismatch)"]))
                else
                    let with_pds : Atp.State := { st with pds := pds } in
                    Atp.fetch_resource_meta with_pds did handle,
        },
    }

def Atp.after_resource_meta (st : Atp.State) (did : String) (handle : String)
    (body : String) : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.resource_metadata body {
        Result.err e => IO.pure (atp_notice st e),
        Result.ok issuer => Atp.fetch_as_meta st did handle issuer,
    }

def Atp.after_as_meta (st : Atp.State) (did : String) (handle : String)
    (issuer : String) (body : String) : IO (Pair Atp.State Atp.Outcome) := do {
    let url : String := String.concat issuer "/.well-known/oauth-authorization-server";
    match Atp.as_metadata url issuer body {
        Result.err e => IO.pure (atp_notice st e),
        Result.ok as =>
            if Bool.not (atp_offers_es256 body)
            then IO.pure (atp_notice st
                "That server does not offer ES256, the only DPoP algorithm this app signs with")
            else Atp.start_keygen st as did handle,
    }
}

/// Is ES256 offered? Re-parsed here so `Atp.AsMetadata` stays a record of
/// endpoints rather than also carrying a capability check.
def atp_offers_es256 (body : String) : Bool :=
    match Atp.parse_json "authorization server metadata" body {
        Result.err _ => false,
        Result.ok j => Atp.as_supports_es256 j,
    }

/// The PAR response. A `use_dpop_nonce` error means "retry with the nonce the
/// response just carried"; anything else is a real failure.
def Atp.after_par (st : Atp.State) (status : I64) (nonce_in : String) (nonce : String)
    (body : String) : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.par_request_uri body {
        Result.ok request_uri => do {
            // Success: remember where to send the browser, and report it.
            let url : String :=
                Atp.authorize_url st.authorize_endpoint st.pending.client_id request_uri;
            let next : Atp.State := { st with auth_url := url };
            IO.pure (Pair.pair next (Atp.Outcome.adk_out_redirect url))
        },
        Result.err _ =>
            if String.is_empty nonce_in && Bool.not (String.is_empty nonce)
            then Atp.start_par st st.jwk nonce
            else IO.pure (atp_notice st
                (String.concat_list ["The authorization server rejected the request (HTTP ",
                    I64.to_string status, "): ", atp_short body])),
    }

def Atp.after_token (st : Atp.State) (status : I64) (nonce_in : String) (nonce : String)
    (body : String) : IO (Pair Atp.State Atp.Outcome) :=
    match Atp.token_response st.pending st.jkt 0i64 body {
        Result.ok session => Atp.finish_session st session,
        Result.err e =>
            // A nonce-required failure retries once with the header's nonce.
            if String.is_empty nonce_in && Bool.not (String.is_empty nonce)
            then Atp.start_token st st.code nonce
            else IO.pure (atp_notice st
                (String.concat_list ["Sign-in failed (HTTP ", I64.to_string status,
                    "): ", e])),
    }

/// Keep the session, persist it, and report success.
///
/// The token response was parsed with `now_ms = 0` (see `after_token`), so the
/// expiry is rebased here against the real clock rather than trusting the
/// wall time the response was parsed at. `expires_at` from the parser is a
/// duration when `now_ms` is 0, which is exactly what is wanted.
def Atp.finish_session (st : Atp.State) (session : Atp.Session)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let now <- Clock.now_ms;
    let stamped : Atp.Session := { session with expires_at := I64.add now session.expires_at };
    let _ <- Storage.set (Atp.session_key st.config.storage_prefix) (Atp.session_to_json stamped);
    // The login is complete: the pending blob (state, verifier) is spent.
    let _ <- Storage.remove (Atp.pending_key st.config.storage_prefix);
    let idle : Atp.State := Atp.fresh st.config;
    let next : Atp.State := { idle with did := stamped.did };
    IO.pure (Pair.pair next (Atp.Outcome.adk_out_done
        (Atp.Done.adk_done_signed_in stamped)))
}

// ── The callback ────────────────────────────────────────────────────────

/// Complete a login from the callback URL. Called once at mount, when the page
/// URL carries `code`/`state`.
///
/// The stored `PendingLogin` IS the source of truth for the state and the
/// verifier, so a callback arriving in a fresh page still matches.
pub def Atp.finish_auth (cfg : Atp.ClientConfig) : IO (Pair Atp.State Atp.Outcome) := do {
    let code <- Window.search_param "code";
    let state <- Window.search_param "state";
    let iss <- Window.search_param "iss";
    let err <- Window.search_param "error";
    let desc <- Window.search_param "error_description";
    match Atp.callback code state iss err desc {
        Result.err e => IO.pure (atp_notice (Atp.fresh cfg) e),
        Result.ok cb => Atp.stored_pending (Atp.fresh cfg) cb,
    }
}

/// Read the stored pending login, then check the callback against it.
def Atp.stored_pending (st : Atp.State) (cb : Atp.Callback)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let key : String := Atp.pending_key st.config.storage_prefix;
    let raw <- Storage.get key;
    match raw {
        Option.none => IO.pure (atp_notice st
            "This browser has no sign-in in progress, so the callback cannot be completed"),
        Option.some body => match Atp.pending_of_json body {
            Result.err e => IO.pure (atp_notice st e),
            Result.ok pending => match Atp.check_callback pending cb {
                // A mismatched callback (possibly forged) leaves the real
                // pending login in place.
                Result.err e => IO.pure (atp_notice st e),
                Result.ok _ => do {
                    // The machine now holds the pending login, and the code
                    // is single-use: a reload of this URL must not retry it.
                    let _ <- Storage.remove key;
                    Atp.restore_and_exchange st pending cb
                },
            },
        },
    }
}

/// Restore the DPoP key the login started with, then exchange the code.
///
/// The key MUST be the one the PAR request bound the code to (`dpop_jkt`), so
/// the token endpoint refuses the exchange if a different key is found --
/// which is exactly why the key store, not `localStorage`, holds it.
def Atp.restore_and_exchange (base : Atp.State) (pending : Atp.PendingLogin) (cb : Atp.Callback)
    : IO (Pair Atp.State Atp.Outcome) := do {
    let op <- KeyStore.get_begin pending.did;
    let st : Atp.State := {
        base with step := Atp.Step.adk_step_key_get cb.code "",
            crypto := Option.some op, pending := pending, code := cb.code,
            issuer := pending.issuer, did := pending.did, slot := pending.did,
            jwk := pending.jwk, jkt := pending.jkt, pds := pending.pds,
    };
    IO.pure (atp_pending_state st)
}

/// Poll the key restore. `KeyStore.get_begin` adds a state the other crypto ops
/// do not have: 3 = done and the slot is EMPTY, which is a miss rather than a
/// failure ("this browser has no key for this DID" is the ordinary answer on a
/// first visit), so it is reported as such.
def Atp.step_key_get (st : Atp.State) (code : String) (nonce : String)
    : IO (Pair Atp.State Atp.Outcome) :=
    match st.crypto {
        Option.none => IO.pure (atp_failed st "internal error: no key op to poll"),
        Option.some op => do {
            let state <- Crypto.poll op;
            if I64.beq state 0i64
            then IO.pure (atp_pending_state st)
            else if I64.beq state 1i64
            then do {
                let k <- Crypto.op_key op;
                // The key is in hand but no signature is in flight yet, so the
                // token proof is BUILT and signed here -- moving straight to
                // `adk_step_signing` without a `sign_begin` would poll an op
                // that does not exist.
                let with_key : Atp.State := { st with key := Option.some k };
                Atp.start_token with_key code nonce
            }
            else if I64.beq state 3i64
            then IO.pure (atp_notice st
                "The DPoP key for this sign-in is gone (IndexedDB was cleared); start again")
            else IO.pure (atp_notice st
                "The browser refused to read back the DPoP key, so the code cannot be exchanged")
        },
    }
