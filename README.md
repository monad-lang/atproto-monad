# atproto-monad

[AT Protocol](https://atproto.com) libraries for [Monad](https://monad-lang.org).

## Motes

| Mote | What it is | Targets |
|---|---|---|
| `atproto_common` | Reading JSON responses with errors you can act on, writing JSON strings, JWS signing inputs, S256 | native, web |
| `atproto_identity` | Handle and DID syntax, DID documents, the pure halves of handle resolution (DNS-over-HTTPS TXT, `/.well-known/atproto-did`, `resolveHandle`) | native, web |
| `atproto_oauth` | The atproto OAuth profile: PKCE (S256), DPoP proofs, AS and resource metadata with the mix-up checks, PAR, the callback, token, refresh and revocation bodies, client metadata and `Atp.ClientConfig`, and the codec for the pending login and the session | native, web |
| `atproto_repo` | `com.atproto.repo` records: getRecord/putRecord URLs and bodies, `swapRecord`, the XRPC error classifiers, RFC 3339 timestamps | native, web |
| `atproto_web` | The browser driver: a pure login/record/sign-out machine (`machine.mo`), and `web.mo`, which advances it one begin/poll step at a time on `web_wasm` (Fetch, WebCrypto P-256, IndexedDB `KeyStore`, localStorage) | web |

Each mote's API is its modules. Import them as `<mote>::<module>`, e.g.
`use atproto_web::web {Atp.begin_sign_in}`. Every public name has the `Atp.`
prefix.

## Design

- **Pure core, IO at the edge.** Everything except `atproto_web::web` is a
  pure function over strings and `Json`, so `monad test` runs all of it
  natively, with no browser and no network. The signing and transport halves
  are split at the `signing_input`/`assemble` seam, because in a browser both
  are asynchronous begin/poll operations.
- **The app owns its data.** Nothing in these motes names an app. An app
  passes an `Atp.ClientConfig` (client name, scope, storage-key prefix), and
  records are plain `Json` values that the app encodes and decodes itself.
- **The machine lives in the app's model.** `Atp.State` holds only opaque
  `web_wasm` handles, so an Oak/Elm-style model can store it and still build
  for native tests. The app's update loop calls `Atp.step` once per tick until
  the outcome is no longer pending.

## Using it from a web app

```toml
# mote.toml
[dependencies.atproto_oauth]
path = "../atproto-monad/motes/atproto_oauth"

[dependencies.atproto_repo]
path = "../atproto-monad/motes/atproto_repo"

[dependencies.atproto_web]
path = "../atproto-monad/motes/atproto_web"
```

```monad
use atproto_oauth::client_metadata {Atp.ClientConfig, Atp.repo_scope}
use atproto_web::web {Atp.begin_sign_in, Atp.finish_auth, Atp.step,
    Atp.begin_get_record, Atp.begin_put_record, Atp.begin_sign_out}

def App.atp : Atp.ClientConfig := {
    name := "my app",
    scope := Atp.repo_scope ["com.example.thing"],
    storage_prefix := "myapp",
}
```

- **Sign in:** call `Atp.begin_sign_in App.atp handle`, then keep calling
  `Atp.step` until it returns `adk_out_redirect url`, and navigate there.
- **Callback:** at mount, when the URL carries `code`, call
  `Atp.finish_auth App.atp` and step it until it returns
  `adk_done_signed_in session`.
- **Records:**
  - `Atp.begin_get_record session collection rkey` ends in
    `adk_done_pulled`.
  - `Atp.begin_put_record session collection rkey json swap` ends in
    `adk_done_pushed` or `adk_done_conflict`.
  - Either one can end in `adk_done_expired`.
- **Hosting:** serve
  `Atp.client_metadata App.atp (Atp.hosted_client_id origin) (Atp.redirect_uri origin)`
  as `/client-metadata.json`.

Its `web/atproto_smoke.mjs` drives the real wasm against a strict stub
authorization server and PDS.

## Development

```bash
devenv shell          # clang/lld for wasm, Boehm GC, node
monad fetch
monad test motes/atproto_oauth      # or any mote
monad check motes/atproto_web
```

Every monad dependency is pinned in the workspace root's
`[workspace.dependencies]` to the installed compiler's revision
(`monad version` == `6ff8cdb`). An app that uses these motes must pin the same
revision.

## Roadmap

The long-term plan is `plans/library-ideas/atproto.md` in the monad repo.
Likely next motes:

- `atproto_syntax`: typed `Handle`, `Did`, `Nsid`, `AtUri`, `RecordKey`,
  `Tid`, with the interop-test vectors
- `atproto_native`: a straight-line IO driver for servers and CLIs, using
  `moose`/`crypto`
- `atproto_xrpc`: a general XRPC client, then lexicon codegen
- verification: CAR files, the MST, signed commits
