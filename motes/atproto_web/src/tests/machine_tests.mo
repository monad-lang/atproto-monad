// Native tests for the pure login machine. `web.mo` does IO and is covered
// end to end by the consuming app's smoke test (example.game's
// web/atproto_smoke.mjs); `machine.mo` imports only opaque handle
// declarations, so it builds and runs here.

use atproto_oauth::client_metadata {Atp.ClientConfig, Atp.repo_scope}
use lib::machine {Atp.State, Atp.blank, Atp.fresh, Atp.busy, Atp.waiting_on_fetch}

def atp_cfg : Atp.ClientConfig := {
    name := "example",
    scope := Atp.repo_scope ["com.example.thing"],
    storage_prefix := "example",
}

#[test]
def test_blank_is_idle : Bool :=
    Bool.not (Atp.busy Atp.blank) && Bool.not (Atp.waiting_on_fetch Atp.blank)

#[test]
def test_fresh_carries_the_config_and_is_idle : Bool :=
    let st : Atp.State := Atp.fresh atp_cfg in
    String.beq st.config.name "example"
        && String.beq st.config.storage_prefix "example"
        && String.beq st.config.scope "atproto repo:com.example.thing?action=create&action=update"
        && Bool.not (Atp.busy st)
