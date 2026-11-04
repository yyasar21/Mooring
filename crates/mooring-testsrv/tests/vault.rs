//! Self-tests of the Vault mock: token lookup / renew / revoke, `AppRole`, OIDC, KV v2 reads,
//! policies, namespaces, sealed / standby knobs, TTL expiry and the violation trap.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::http_client::{get, post_json, request, send};
use common::within;
use http::Method;
use mooring_testsrv::vault::{self, TokenFixture, VaultConfig, VaultKnobs, VaultServer};
use serde_json::json;

const TOKEN: (&str, &str) = ("x-vault-token", "hvs.test-token");

async fn srv(config: VaultConfig) -> VaultServer {
    vault::start(config, 0).await.expect("start")
}

#[tokio::test]
async fn token_lookup_renew_and_root_detection() {
    let s = srv(VaultConfig::default()).await;
    within(async {
        let me = get(s.addr(), "/v1/auth/token/lookup-self", &[TOKEN]).await.json();
        assert_eq!(me["data"]["policies"], json!(["default", "mooring-read"]));
        assert!(me["data"]["ttl"].as_u64().is_some_and(|t| t > 3500 && t <= 3600));
        assert_eq!(me["data"]["renewable"], true);
        let root =
            get(s.addr(), "/v1/auth/token/lookup-self", &[("x-vault-token", "hvs.root-token")])
                .await
                .json();
        assert_eq!(
            (root["data"]["policies"].clone(), root["data"]["ttl"].as_u64()),
            (json!(["root"]), Some(0))
        );
        assert_eq!(
            get(s.addr(), "/v1/auth/token/lookup-self", &[("x-vault-token", "hvs.bogus")])
                .await
                .status,
            403
        );
        let renew = send(
            s.addr(),
            request(Method::POST, "/v1/auth/token/renew-self", &[TOKEN], Bytes::new()),
            None,
        )
        .await;
        assert_eq!(renew.json()["auth"]["lease_duration"], 3600);
        let no = send(
            s.addr(),
            request(
                Method::POST,
                "/v1/auth/token/renew-self",
                &[("x-vault-token", "hvs.no-policy")],
                Bytes::new(),
            ),
            None,
        )
        .await;
        assert_eq!(no.status, 400);
        s.set_knobs(VaultKnobs { root_token: true, ..VaultKnobs::default() });
        let forced = get(s.addr(), "/v1/auth/token/lookup-self", &[TOKEN]).await.json();
        assert_eq!(forced["data"]["policies"], json!(["root"]));
    })
    .await;
    let kinds: Vec<String> = s.token_events().into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, ["lookup", "lookup", "renew", "lookup"]);
    assert!(s
        .recorder()
        .requests()
        .iter()
        .all(|r| r.header("x-vault-token") == Some(mooring_testsrv::http::REDACTED)));
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn approle_login_read_and_revoke() {
    let s = srv(VaultConfig::default()).await;
    within(async {
        let bad = post_json(
            s.addr(),
            "/v1/auth/approle/login",
            &[],
            &json!({ "role_id": "test-role-id", "secret_id": "no" }),
        )
        .await;
        assert_eq!(bad.status, 400);
        let ok = post_json(
            s.addr(),
            "/v1/auth/approle/login",
            &[],
            &json!({ "role_id": "test-role-id", "secret_id": "test-secret-id" }),
        )
        .await
        .json();
        assert_eq!(ok["auth"]["lease_duration"], 1200);
        let tok = ok["auth"]["client_token"].as_str().expect("token").to_owned();
        let h = [("x-vault-token", tok.as_str())];
        let kv = get(s.addr(), "/v1/secret/data/servers/web", &h).await.json();
        assert_eq!(kv["data"]["data"]["password"], "testpass");
        assert_eq!(s.live_issued_tokens(), 1);
        let rv = send(
            s.addr(),
            request(Method::POST, "/v1/auth/token/revoke-self", &h, Bytes::new()),
            None,
        )
        .await;
        assert_eq!(rv.status, 204);
        assert_eq!(get(s.addr(), "/v1/secret/data/servers/web", &h).await.status, 403);
    })
    .await;
    assert_eq!(s.live_issued_tokens(), 0);
    let kinds: Vec<String> = s.token_events().into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, ["login-approle", "revoke"]);
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn oidc_auth_url_and_callback() {
    let s = srv(VaultConfig::default()).await;
    let redirect = "http://localhost:8250/oidc/callback";
    within(async {
        let url = "/v1/auth/oidc/oidc/auth_url";
        let role = post_json(s.addr(), url, &[], &json!({ "role": "x", "redirect_uri": redirect, "client_nonce": "n1" })).await;
        assert_eq!(role.status, 400);
        let uri = post_json(s.addr(), url, &[], &json!({ "role": "mooring", "redirect_uri": "http://evil.example.test/cb", "client_nonce": "n1" })).await;
        assert_eq!(uri.status, 400);
        let r = post_json(s.addr(), url, &[], &json!({ "role": "mooring", "redirect_uri": redirect, "client_nonce": "n1" })).await.json();
        let auth_url = r["data"]["auth_url"].as_str().expect("auth_url").to_owned();
        assert!(auth_url.starts_with("https://idp.example.test/authorize?"));
        let back = s.idp_redirect(&auth_url).expect("known state");
        let query = back.strip_prefix(redirect).expect("redirect_uri").trim_start_matches('?');
        let wrong = get(s.addr(), &format!("/v1/auth/oidc/oidc/callback?{query}&client_nonce=n2"), &[]).await;
        assert_eq!(wrong.status, 400, "nonce mismatch (and the state is now spent)");
        let r = post_json(s.addr(), url, &[], &json!({ "role": "mooring", "redirect_uri": redirect, "client_nonce": "n1" })).await.json();
        let back = s.idp_redirect(r["data"]["auth_url"].as_str().expect("url")).expect("state");
        let query = back.strip_prefix(redirect).expect("redirect").trim_start_matches('?').to_owned();
        let cb = format!("/v1/auth/oidc/oidc/callback?{query}&client_nonce=n1");
        let ok = get(s.addr(), &cb, &[]).await.json();
        assert_eq!(ok["auth"]["lease_duration"], 900);
        assert_eq!(get(s.addr(), &cb, &[]).await.status, 400, "a state is single-use");
    })
    .await;
    let cbs: Vec<_> =
        s.recorder().requests().into_iter().filter(|r| r.path.ends_with("/callback")).collect();
    assert!(cbs.iter().all(|r| r.query_get("code") == Some(mooring_testsrv::http::REDACTED)));
    assert!(cbs.iter().all(|r| r.query_get("state") == Some(mooring_testsrv::http::REDACTED)));
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn kv_versions_deleted_destroyed_metadata_and_policy() {
    let s = srv(VaultConfig::default()).await;
    within(async {
        let kv = |p: &'static str| get(s.addr(), p, &[TOKEN]);
        let latest = kv("/v1/secret/data/servers/web").await.json();
        assert_eq!(
            (latest["data"]["metadata"]["version"].as_u64(), latest["lease_duration"].as_u64()),
            (Some(2), Some(0))
        );
        assert_eq!(
            kv("/v1/secret/data/servers/web?version=1").await.json()["data"]["data"]["password"],
            "old-testpass"
        );
        assert_eq!(kv("/v1/secret/data/servers/web?version=9").await.status, 404);
        let del = kv("/v1/secret/data/servers/deleted").await;
        assert_eq!(del.status, 404);
        assert_ne!(del.json()["data"]["metadata"]["deletion_time"], "");
        assert_eq!(del.json()["data"]["data"], serde_json::Value::Null);
        assert_eq!(
            kv("/v1/secret/data/servers/destroyed").await.json()["data"]["metadata"]["destroyed"],
            true
        );
        assert_eq!(kv("/v1/secret/data/nope").await.status, 404);
        let meta = kv("/v1/secret/metadata/servers/web").await.json();
        assert_eq!(meta["data"]["current_version"], 2);
        assert_eq!(
            get(s.addr(), "/v1/secret/data/servers/web", &[("x-vault-token", "hvs.no-policy")])
                .await
                .status,
            403
        );
        assert_eq!(
            get(s.addr(), "/v1/secret/data/servers/web", &[("x-vault-token", "hvs.root-token")])
                .await
                .status,
            200
        );
        s.set_knobs(VaultKnobs {
            raw_kv_body: Some(r#"{"data":{"data":{"password":"a","password":"b"}}}"#.to_owned()),
            ..VaultKnobs::default()
        });
        assert!(kv("/v1/secret/data/servers/web")
            .await
            .text()
            .contains(r#""password":"a","password":"b""#));
        s.set_knobs(VaultKnobs { oversized_body: Some(2 * 1024 * 1024), ..VaultKnobs::default() });
        assert!(kv("/v1/secret/data/servers/web").await.body.len() > 2 * 1024 * 1024);
        s.set_knobs(VaultKnobs { force_403: true, ..VaultKnobs::default() });
        assert_eq!(kv("/v1/secret/data/servers/web").await.status, 403);
    })
    .await;
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn sealed_standby_namespace_and_ttl_expiry() {
    let mut cfg = VaultConfig { namespace: Some("team-a".to_owned()), ..VaultConfig::default() };
    cfg.tokens.push(TokenFixture {
        token: "hvs.short".to_owned(),
        policies: vec!["mooring-read".to_owned()],
        ttl: 1,
        renewable: false,
    });
    let s = srv(cfg).await;
    within(async {
        let p = "/v1/secret/data/servers/web";
        assert_eq!(get(s.addr(), p, &[TOKEN]).await.status, 403, "namespace header missing");
        assert_eq!(get(s.addr(), p, &[TOKEN, ("x-vault-namespace", "team-a/")]).await.status, 200);
        let short = [("x-vault-token", "hvs.short"), ("x-vault-namespace", "team-a")];
        assert_eq!(get(s.addr(), p, &short).await.status, 200);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(get(s.addr(), p, &short).await.status, 403, "TTL ran out");
        s.set_knobs(VaultKnobs { sealed: true, ..VaultKnobs::default() });
        assert_eq!(get(s.addr(), p, &[TOKEN]).await.status, 503);
        assert_eq!(get(s.addr(), "/v1/sys/health", &[]).await.status, 503);
        s.set_knobs(VaultKnobs { standby: true, ..VaultKnobs::default() });
        let r = get(s.addr(), p, &[TOKEN]).await;
        assert_eq!(r.status, 307);
        assert_eq!(
            r.header("location").as_deref(),
            Some("https://vault-active.example.test:8200/v1/secret/data/servers/web")
        );
        assert_eq!(get(s.addr(), "/v1/sys/health", &[]).await.status, 429);
    })
    .await;
    s.recorder().assert_no_violations();
}

#[tokio::test]
async fn writes_and_other_paths_are_violations() {
    let s = srv(VaultConfig::default()).await;
    within(async {
        for (m, p) in [
            (Method::POST, "/v1/secret/data/servers/web"),
            (Method::PUT, "/v1/secret/data/servers/web"),
            (Method::DELETE, "/v1/secret/metadata/servers/web"),
            (Method::POST, "/v1/secret/destroy/servers/web"),
            (Method::GET, "/v1/sys/mounts"),
            (Method::POST, "/v1/auth/token/create"),
        ] {
            let r =
                send(s.addr(), request(m.clone(), p, &[TOKEN], Bytes::from_static(b"{}")), None)
                    .await;
            assert_eq!(r.status, 500, "{m} {p}");
        }
    })
    .await;
    assert_eq!(s.recorder().violations().len(), 6);
}
