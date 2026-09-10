use std::io;
use std::net::SocketAddr;

use pretty_assertions::assert_eq;

use super::FETCH_URL_NON_PUBLIC;
use super::FETCH_URL_SCHEME;
use super::FETCH_URL_UNVERIFIED;
use super::ensure_public_http_url_with_lookup;
use crate::function_tool::FunctionCallError;

fn parse_url(url: &str) -> reqwest::Url {
    reqwest::Url::parse(url).unwrap_or_else(|err| panic!("test URL should parse ({url}): {err}"))
}

fn lookup_should_not_run(
    host: String,
    _port: u16,
) -> impl std::future::Future<Output = io::Result<Vec<SocketAddr>>> {
    async move { panic!("DNS lookup should not run for {host}") }
}

fn lookup_addrs(
    addrs: Vec<SocketAddr>,
) -> impl FnOnce(
    String,
    u16,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = io::Result<Vec<SocketAddr>>> + Send>,
> {
    move |_host, _port| Box::pin(async move { Ok(addrs) })
}

#[tokio::test]
async fn rejects_non_public_ip_literals_loopback_rfc1918_link_local_and_unsafe_schemes() {
    let cases = [
        "http://127.0.0.1/",
        "https://127.0.0.1/path",
        "http://10.0.0.1/",
        "http://10.255.255.255/",
        "http://172.16.0.1/",
        "http://172.31.255.1/",
        "http://192.168.1.1/",
        "http://192.168.0.1:8080/internal",
        "http://169.254.169.254/",
        "http://169.254.1.1/",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:10.0.0.1]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://localhost/",
        "https://LOCALHOST/",
        "http://localhost./",
        "http://foo.localhost/",
        "file:///etc/passwd",
        "ftp://example.com/",
        "gopher://example.com/",
        "data:text/plain,hello",
        "javascript:alert(1)",
        "ws://example.com/",
        "unix:///tmp/socket",
    ];

    for url in cases {
        let parsed = parse_url(url);
        let result = ensure_public_http_url_with_lookup(&parsed, lookup_should_not_run).await;
        assert!(result.is_err(), "{url} should be rejected, got {result:?}");
    }
}

#[tokio::test]
async fn rejects_metadata_style_link_local_redirect_target() {
    let url = parse_url("http://169.254.169.254/latest/meta-data/");
    assert_eq!(
        ensure_public_http_url_with_lookup(&url, lookup_should_not_run).await,
        Err(FunctionCallError::RespondToModel(
            FETCH_URL_NON_PUBLIC.to_string()
        ))
    );
}

#[tokio::test]
async fn rejects_hostname_that_resolves_to_a_private_or_loopback_address() {
    let url = parse_url("https://example.test/docs");
    assert_eq!(
        ensure_public_http_url_with_lookup(
            &url,
            lookup_addrs(vec![SocketAddr::from(([10, 0, 0, 1], 443))])
        )
        .await,
        Err(FunctionCallError::RespondToModel(
            FETCH_URL_NON_PUBLIC.to_string()
        ))
    );

    let url = parse_url("http://example.test/");
    assert_eq!(
        ensure_public_http_url_with_lookup(
            &url,
            lookup_addrs(vec![
                SocketAddr::from(([93, 184, 216, 34], 80)),
                SocketAddr::from(([127, 0, 0, 1], 80)),
            ])
        )
        .await,
        Err(FunctionCallError::RespondToModel(
            FETCH_URL_NON_PUBLIC.to_string()
        ))
    );
}

#[tokio::test]
async fn rejects_when_dns_cannot_prove_the_host_is_public() {
    let url = parse_url("https://example.test/");
    assert_eq!(
        ensure_public_http_url_with_lookup(&url, |_host, _port| async {
            Err(io::Error::other("lookup failed"))
        })
        .await,
        Err(FunctionCallError::RespondToModel(
            FETCH_URL_UNVERIFIED.to_string()
        ))
    );

    assert_eq!(
        ensure_public_http_url_with_lookup(&url, lookup_addrs(Vec::new())).await,
        Err(FunctionCallError::RespondToModel(
            FETCH_URL_UNVERIFIED.to_string()
        ))
    );
}

#[tokio::test]
async fn rejects_non_http_schemes_with_the_public_contract_message() {
    let url = parse_url("file://example.com/tmp");
    assert_eq!(
        ensure_public_http_url_with_lookup(&url, lookup_should_not_run).await,
        Err(FunctionCallError::RespondToModel(
            FETCH_URL_SCHEME.to_string()
        ))
    );
}

#[tokio::test]
async fn allows_public_ip_literals_and_hostnames_that_resolve_publicly() {
    let url = parse_url("https://8.8.8.8/");
    assert_eq!(
        ensure_public_http_url_with_lookup(&url, lookup_should_not_run).await,
        Ok(())
    );

    let url = parse_url("http://1.1.1.1/path");
    assert_eq!(
        ensure_public_http_url_with_lookup(&url, lookup_should_not_run).await,
        Ok(())
    );

    let url = parse_url("http://172.15.0.1/");
    assert_eq!(
        ensure_public_http_url_with_lookup(&url, lookup_should_not_run).await,
        Ok(())
    );

    let url = parse_url("https://[2001:4860:4860::8888]/");
    assert_eq!(
        ensure_public_http_url_with_lookup(&url, lookup_should_not_run).await,
        Ok(())
    );

    let url = parse_url("https://example.test/path");
    assert_eq!(
        ensure_public_http_url_with_lookup(
            &url,
            lookup_addrs(vec![SocketAddr::from(([93, 184, 216, 34], 443))])
        )
        .await,
        Ok(())
    );
}
