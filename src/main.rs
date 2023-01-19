use axum::{
    body::{Bytes, HttpBody},
    extract::State,
    http::Request,
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};

use axum_macros::debug_handler;
use bytes::BytesMut;
use http::uri::{Authority, Scheme};

use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tower::ServiceBuilder;
use tower_http::{
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit, ServiceBuilderExt,
};

use hyper::{client::HttpConnector, Body};

pub mod cfg;
pub mod explain;
pub mod rules;
pub mod types;

use crate::cfg::STARPROXY_UPSTREAM_URL;
use crate::rules::*;

#[derive(Clone, Debug)]
struct OurState {
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    rules: Arc<RuleConfig>,
}

#[tokio::main]
async fn main() {
    // Setup tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Run our service
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 3000));
    tracing::info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app().into_make_service())
        .await
        .expect("server error");
}

fn app() -> Router {
    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .build();

    let client = hyper::Client::builder().build::<_, hyper::Body>(connector);

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    // Build our middleware stack
    let middleware = ServiceBuilder::new()
        // Mark the `Authorization` and `Cookie` headers as sensitive so it doesn't show in logs
        .sensitive_request_headers(sensitive_headers.clone())
        // Add high level tracing/logging to all requests
        .layer(
            TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                })
                .make_span_with(DefaultMakeSpan::new())
                .on_response(DefaultOnResponse::new().latency_unit(LatencyUnit::Micros)),
        )
        .sensitive_response_headers(sensitive_headers)
        // Set a timeout
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        // Box the response body so it implements `Default` which is required by axum
        .map_response_body(axum::body::boxed);

    // Open the config file and gather the rules into a RuleConfig struct.
    let config_file = std::fs::read_to_string(
        std::env::var("STARPROXY_CONFIG_PATH")
            .unwrap_or_else(|_| "/etc/starproxy/config.json".to_string()),
    )
    .expect("Could not open config file");
    let config: RuleConfig =
        serde_json::from_str(&config_file).expect("Could not parse config file");

    // Build route service
    Router::new()
        .route("/*path", any(proxy_handler))
        .layer(middleware)
        .with_state(OurState {
            client,
            rules: Arc::new(config),
        })
}

#[debug_handler]
#[tracing::instrument(name = "proxy_handler", skip(state, req))]
async fn proxy_handler(state: State<OurState>, mut req: Request<Body>) -> impl IntoResponse {
    debug!("incoming request headers: {:#?}", req.headers().keys());

    let mut parts = req.uri().clone().into_parts();
    parts.scheme = Some(Scheme::HTTPS);
    parts.authority = Some(Authority::from_static(&STARPROXY_UPSTREAM_URL));
    let new_url = http::Uri::from_parts(parts).expect("provided uri is not valid");
    info!("new_url: {}", new_url);

    *req.uri_mut() = new_url;

    info!("injecting HOST header: {:#?}", &STARPROXY_UPSTREAM_URL);
    req.headers_mut().insert(
        header::HOST,
        HeaderValue::from_static(&STARPROXY_UPSTREAM_URL),
    );

    if req.method() == http::Method::POST
        && req.uri().path() == "/v1/statement"
        && req
            .headers()
            .contains_key(header::HeaderName::from_static("authorization"))
    {
        // read the body of the request w/o consuming it
        let buffer: Bytes = {
            let body: &mut Body = req.body_mut();
            let mut buf = BytesMut::with_capacity(body.size_hint().lower() as usize);
            while let Some(chunk) = body.data().await {
                buf.extend_from_slice(&chunk.unwrap());
            }
            buf.freeze()
        };

        let body_str = String::from_utf8(buffer.to_vec()).expect("invalid utf8");

        // extract the table names from the query

        let table_names =
            extract_tables_from_query(&body_str).expect("could not extract tables from query");

        for rule in state.rules.rules.iter() {
            let qd = QueryData {
                query: body_str.clone(),
                headers: req.headers().clone(),
            };

            // if the table doesn't match the rule, we can skip the check
            if !table_names.contains(&rule.table_name) {
                continue;
            }

            // marshalling logic betwen the config and evaluating the rule
            let res = match &rule.value {
                RuleContainer::CidrOrigin(cidr) => {
                    inbound_cidr_check(&rule.table_name, cidr.inbound_cidr, &qd).await
                }
                RuleContainer::WhereClause(where_clause) => {
                    check_for_predicate(&where_clause.filter, &rule.table_name, &qd).await
                }
                RuleContainer::SelectStarNoLimit(_ss) => {
                    require_limit_if_select_star(&rule.table_name, &qd)
                }
                RuleContainer::ScanEstimates(_se) => {
                    scan_estimates_check(&rule.table_name, _se.max_cpu_cost as f32, &qd).await
                }
            };

            match res {
                Ok(false) => {
                    debug!("No violation of rule: {}", rule.name);
                }
                Ok(true) => {
                    debug!("Violation of rule!: {}", rule.name);
                    if let Some(func) = &rule.action {
                        let action_result = match func {
                            ActionType::Block => {
                                return (StatusCode::FORBIDDEN, "Request blocked").into_response();
                            }
                            ActionType::InjectHeader => {
                                send_query_to_low_priority(&mut req.headers_mut())
                            }
                        };

                        match action_result {
                            Ok(ActionState::Applied) => {
                                debug!("Successfully applied action: {}", rule.name);
                            }
                            Err(e) => {
                                warn!("Error applying action: {}", e);
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Error applying action",
                                )
                                    .into_response();
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Error checking rule: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Error checking rule")
                        .into_response();
                }
            }
        }

        // replace the body with the original body
        *req.body_mut() = Body::from(buffer);
    }

    match state.client.request(req).await {
        Ok(res) => res.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", e)).into_response(),
    }
}
