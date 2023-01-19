pub static STARPROXY_UPSTREAM_URL: once_cell::sync::Lazy<String> =
    once_cell::sync::Lazy::new(|| {
        std::env::var("STARPROXY_UPSTREAM_URL").unwrap_or_else(|_| "trino".to_string())
    });
