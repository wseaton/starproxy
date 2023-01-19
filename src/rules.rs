use anyhow::anyhow;
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::time::Duration;

use axum::http::header;

use derive_visitor::{visitor_enter_fn, Drive};

use http::HeaderMap;
use http::HeaderValue;

use cidr_utils::cidr::Ipv4Cidr;

use log::info;
use log::warn;
use serde::Serialize;

use sqlparser::ast::SelectItem;
use sqlparser::ast::SetExpr;
use sqlparser::ast::{Expr, Query};
use sqlparser::ast::{ObjectName, TableFactor, TableFactor::Table};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser as SQLParser;

use serde::Deserialize;

use anyhow::Result;
use tracing::debug;
use tracing::error;

const ALLOWED_HEADERS: &[header::HeaderName] = &[
    header::CONTENT_LENGTH,
    header::CONTENT_TYPE,
    header::IF_MATCH,
    header::RANGE,
];

/// The structs in this section are mainly for parsing the rules from a config file.

#[derive(Debug, Serialize, Deserialize)]
pub struct WhereClauseRule {
    pub filter: Expr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelectStarRule {
    // #TODO: add limit min/max
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CidrOriginRule {
    pub inbound_cidr: Ipv4Cidr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CostInput {
    pub max_cpu_cost: f64,
}

/// As new Rule architypes are added, this enum is to be extended as it
/// controls how config is parsed and any input parameters to the rule.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleContainer {
    WhereClause(WhereClauseRule),
    SelectStarNoLimit(SelectStarRule),
    CidrOrigin(CidrOriginRule),
    ScanEstimates(CostInput),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleEntry {
    pub name: String,
    pub table_name: String,
    pub value: RuleContainer,
    pub action: Option<ActionType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleConfig {
    pub rules: Vec<RuleEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ActionType {
    Block,
    InjectHeader,
}

// This enum is used to decouple the state of Action application failure vs. blocking.
pub enum ActionState {
    Applied,
}

pub fn send_query_to_low_priority(headers: &mut HeaderMap<HeaderValue>) -> Result<ActionState> {
    let prev_value = headers
        .get(header::HeaderName::from_static("x-trino-client-tags"))
        .map(|v| v.to_str().expect("Could not convert header value to str"));

    // split the value on commas and add lowprio to the list
    let new_value = match prev_value {
        Some(v) => {
            let mut values = v.split(',').collect::<Vec<&str>>();
            values.push("lowprio");
            values.join(",")
        }
        None => "lowprio".to_string(),
    };

    headers.insert(
        header::HeaderName::from_static("x-trino-client-tags"),
        header::HeaderValue::from_str(&new_value).expect("invalid header value"),
    );
    Ok(ActionState::Applied)
}

#[derive(Debug, Clone)]
pub struct QueryData {
    pub query: String,
    pub headers: HeaderMap<HeaderValue>,
}

#[tracing::instrument]
pub async fn inbound_cidr_check(
    input_table_name: &str,
    input_cidr: Ipv4Cidr,
    data: &QueryData,
) -> Result<bool> {
    let mut found_table = false;
    let ast = SQLParser::parse_sql(&MySqlDialect {}, &data.query)?;

    // scan through all of the table references and look for the one w/ the right name
    ast.drive(&mut visitor_enter_fn(|table: &TableFactor| {
        if let Table {
            name: ObjectName(parts),
            ..
        } = table
        {
            let table_name = parts
                .iter()
                .map(|x| x.value.to_owned())
                .collect::<Vec<String>>()
                .join(".");
            if input_table_name == table_name {
                found_table = true;
            }
        }
    }));

    if !found_table {
        debug!("No table found in query");
        return Ok(false);
    }

    let ip = data
        .headers
        .get(header::HeaderName::from_static("x-forwarded-for"))
        .map(|v| v.to_str().expect("Could not convert header value to str"));

    match ip {
        Some(ip) => {
            let ip = ip.parse::<Ipv4Addr>().expect("Could not parse IP address");
            if input_cidr.contains(ip) {
                debug!("IP {} is in CIDR {}", ip, input_cidr);
                Ok(false)
            } else {
                debug!("IP {} is NOT in CIDR {}", ip, input_cidr);
                Ok(true)
            }
        }
        None => {
            debug!("No IP address found in headers");
            // we will consider this case a violation, something is wrong
            Ok(true)
        }
    }
}

// // Generic "Rule" implementation that searches for a WHERE clause in a query
#[tracing::instrument]
pub async fn check_for_predicate(
    input_predicate: &Expr,
    input_table_name: &str,
    data: &QueryData,
) -> Result<bool> {
    let ast = SQLParser::parse_sql(&MySqlDialect {}, &data.query)?;

    let mut found_table = false;
    let mut found_predicate = false;

    ast.drive(&mut visitor_enter_fn(|predicate: &Expr| {
        if predicate == input_predicate {
            found_predicate = true;
        }
    }));

    // scan through all of the table references and look for the one w/ the right name
    ast.drive(&mut visitor_enter_fn(|table: &TableFactor| {
        if let Table {
            name: ObjectName(parts),
            ..
        } = table
        {
            let table_name = parts
                .iter()
                .map(|x| x.value.to_owned())
                .collect::<Vec<String>>()
                .join(".");
            if input_table_name == table_name {
                found_table = true;
            }
        }
    }));

    debug!(
        "Found predicate: {} and table: {}",
        found_predicate, found_table
    );

    Ok(!found_predicate && found_table)
}

// write the scan_estimates_check function
#[tracing::instrument]
pub async fn scan_estimates_check(
    input_table_name: &str,
    max_cpu_cost: f32,
    data: &QueryData,
) -> Result<bool> {
    // ceck if the authorization header is set here
    if !data
        .headers
        .contains_key(header::HeaderName::from_static("authorization"))
    {
        // throw error because we can't run this check w/o user auth
        return Err(anyhow!(
            "Authorization header not set, we can't run this rule!"
        ));
    }

    let mut http_client = reqwest::ClientBuilder::new();

    let mut retained_headers = data.headers.clone();
    ALLOWED_HEADERS.iter().for_each(|h| {
        retained_headers.remove(h);
    });

    // set default headers
    http_client = http_client
        .default_headers(retained_headers)
        .timeout(Duration::from_secs(30));

    let client = trino::Client {
        base_url: format!(
            "https://{}",
            std::env::var("STARPROXY_UPSTREAM_URL").expect("STARPROXY_UPSTREAM_URL not set")
        ),
        port: 443,
        user: None,
        http_client: http_client.build().expect("Failed to make http client"),
    };

    use crate::explain::ExplainNode;
    let explain_query = format!("EXPLAIN (TYPE LOGICAL, FORMAT JSON) {}", data.query.clone());

    info!("explain_query: {}", explain_query);
    let res = client.query::<Vec<String>>(&explain_query).await;

    match res {
        Ok(graph) => {
            let graph: ExplainNode =
                serde_json::from_str(&graph[0][0]).expect("Could not parse explain node");
            info!("res: {:?}", graph);

            // recursively search the graph for the max_cpu_cost
            let mut max_cpu_cost_found = 0.0;
            graph.drive(&mut visitor_enter_fn(|node: &ExplainNode| {
                if let Some(estimates) = &node.estimates {
                    for estimate in estimates {
                        if let crate::explain::FloatingPointHack::Float(cost) = estimate.cpu_cost {
                            if cost > max_cpu_cost_found {
                                max_cpu_cost_found = cost;
                            }
                        }
                    }
                }
            }));

            info!("max_cpu_cost_found: {}", max_cpu_cost_found);

            if max_cpu_cost_found > max_cpu_cost {
                return Ok(true);
            }
        }
        Err(e) => {
            error!("Error: {:?}", e);
            return Ok(false);
        }
    }

    Ok(false)
}

pub fn extract_tables_from_query(query: &str) -> Result<HashSet<String>> {
    let ast = SQLParser::parse_sql(&MySqlDialect {}, query)?;

    let mut tables = HashSet::new();

    ast.drive(&mut visitor_enter_fn(|table: &TableFactor| {
        if let Table {
            name: ObjectName(parts),
            ..
        } = table
        {
            let table_name = parts
                .iter()
                .map(|x| x.value.to_owned())
                .collect::<Vec<String>>()
                .join(".");
            tables.insert(table_name);
        }
    }));
    Ok(tables)
}

/// Return value of true means there is a violation
#[tracing::instrument]
pub fn require_limit_if_select_star(input_table_name: &str, data: &QueryData) -> Result<bool> {
    let ast = SQLParser::parse_sql(&MySqlDialect {}, &data.query)?;

    let mut found_select_star = false;
    let mut found_limit = false;
    let mut found_table = false;

    ast.drive(&mut visitor_enter_fn(|query: &Query| {
        let q = query.clone();
        // scan through all of the table references and look for the one w/ the right name
        q.drive(&mut visitor_enter_fn(|table: &TableFactor| {
            if let Table {
                name: ObjectName(parts),
                ..
            } = table
            {
                let table_name = parts
                    .iter()
                    .map(|x| x.value.to_owned())
                    .collect::<Vec<String>>()
                    .join(".");
                if input_table_name == table_name {
                    found_table = true;
                }
            }
        }));

        if let SetExpr::Select(select) = *q.body {
            select.projection.iter().for_each(|item| {
                if let SelectItem::Wildcard = item {
                    found_select_star = true;
                }
            });
        }

        if query.limit.is_some() {
            found_limit = true;
        }
    }));

    debug!(
        "found_table: {}, found_select_star: {}, found_limit: {}",
        found_table, found_select_star, found_limit
    );

    // if we find the table + select * and there is no limit, return true
    Ok(found_table && found_select_star && !found_limit)
}
