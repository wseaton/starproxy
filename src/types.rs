use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResults {
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub info_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_cancel_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<Stats>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,

    pub warnings: Vec<Warning>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_count: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Warning {
    #[serde(rename = "warningCode")]
    pub code: u32,
    pub message: String,
}

// stats example data:
// {"state":"QUEUED","queued":true,"scheduled":false,"nodes":0,"totalSplits":0,"queuedSplits":0,"runningSplits":0,"completedSplits":0,"cpuTimeMillis":0,"wallTimeMillis":0,"queuedTimeMillis":0,"elapsedTimeMillis":0,"processedRows":0,"processedBytes":0,"physicalInputBytes":0,"peakMemoryBytes":0,"spilledBytes":0}
// make a rust struct for stats
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub state: String,
    pub queued: bool,
    pub scheduled: bool,
    pub nodes: u32,
    pub total_splits: u32,
    pub queued_splits: u32,
    pub running_splits: u32,
    pub completed_splits: u32,
    pub cpu_time_millis: u32,
    pub wall_time_millis: u32,
    pub queued_time_millis: u32,
    pub elapsed_time_millis: u32,
    pub processed_rows: u32,
    pub processed_bytes: u32,
    pub physical_input_bytes: u32,
    pub peak_memory_bytes: u32,
    pub spilled_bytes: u32,
}
