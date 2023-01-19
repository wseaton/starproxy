use derive_visitor::Drive;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Drive)]
pub struct ExplainNode {
    #[drive(skip)]
    pub id: String,
    #[drive(skip)]
    pub name: String,
    #[drive(skip)]
    pub descriptor: Description,
    #[drive(skip)]
    pub outputs: Vec<ColumnOutput>,
    #[drive(skip)]
    pub details: Vec<String>,
    #[drive(skip)]
    pub estimates: Option<Vec<Estimate>>,
    pub children: Option<Vec<ExplainNode>>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Estimate {
    pub output_row_count: FloatingPointHack,
    pub output_size_in_bytes: FloatingPointHack,
    pub cpu_cost: FloatingPointHack,
    pub memory_cost: FloatingPointHack,
    pub network_cost: FloatingPointHack,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum FloatingPointHack {
    Float(f32),
    NaN(String),
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Description {
    pub column_names: Option<String>,
    pub count: Option<String>,
    pub with_ties: Option<String>,
    pub input_pre_sorted_by: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ColumnOutput {
    pub symbol: String,
    #[serde(rename = "type")]
    pub _type: String,
}
