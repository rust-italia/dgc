use crate::lookup_value;
use serde::{Deserialize, Serialize};

/// Test entry
/// <https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json>
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Test {
    /// Disease agent targeted
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted`
    pub tg: String,
    /// Type of test
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-type`
    pub tt: String,
    /// NAA Test Name
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nm: Option<String>,
    /// RAT Test name and manufacturer
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-manf`
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ma: Option<String>,
    /// Date/Time of Sample Collection
    pub sc: String,
    /// Date/Time (???)
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dr: Option<String>,
    /// Test Result
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-result`
    pub tr: String,
    /// Testing Centre
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tc: Option<String>,
    /// Country of Test
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt`
    pub co: String,
    /// Certificate Issuer
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer`
    pub is: String,
    /// Unique Certificate Identifier, UVCI
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id`
    pub ci: String,
}

impl Test {
    pub fn expand_values(&self) -> Self {
        let mut expanded = self.clone();
        expanded.tg = lookup_value(&expanded.tg);
        expanded.tt = lookup_value(&expanded.tt);
        expanded.tr = lookup_value(&expanded.tr);
        expanded.ma = expanded.ma.map(|v| lookup_value(&v));
        expanded.co = lookup_value(&expanded.co);
        expanded.is = lookup_value(&expanded.is);
        expanded
    }
}
