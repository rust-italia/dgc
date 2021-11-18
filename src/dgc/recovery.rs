use serde::{Deserialize, Serialize};

use super::valuesets::expand_value;

/// Recovery Entry
/// https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Recovery {
    /// Disease agent targeted
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted
    pub tg: String,
    /// ISO 8601 complete date of first positive NAA test result
    pub fr: String,
    /// Country of Test
    /// https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt]
    pub co: String,
    /// Certificate Issuer
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer
    pub is: String,
    /// ISO 8601 complete date: Certificate Valid From
    pub df: String,
    /// ISO 8601 complete date: Certificate Valid Until
    pub du: String,
    /// Unique Certificate Identifier, UVCI
    /// https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id
    pub ci: String,
}

impl Recovery {
    pub fn expand_values(&self) -> Self {
        let mut expanded = self.clone();
        expanded.tg = expand_value(&expanded.tg);
        expanded.fr = expand_value(&expanded.fr);
        expanded.co = expand_value(&expanded.co);
        expanded
    }
}
