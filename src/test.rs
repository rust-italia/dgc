use std::borrow::Cow;

use crate::lookup_value;
use serde::{Deserialize, Serialize};

/// Test entry
/// <https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json>
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Test {
    /// Disease agent targeted
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted`
    pub tg: Cow<'static, str>,
    /// Type of test
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-type`
    pub tt: Cow<'static, str>,
    /// NAA Test Name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nm: Option<String>,
    /// RAT Test name and manufacturer
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-manf`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ma: Option<Cow<'static, str>>,
    /// Date/Time of Sample Collection
    pub sc: String,
    /// Date/Time (???)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dr: Option<String>,
    /// Test Result
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/test-result`
    pub tr: Cow<'static, str>,
    /// Testing Centre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tc: Option<String>,
    /// Country of Test
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt`
    pub co: Cow<'static, str>,
    /// Certificate Issuer
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer`
    pub is: Cow<'static, str>,
    /// Unique Certificate Identifier, UVCI
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id`
    pub ci: String,
}

impl Test {
    pub fn expand_values(&mut self) {
        self.tg = lookup_value(&self.tg);
        self.tt = lookup_value(&self.tt);
        self.tr = lookup_value(&self.tr);
        if let Some(ma) = &mut self.ma {
            *ma = lookup_value(ma);
        }
        self.co = lookup_value(&self.co);
        self.is = lookup_value(&self.is);
    }
}
