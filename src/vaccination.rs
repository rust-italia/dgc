use std::borrow::Cow;

use crate::lookup_value;
use serde::{Deserialize, Serialize};

/// <https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json>

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Vaccination {
    /// disease or agent targeted
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted`
    pub tg: Cow<'static, str>,
    /// vaccine or prophylaxis
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/vaccine-prophylaxis`
    pub vp: Cow<'static, str>,
    /// vaccine medicinal product
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/vaccine-medicinal-product`
    pub mp: Cow<'static, str>,
    /// Marketing Authorization Holder - if no MAH present, then manufacturer
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/vaccine-mah-manf`
    pub ma: Cow<'static, str>,
    /// Dose Number
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/dose_posint`
    pub dn: usize,
    /// Total Series of Doses
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/dose_posint`
    pub sd: usize,
    /// ISO8601 complete date: Date of Vaccination
    pub dt: String,
    /// Country of Vaccination
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt`
    pub co: Cow<'static, str>,
    /// Certificate Issuer
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer`
    pub is: String,
    /// Unique Certificate Identifier: UVCI
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id`
    pub ci: String,
}

impl Vaccination {
    pub fn expand_values(&mut self) {
        self.tg = lookup_value(&self.tg);
        self.vp = lookup_value(&self.vp);
        self.mp = lookup_value(&self.mp);
        self.ma = lookup_value(&self.ma);
        self.co = lookup_value(&self.co);
    }
}
