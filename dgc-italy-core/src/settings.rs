//! A set of helpers to handle official DGC settings.

use std::{borrow::Cow, fmt};

use serde::{
    de::{self, value::StrDeserializer, IntoDeserializer},
    Deserialize, Serialize,
};

/// The URL from which the settings can be retrieved in JSON format.
pub const URL: &str = "https://get.dgc.gov.it/v1/dgc/settings";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Settings<'a> {
    pub vaccines: Vaccines,
    pub deny_list: DenyList<'a>,
    pub min_versions: MinVersions<'a>,
    pub tests: Tests,
    pub recovery: Recovery,
    pub generic_vaccine: GenericVaccine,
    pub unknown: Vec<RawSetting<'a>>,
}

#[derive(Debug, Default)]
struct PartialSettings<'a> {
    vaccines: PartialVaccines,
    deny_list: Option<&'a str>,
    min_versions: PartialMinVersions<'a>,
    tests: PartialTests,
    recovery: PartialRecovery,
    generic_vaccine: PartialGenericVaccine,
    unknown: Vec<RawSetting<'a>>,
}

impl<'a> PartialSettings<'a> {
    fn get_field(&mut self, ty: SettingType, name: SettingName) -> Option<InnerField<'a, '_>> {
        use SettingName::*;
        use SettingType::*;

        Some(match ty {
            JensenVaccine | VaxzevriaVaccine | SpikevaxVaccine | ComirnatyVaccine
            | CoviShieldVaccine | RCoviVaccine | RecombinantVaccine | SputnikVaccine => {
                let vaccines = &mut self.vaccines;
                let vaccine = match ty {
                    JensenVaccine => &mut vaccines.jensen,
                    VaxzevriaVaccine => &mut vaccines.vaxzevria,
                    SpikevaxVaccine => &mut vaccines.spikevax,
                    ComirnatyVaccine => &mut vaccines.comirnaty,
                    CoviShieldVaccine => &mut vaccines.covi_shield,
                    RCoviVaccine => &mut vaccines.r_covi,
                    RecombinantVaccine => &mut vaccines.recombinant,
                    SputnikVaccine => &mut vaccines.sputnik,
                    Generic | AppMinVersion | DenyList => unreachable!(),
                };

                InnerField::U16(match name {
                    VaccineStartDayComplete => &mut vaccine.start_day_complete,
                    VaccineEndDayComplete => &mut vaccine.end_day_complete,
                    VaccineStartDayNotComplete => &mut vaccine.start_day_not_complete,
                    VaccineEndDayNotComplete => &mut vaccine.end_day_not_complete,
                    _ => return None,
                })
            }
            Generic => match name {
                RapidTestStartHours => InnerField::U8(&mut self.tests.rapid.start_hours),
                RapidTestEndHours => InnerField::U8(&mut self.tests.rapid.end_hours),
                MolecularTestStartHours => InnerField::U8(&mut self.tests.molecular.start_hours),
                MolecularTestEndHours => InnerField::U8(&mut self.tests.molecular.end_hours),
                RecoveryCertStartDay
                | RecoveryCertEndDay
                | RecoveryPvCertStartDay
                | RecoveryPvCertEndDay
                | RecoveryCertStartDayIt
                | RecoveryCertEndDayIt
                | RecoveryCertStartDayNotIt
                | RecoveryCertEndDayNotIt => {
                    let recovery = &mut self.recovery;
                    InnerField::U16(match name {
                        RecoveryCertStartDay => &mut recovery.cert.start_day,
                        RecoveryCertEndDay => &mut recovery.cert.end_day,
                        RecoveryPvCertStartDay => &mut recovery.pv_cert.start_day,
                        RecoveryPvCertEndDay => &mut recovery.pv_cert.end_day,
                        RecoveryCertStartDayIt => &mut recovery.cert_it.start_day,
                        RecoveryCertEndDayIt => &mut recovery.cert_it.end_day,
                        RecoveryCertStartDayNotIt => &mut recovery.cert_not_it.start_day,
                        RecoveryCertEndDayNotIt => &mut recovery.cert_not_it.end_day,
                        _ => unreachable!(),
                    })
                }
                VaccineStartDayCompleteIt
                | VaccineEndDayCompleteIt
                | VaccineStartDayCompleteNotIt
                | VaccineEndDayCompleteNotIt
                | VaccineStartDayBoosterIt
                | VaccineEndDayBoosterIt
                | VaccineStartDayBoosterNotIt
                | VaccineEndDayBoosterNotIt => {
                    let vaccine = &mut self.generic_vaccine;
                    InnerField::U16(match name {
                        VaccineStartDayCompleteIt => &mut vaccine.complete_it.start_day,
                        VaccineEndDayCompleteIt => &mut vaccine.complete_it.end_day,
                        VaccineStartDayCompleteNotIt => &mut vaccine.complete_not_it.start_day,
                        VaccineEndDayCompleteNotIt => &mut vaccine.complete_not_it.end_day,
                        VaccineStartDayBoosterIt => &mut vaccine.booster_it.start_day,
                        VaccineEndDayBoosterIt => &mut vaccine.booster_it.end_day,
                        VaccineStartDayBoosterNotIt => &mut vaccine.booster_not_it.start_day,
                        VaccineEndDayBoosterNotIt => &mut vaccine.booster_not_it.end_day,
                        _ => unreachable!(),
                    })
                }
                VaccineStartDayComplete
                | VaccineEndDayComplete
                | VaccineStartDayNotComplete
                | VaccineEndDayNotComplete
                | Ios
                | Android
                | BlackListUvci => unreachable!(),
            },
            AppMinVersion => {
                let min_ver = &mut self.min_versions;
                InnerField::Str(match name {
                    Ios => &mut min_ver.ios,
                    Android => &mut min_ver.android,
                    _ => return None,
                })
            }
            DenyList => match name {
                BlackListUvci => InnerField::Str(&mut self.deny_list),
                _ => return None,
            },
        })
    }
}

#[derive(Debug)]
enum InnerField<'a: 'b, 'b> {
    U8(&'b mut Option<u8>),
    U16(&'b mut Option<u16>),
    Str(&'b mut Option<&'a str>),
}

#[derive(Debug)]
enum InnerFieldOwned<'a> {
    U8(u8),
    U16(u16),
    Str(&'a str),
}

impl<'a: 'b, 'b> InnerField<'a, 'b> {
    fn try_set(&mut self, raw: &'a str) -> Result<Option<InnerFieldOwned<'a>>, &str> {
        use InnerField::*;
        Ok(match self {
            U8(value) => value
                .replace(raw.parse().map_err(|_| "u8 str")?)
                .map(InnerFieldOwned::U8),
            U16(value) => value
                .replace(raw.parse().map_err(|_| "u16 str")?)
                .map(InnerFieldOwned::U16),
            Str(s) => s.replace(raw).map(InnerFieldOwned::Str),
        })
    }
}

#[derive(Debug)]
enum Setting<'a> {
    Raw(RawSetting<'a>),
    Parsed {
        name: SettingName,
        ty: SettingType,
        value: &'a str,
    },
}

impl<'de: 'a, 'a> Deserialize<'de> for Setting<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SettingVisitor;
        impl<'de> de::Visitor<'de> for SettingVisitor {
            type Value = Setting<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with name, type and value")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                #[derive(Debug)]
                enum Data<'a, T> {
                    Raw(&'a str),
                    Parsed { data: T, raw: &'a str },
                }

                let mut name = None;
                let mut ty = None;
                let mut value = None;

                while let Some((key, val)) = map.next_entry::<_, &str>()? {
                    macro_rules! try_deserialize {
                        ($field:ident: $ty:ty, $field_name:literal) => {{
                            let new_val = <$ty>::deserialize::<StrDeserializer<A::Error>>(
                                val.into_deserializer(),
                            )
                            .ok()
                            .map(|data| Data::Parsed { raw: val, data })
                            .unwrap_or_else(|| Data::Raw(val));

                            if $field.replace(new_val).is_some() {
                                return Err(de::Error::duplicate_field($field_name));
                            }
                        }};
                    }

                    match key {
                        "name" => try_deserialize!(name: SettingName, "name"),
                        "type" => {
                            try_deserialize!(ty: SettingType, "type")
                        }
                        "value" => {
                            if value.replace(val).is_some() {
                                return Err(de::Error::custom(
                                    "type field found more than one time",
                                ));
                            }
                        }
                        _ => {
                            // FIXME: Should we ignore unknown fields or should we return an error?
                            // Or log if a logging crate is available?
                        }
                    }
                }

                match (name, ty, value) {
                    (None, _, _) => Err(de::Error::missing_field("name")),
                    (_, None, _) => Err(de::Error::missing_field("type")),
                    (_, _, None) => Err(de::Error::missing_field("value")),
                    (
                        Some(Data::Raw(name)),
                        Some(Data::Raw(ty) | Data::Parsed { raw: ty, .. }),
                        Some(value),
                    )
                    | (Some(Data::Parsed { raw: name, .. }), Some(Data::Raw(ty)), Some(value)) => {
                        let name = name.into();
                        let ty = ty.into();
                        let value = value.into();
                        Ok(Setting::Raw(RawSetting { name, ty, value }))
                    }
                    (
                        Some(Data::Parsed { data: name, .. }),
                        Some(Data::Parsed { data: ty, .. }),
                        Some(value),
                    ) => Ok(Setting::Parsed { name, ty, value }),
                }
            }
        }

        deserializer.deserialize_map(SettingVisitor)
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for Settings<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SettingsVisitor;
        impl<'de> de::Visitor<'de> for SettingsVisitor {
            type Value = PartialSettings<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of maps")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut partial_settings = PartialSettings::default();
                while let Some(setting) = seq.next_element()? {
                    match setting {
                        Setting::Parsed { name, ty, value } => {
                            let mut field = partial_settings
                                .get_field(ty, name)
                                .ok_or_else(|| de::Error::custom(InvalidSetting { name, ty }))?;

                            let old_value = field.try_set(value).map_err(|expected| {
                                de::Error::invalid_value(de::Unexpected::Str(value), &expected)
                            })?;
                            if old_value.is_some() {
                                return Err(de::Error::duplicate_field(name.as_str()));
                            }
                        }
                        Setting::Raw(raw_setting) => partial_settings.unknown.push(raw_setting),
                    }
                }
                Ok(partial_settings)
            }
        }

        let PartialSettings {
            vaccines,
            deny_list,
            min_versions,
            tests,
            recovery,
            generic_vaccine,
            unknown,
        } = deserializer.deserialize_seq(SettingsVisitor)?;

        let vaccines = vaccines.into_complete().map_err(de::Error::custom)?;
        let deny_list = deny_list
            .map(|deny_list| DenyList(deny_list.into()))
            .ok_or_else(|| de::Error::custom(IncompleteSettings::MissingDenyList))?;
        let min_versions = min_versions.into_complete().map_err(de::Error::custom)?;
        let tests = tests.into_complete().map_err(de::Error::custom)?;
        let recovery = recovery.into_complete().map_err(de::Error::custom)?;
        let generic_vaccine = generic_vaccine.into_complete().map_err(de::Error::custom)?;

        Ok(Self {
            vaccines,
            deny_list,
            min_versions,
            tests,
            recovery,
            generic_vaccine,
            unknown,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvalidSetting {
    pub name: SettingName,
    pub ty: SettingType,
}

impl fmt::Display for InvalidSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"invalid setting with type "{}" and name {}"#,
            self.ty, self.name
        )
    }
}

/// A direct representation of a DGC setting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct RawSetting<'a> {
    /// The name of the setting for the given type.
    pub name: Cow<'a, str>,

    /// The type of setting.
    #[serde(rename = "type")]
    pub ty: Cow<'a, str>,

    /// The value of the setting for the given type.
    pub value: Cow<'a, str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vaccines {
    pub jensen: VaccineSettings,
    pub vaxzevria: VaccineSettings,
    pub spikevax: VaccineSettings,
    pub comirnaty: VaccineSettings,
    pub covi_shield: VaccineSettings,
    pub r_covi: VaccineSettings,
    pub recombinant: VaccineSettings,
    pub sputnik: VaccineSettings,
}

#[derive(Debug, Default)]
struct PartialVaccines {
    jensen: PartialVaccineSettings,
    vaxzevria: PartialVaccineSettings,
    spikevax: PartialVaccineSettings,
    comirnaty: PartialVaccineSettings,
    covi_shield: PartialVaccineSettings,
    r_covi: PartialVaccineSettings,
    recombinant: PartialVaccineSettings,
    sputnik: PartialVaccineSettings,
}

impl PartialVaccines {
    fn into_complete(self) -> Result<Vaccines, IncompleteSettings> {
        use SettingType::*;

        let Self {
            jensen,
            vaxzevria,
            spikevax,
            comirnaty,
            covi_shield,
            r_covi,
            recombinant,
            sputnik,
        } = self;

        let jensen = jensen.into_complete(JensenVaccine)?;
        let vaxzevria = vaxzevria.into_complete(VaxzevriaVaccine)?;
        let spikevax = spikevax.into_complete(SpikevaxVaccine)?;
        let comirnaty = comirnaty.into_complete(ComirnatyVaccine)?;
        let covi_shield = covi_shield.into_complete(CoviShieldVaccine)?;
        let r_covi = r_covi.into_complete(RCoviVaccine)?;
        let recombinant = recombinant.into_complete(RecombinantVaccine)?;
        let sputnik = sputnik.into_complete(SputnikVaccine)?;

        Ok(Vaccines {
            jensen,
            vaxzevria,
            spikevax,
            comirnaty,
            covi_shield,
            r_covi,
            recombinant,
            sputnik,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaccineSettings {
    pub start_day_complete: u16,
    pub end_day_complete: u16,
    pub start_day_not_complete: u16,
    pub end_day_not_complete: u16,
}

#[derive(Debug, Default)]
struct PartialVaccineSettings {
    start_day_complete: Option<u16>,
    end_day_complete: Option<u16>,
    start_day_not_complete: Option<u16>,
    end_day_not_complete: Option<u16>,
}

impl PartialVaccineSettings {
    fn into_complete(self, ty: SettingType) -> Result<VaccineSettings, IncompleteSettings> {
        use SettingName::*;
        let Self {
            start_day_complete,
            end_day_complete,
            start_day_not_complete,
            end_day_not_complete,
        } = self;

        let start_day_complete =
            start_day_complete.ok_or(IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: ty,
                missing_field: VaccineStartDayComplete,
            }))?;
        let end_day_complete =
            end_day_complete.ok_or(IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: ty,
                missing_field: VaccineEndDayComplete,
            }))?;
        let start_day_not_complete = start_day_not_complete.ok_or(
            IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: ty,
                missing_field: VaccineStartDayNotComplete,
            }),
        )?;
        let end_day_not_complete = end_day_not_complete.ok_or(
            IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: ty,
                missing_field: VaccineEndDayNotComplete,
            }),
        )?;

        Ok(VaccineSettings {
            start_day_complete,
            end_day_complete,
            start_day_not_complete,
            end_day_not_complete,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DenyList<'a>(pub Cow<'a, str>);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MinVersions<'a> {
    pub ios: Cow<'a, str>,
    pub android: Cow<'a, str>,
}

#[derive(Debug, Default)]
struct PartialMinVersions<'a> {
    ios: Option<&'a str>,
    android: Option<&'a str>,
}

impl<'a> PartialMinVersions<'a> {
    fn into_complete(self) -> Result<MinVersions<'a>, IncompleteSettings> {
        use SettingName::*;
        use SettingType::*;

        let Self { ios, android } = self;

        let ios = ios
            .map(Cow::from)
            .ok_or(IncompleteSettings::IncompleteMinVersion(
                IncompleteSetting {
                    setting: AppMinVersion,
                    missing_field: Ios,
                },
            ))?;
        let android = android
            .map(Cow::from)
            .ok_or(IncompleteSettings::IncompleteMinVersion(
                IncompleteSetting {
                    setting: AppMinVersion,
                    missing_field: Android,
                },
            ))?;

        Ok(MinVersions { ios, android })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tests {
    pub rapid: TestData,
    pub molecular: TestData,
}

#[derive(Debug, Default)]
struct PartialTests {
    rapid: PartialTestData,
    molecular: PartialTestData,
}

impl PartialTests {
    fn into_complete(self) -> Result<Tests, IncompleteSettings> {
        use SettingName::*;
        use SettingType::*;

        let Self { rapid, molecular } = self;

        let rapid = {
            let PartialTestData {
                start_hours,
                end_hours,
            } = rapid;

            let start_hours =
                start_hours.ok_or(IncompleteSettings::IncompleteTest(IncompleteSetting {
                    setting: Generic,
                    missing_field: RapidTestStartHours,
                }))?;
            let end_hours =
                end_hours.ok_or(IncompleteSettings::IncompleteTest(IncompleteSetting {
                    setting: Generic,
                    missing_field: RapidTestEndHours,
                }))?;

            TestData {
                start_hours,
                end_hours,
            }
        };
        let molecular = {
            let PartialTestData {
                start_hours,
                end_hours,
            } = molecular;

            let start_hours =
                start_hours.ok_or(IncompleteSettings::IncompleteTest(IncompleteSetting {
                    setting: Generic,
                    missing_field: MolecularTestStartHours,
                }))?;
            let end_hours =
                end_hours.ok_or(IncompleteSettings::IncompleteTest(IncompleteSetting {
                    setting: Generic,
                    missing_field: MolecularTestEndHours,
                }))?;

            TestData {
                start_hours,
                end_hours,
            }
        };

        Ok(Tests { rapid, molecular })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TestData {
    pub start_hours: u8,
    pub end_hours: u8,
}

#[derive(Debug, Default)]
struct PartialTestData {
    start_hours: Option<u8>,
    end_hours: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Recovery {
    pub cert: Interval,
    pub pv_cert: Interval,
    pub cert_it: Interval,
    pub cert_not_it: Interval,
}

#[derive(Debug, Default)]
struct PartialRecovery {
    cert: PartialInterval,
    pv_cert: PartialInterval,
    cert_it: PartialInterval,
    cert_not_it: PartialInterval,
}

impl PartialRecovery {
    fn into_complete(self) -> Result<Recovery, IncompleteSettings> {
        use SettingName::*;

        let Self {
            cert,
            pv_cert,
            cert_it,
            cert_not_it,
        } = self;

        let cert = cert.into_complete(RecoveryCertStartDay, RecoveryCertEndDay)?;
        let pv_cert = pv_cert.into_complete(RecoveryPvCertStartDay, RecoveryPvCertEndDay)?;
        let cert_it = cert_it.into_complete(RecoveryCertStartDayIt, RecoveryCertEndDayIt)?;
        let cert_not_it =
            cert_not_it.into_complete(RecoveryCertStartDayNotIt, RecoveryCertEndDayNotIt)?;

        Ok(Recovery {
            cert,
            pv_cert,
            cert_it,
            cert_not_it,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenericVaccine {
    pub complete_it: Interval,
    pub booster_it: Interval,
    pub complete_not_it: Interval,
    pub booster_not_it: Interval,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartialGenericVaccine {
    pub complete_it: PartialInterval,
    pub booster_it: PartialInterval,
    pub complete_not_it: PartialInterval,
    pub booster_not_it: PartialInterval,
}

impl PartialGenericVaccine {
    fn into_complete(self) -> Result<GenericVaccine, IncompleteSettings> {
        use SettingName::*;

        let Self {
            complete_it,
            booster_it,
            complete_not_it,
            booster_not_it,
        } = self;

        let complete_it =
            complete_it.into_complete(VaccineStartDayCompleteIt, VaccineEndDayCompleteIt)?;
        let booster_it =
            booster_it.into_complete(VaccineStartDayBoosterIt, VaccineEndDayBoosterIt)?;
        let complete_not_it = complete_not_it
            .into_complete(VaccineStartDayCompleteNotIt, VaccineEndDayCompleteNotIt)?;
        let booster_not_it =
            booster_not_it.into_complete(VaccineStartDayBoosterNotIt, VaccineEndDayBoosterNotIt)?;

        Ok(GenericVaccine {
            complete_it,
            booster_it,
            complete_not_it,
            booster_not_it,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interval {
    pub start_day: u16,
    pub end_day: u16,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartialInterval {
    pub start_day: Option<u16>,
    pub end_day: Option<u16>,
}

impl PartialInterval {
    fn into_complete(
        self,
        start_name: SettingName,
        end_name: SettingName,
    ) -> Result<Interval, IncompleteSettings> {
        use SettingType::*;

        let Self { start_day, end_day } = self;

        let start_day =
            start_day.ok_or(IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: Generic,
                missing_field: start_name,
            }))?;

        let end_day = end_day.ok_or(IncompleteSettings::IncompleteRecovery(IncompleteSetting {
            setting: Generic,
            missing_field: end_name,
        }))?;

        Ok(Interval { start_day, end_day })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[non_exhaustive]
pub enum SettingType {
    #[serde(rename = "EU/1/20/1525")]
    JensenVaccine,

    #[serde(rename = "EU/1/21/1529")]
    VaxzevriaVaccine,

    #[serde(rename = "EU/1/20/1507")]
    SpikevaxVaccine,

    #[serde(rename = "EU/1/20/1528")]
    ComirnatyVaccine,

    #[serde(rename = "GENERIC")]
    Generic,

    #[serde(rename = "APP_MIN_VERSION")]
    AppMinVersion,

    #[serde(rename = "Covishield")]
    CoviShieldVaccine,

    #[serde(rename = "R-COVI")]
    RCoviVaccine,

    #[serde(rename = "Covid-19-recombinant")]
    RecombinantVaccine,

    #[serde(rename = "black_list_uvci")]
    DenyList,

    #[serde(rename = "Sputnik-V")]
    SputnikVaccine,
}

impl fmt::Display for SettingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SettingType::*;
        let s = match self {
            JensenVaccine => "Jensen Vaccine (EU/1/20/1525)",
            VaxzevriaVaccine => "Vaxzevria Vaccine (EU/1/21/1529)",
            SpikevaxVaccine => "Spikevax Vaccine (EU/1/20/1507)",
            ComirnatyVaccine => "Comirnaty Vaccine (EU/1/20/1528)",
            Generic => "Generic (GENERIC)",
            AppMinVersion => "App minimum version (APP_MIN_VERSION)",
            CoviShieldVaccine => "Covishield Vaccine (Covishield)",
            RCoviVaccine => "R-CoVI (R-COVI)",
            RecombinantVaccine => "Covid-19 vaccine-recombinant (Covid-19-recombinant)",
            DenyList => "Deny list (black_list_uvci)",
            SputnikVaccine => "Sputnik V Vaccine (Sputnik-V)",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SettingName {
    VaccineStartDayComplete,
    VaccineEndDayComplete,
    VaccineStartDayNotComplete,
    VaccineEndDayNotComplete,
    RapidTestStartHours,
    RapidTestEndHours,
    MolecularTestStartHours,
    MolecularTestEndHours,
    RecoveryCertStartDay,
    RecoveryCertEndDay,
    Ios,
    Android,
    BlackListUvci,
    RecoveryPvCertStartDay,
    RecoveryPvCertEndDay,
    #[serde(rename = "recovery_cert_start_day_IT")]
    RecoveryCertStartDayIt,
    #[serde(rename = "recovery_cert_end_day_IT")]
    RecoveryCertEndDayIt,
    #[serde(rename = "recovery_cert_start_day_NOT_IT")]
    RecoveryCertStartDayNotIt,
    #[serde(rename = "recovery_cert_end_day_NOT_IT")]
    RecoveryCertEndDayNotIt,
    #[serde(rename = "vaccine_start_day_complete_IT")]
    VaccineStartDayCompleteIt,
    #[serde(rename = "vaccine_end_day_complete_IT")]
    VaccineEndDayCompleteIt,
    #[serde(rename = "vaccine_start_day_complete_NOT_IT")]
    VaccineStartDayCompleteNotIt,
    #[serde(rename = "vaccine_end_day_complete_NOT_IT")]
    VaccineEndDayCompleteNotIt,
    #[serde(rename = "vaccine_start_day_booster_IT")]
    VaccineStartDayBoosterIt,
    #[serde(rename = "vaccine_end_day_booster_IT")]
    VaccineEndDayBoosterIt,
    #[serde(rename = "vaccine_start_day_booster_NOT_IT")]
    VaccineStartDayBoosterNotIt,
    #[serde(rename = "vaccine_end_day_booster_NOT_IT")]
    VaccineEndDayBoosterNotIt,
}

impl SettingName {
    pub fn as_str(self) -> &'static str {
        use SettingName::*;

        match self {
            VaccineStartDayComplete => "vaccine_start_day_complete",
            VaccineEndDayComplete => "vaccine_end_day_complete",
            VaccineStartDayNotComplete => "vaccine_start_day_not_complete",
            VaccineEndDayNotComplete => "vaccine_end_day_not_complete",
            RapidTestStartHours => "rapid_test_start_hours",
            RapidTestEndHours => "rapid_test_end_hours",
            MolecularTestStartHours => "molecular_test_start_hours",
            MolecularTestEndHours => "molecular_test_end_hours",
            RecoveryCertStartDay => "recovery_cert_start_day",
            RecoveryCertEndDay => "recovery_cert_end_day",
            Ios => "ios",
            Android => "android",
            BlackListUvci => "black_list_uvci",
            RecoveryPvCertStartDay => "recovery_pv_cert_start_day",
            RecoveryPvCertEndDay => "recovery_pv_cert_end_day",
            RecoveryCertStartDayIt => "recovery_cert_start_day_IT",
            RecoveryCertEndDayIt => "recovery_cert_end_day_IT",
            RecoveryCertStartDayNotIt => "recovery_cert_start_day_NOT_IT",
            RecoveryCertEndDayNotIt => "recovery_cert_end_day_NOT_IT",
            VaccineStartDayCompleteIt => "vaccine_start_day_complete_IT",
            VaccineEndDayCompleteIt => "vaccine_end_day_complete_IT",
            VaccineStartDayCompleteNotIt => "vaccine_start_day_complete_NOT_IT",
            VaccineEndDayCompleteNotIt => "vaccine_end_day_complete_NOT_IT",
            VaccineStartDayBoosterIt => "vaccine_start_day_booster_IT",
            VaccineEndDayBoosterIt => "vaccine_end_day_booster_IT",
            VaccineStartDayBoosterNotIt => "vaccine_start_day_booster_NOT_IT",
            VaccineEndDayBoosterNotIt => "vaccine_end_day_booster_NOT_IT",
        }
    }
}

impl fmt::Display for SettingName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncompleteSettings {
    IncompleteVaccine(IncompleteSetting),
    MissingDenyList,
    IncompleteMinVersion(IncompleteSetting),
    IncompleteTest(IncompleteSetting),
    IncompleteRecovery(IncompleteSetting),
}

impl fmt::Display for IncompleteSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IncompleteSettings::*;

        match self {
            MissingDenyList => f.write_str("UVCI deny list is missing"),
            IncompleteVaccine(incomplete)
            | IncompleteMinVersion(incomplete)
            | IncompleteTest(incomplete)
            | IncompleteRecovery(incomplete) => match self {
                IncompleteVaccine(_) => write!(f, "incomplete vaccines, {}", incomplete),
                IncompleteMinVersion(_) => write!(f, "incomplete app min versions, {}", incomplete),
                IncompleteTest(_) => write!(f, "incomplete tests, {}", incomplete),
                IncompleteRecovery(_) => write!(f, "incomplete recovery, {}", incomplete),
                MissingDenyList => unreachable!(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IncompleteSetting {
    setting: SettingType,
    missing_field: SettingName,
}

impl fmt::Display for IncompleteSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"setting = "{}", missing field = "{}""#,
            self.setting, self.missing_field
        )
    }
}
