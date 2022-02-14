//! A set of helpers to handle official DGC settings.

use std::{borrow::Cow, fmt};

use serde::{
    de::{self, value::StrDeserializer, IntoDeserializer},
    Deserialize, Serialize,
};

/// The URL from which the settings can be retrieved in JSON format.
pub const URL: &str = "https://get.dgc.gov.it/v1/dgc/settings";

/// A typed representation of the settings exposed from [official APIs](URL).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Settings<'a> {
    /// Settings for approved vaccines.
    pub vaccines: Vaccines,

    /// A list of Unique Vaccination Certificate/Assertion Identifiers (UVCIs) that must be
    /// considered invalid.
    pub deny_list: DenyList<'a>,

    /// Minimal app versions by OS.
    pub min_versions: MinVersions<'a>,

    /// Settings for COVID-19 tests.
    pub tests: Tests,

    /// Interval settings related to recoveries.
    pub recovery: Recovery,

    /// Interval settings related to generic vaccine.
    pub generic_vaccine: GenericVaccine,

    /// A list of unknown settings.
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
            JanssenVaccine | VaxzevriaVaccine | SpikevaxVaccine | ComirnatyVaccine
            | CovishieldVaccine | RCoviVaccine | RecombinantVaccine | SputnikVVaccine => {
                let vaccines = &mut self.vaccines;
                let vaccine = match ty {
                    JanssenVaccine => &mut vaccines.janssen,
                    VaxzevriaVaccine => &mut vaccines.vaxzevria,
                    SpikevaxVaccine => &mut vaccines.spikevax,
                    ComirnatyVaccine => &mut vaccines.comirnaty,
                    CovishieldVaccine => &mut vaccines.covi_shield,
                    RCoviVaccine => &mut vaccines.r_covi,
                    RecombinantVaccine => &mut vaccines.recombinant,
                    SputnikVVaccine => &mut vaccines.sputnik_v,
                    Generic | AppMinVersion | DenyList => unreachable!(),
                };

                InnerField::U16(match name {
                    VaccineStartDayComplete => &mut vaccine.complete.start_day,
                    VaccineEndDayComplete => &mut vaccine.complete.end_day,
                    VaccineStartDayNotComplete => &mut vaccine.not_complete.start_day,
                    VaccineEndDayNotComplete => &mut vaccine.not_complete.end_day,
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

#[derive(Debug, PartialEq, Eq)]
enum InnerField<'a: 'b, 'b> {
    U8(&'b mut Option<u8>),
    U16(&'b mut Option<u16>),
    Str(&'b mut Option<&'a str>),
}

#[derive(Debug, PartialEq, Eq)]
enum InnerFieldOwned<'a> {
    U8(u8),
    U16(u16),
    Str(&'a str),
}

#[derive(Debug, PartialEq)]
enum InnerFieldError {
    U8,
    U16,
}

impl de::Expected for InnerFieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::U8 => formatter.write_str("a u8 str"),
            Self::U16 => formatter.write_str("a u16 str"),
        }
    }
}

impl<'a: 'b, 'b> InnerField<'a, 'b> {
    fn try_set(&mut self, raw: &'a str) -> Result<Option<InnerFieldOwned<'a>>, InnerFieldError> {
        use InnerField::*;
        Ok(match self {
            U8(value) => value
                .replace(raw.parse().map_err(|_| InnerFieldError::U8)?)
                .map(InnerFieldOwned::U8),
            U16(value) => value
                .replace(raw.parse().map_err(|_| InnerFieldError::U16)?)
                .map(InnerFieldOwned::U16),
            Str(s) => s.replace(raw).map(InnerFieldOwned::Str),
        })
    }
}

#[derive(Debug, PartialEq)]
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
                                return Err(de::Error::duplicate_field("value"));
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

/// An invalid pair of name and type parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvalidSetting {
    /// The name of the setting.
    pub name: SettingName,

    /// The type of the setting.
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

/// A list of vaccine settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Vaccines {
    /// COVID-19 vaccine Janssen (EU/1/20/1525)
    pub janssen: VaccineSettings,

    /// Vaxzevria vaccine (EU/1/21/1529)
    pub vaxzevria: VaccineSettings,

    /// Spikevax vaccine (EU/1/20/1507)
    pub spikevax: VaccineSettings,

    /// Comirnaty vaccine (EU/1/20/1528)
    pub comirnaty: VaccineSettings,

    /// Covishield vaccine
    pub covishield: VaccineSettings,

    /// R-CoVI vaccine
    pub r_covi: VaccineSettings,

    /// Covid-19 (recombinant) vaccine
    pub recombinant: VaccineSettings,

    /// Sputnik-V vaccine
    pub sputnik_v: VaccineSettings,
}

#[derive(Debug, Default)]
struct PartialVaccines {
    janssen: PartialVaccineSettings,
    vaxzevria: PartialVaccineSettings,
    spikevax: PartialVaccineSettings,
    comirnaty: PartialVaccineSettings,
    covi_shield: PartialVaccineSettings,
    r_covi: PartialVaccineSettings,
    recombinant: PartialVaccineSettings,
    sputnik_v: PartialVaccineSettings,
}

impl PartialVaccines {
    fn into_complete(self) -> Result<Vaccines, IncompleteSettings> {
        use SettingType::*;

        let Self {
            janssen,
            vaxzevria,
            spikevax,
            comirnaty,
            covi_shield,
            r_covi,
            recombinant,
            sputnik_v,
        } = self;

        let janssen = janssen.into_complete(JanssenVaccine)?;
        let vaxzevria = vaxzevria.into_complete(VaxzevriaVaccine)?;
        let spikevax = spikevax.into_complete(SpikevaxVaccine)?;
        let comirnaty = comirnaty.into_complete(ComirnatyVaccine)?;
        let covishield = covi_shield.into_complete(CovishieldVaccine)?;
        let r_covi = r_covi.into_complete(RCoviVaccine)?;
        let recombinant = recombinant.into_complete(RecombinantVaccine)?;
        let sputnik_v = sputnik_v.into_complete(SputnikVVaccine)?;

        Ok(Vaccines {
            janssen,
            vaxzevria,
            spikevax,
            comirnaty,
            covishield,
            r_covi,
            recombinant,
            sputnik_v,
        })
    }
}

/// Settings for a vaccine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaccineSettings {
    /// Settings for a complete vaccination cycle.
    pub complete: Interval,

    /// Settings for an incomplete vaccination cycle.
    pub not_complete: Interval,
}

#[derive(Debug, Default)]
struct PartialVaccineSettings {
    pub complete: PartialInterval,
    pub not_complete: PartialInterval,
}

impl PartialVaccineSettings {
    fn into_complete(self, ty: SettingType) -> Result<VaccineSettings, IncompleteSettings> {
        use SettingName::*;
        let Self {
            complete,
            not_complete,
        } = self;

        let complete = complete.into_complete(
            ty,
            VaccineStartDayComplete,
            VaccineEndDayComplete,
            IncompleteSettings::IncompleteVaccine,
        )?;
        let not_complete = not_complete.into_complete(
            ty,
            VaccineStartDayNotComplete,
            VaccineEndDayNotComplete,
            IncompleteSettings::IncompleteVaccine,
        )?;

        Ok(VaccineSettings {
            complete,
            not_complete,
        })
    }
}

/// A wrapper to help handling a list a Unique Vaccination Certificate/Assertion Identifiers (UVCIs) that must be considered invalid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DenyList<'a>(
    /// The raw representation of the deny list.
    pub Cow<'a, str>,
);

/// Minimal app versions by OS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MinVersions<'a> {
    /// Minimal app versions for iOS.
    pub ios: Cow<'a, str>,

    /// Minimal app versions for Android.
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

/// Settings for COVID-19 tests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tests {
    /// Settings for rapid antigenic test.
    pub rapid: TestData,

    /// Settings for molecular test.
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

/// Settings for a COVID-19 test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TestData {
    /// The hours that must pass from the test for its validity.
    pub start_hours: u8,

    /// The hours after which the test is not valid anymore.
    pub end_hours: u8,
}

#[derive(Debug, Default)]
struct PartialTestData {
    start_hours: Option<u8>,
    end_hours: Option<u8>,
}

// FIXME: what's the meaning of these fields?
/// Settings for COVID-19 recovery.
#[allow(missing_docs)]
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
        use SettingType::*;

        let Self {
            cert,
            pv_cert,
            cert_it,
            cert_not_it,
        } = self;

        let cert = cert.into_complete(
            Generic,
            RecoveryCertStartDay,
            RecoveryCertEndDay,
            IncompleteSettings::IncompleteRecovery,
        )?;
        let pv_cert = pv_cert.into_complete(
            Generic,
            RecoveryPvCertStartDay,
            RecoveryPvCertEndDay,
            IncompleteSettings::IncompleteRecovery,
        )?;
        let cert_it = cert_it.into_complete(
            Generic,
            RecoveryCertStartDayIt,
            RecoveryCertEndDayIt,
            IncompleteSettings::IncompleteRecovery,
        )?;
        let cert_not_it = cert_not_it.into_complete(
            Generic,
            RecoveryCertStartDayNotIt,
            RecoveryCertEndDayNotIt,
            IncompleteSettings::IncompleteRecovery,
        )?;

        Ok(Recovery {
            cert,
            pv_cert,
            cert_it,
            cert_not_it,
        })
    }
}

/// Interval settings related to generic vaccine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenericVaccine {
    /// Settings for a complete vaccination cycle in Italy.
    pub complete_it: Interval,

    /// Settings for a _booster_ vaccination cycle (complete + dose/recovery) in Italy.
    pub booster_it: Interval,

    /// Settings for a complete vaccination cycle not in Italy.
    pub complete_not_it: Interval,

    /// Settings for a _booster_ vaccination cycle (complete + dose/recovery) not in Italy.
    pub booster_not_it: Interval,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
struct PartialGenericVaccine {
    pub complete_it: PartialInterval,
    pub booster_it: PartialInterval,
    pub complete_not_it: PartialInterval,
    pub booster_not_it: PartialInterval,
}

impl PartialGenericVaccine {
    fn into_complete(self) -> Result<GenericVaccine, IncompleteSettings> {
        use SettingName::*;
        use SettingType::*;

        let Self {
            complete_it,
            booster_it,
            complete_not_it,
            booster_not_it,
        } = self;

        let complete_it = complete_it.into_complete(
            Generic,
            VaccineStartDayCompleteIt,
            VaccineEndDayCompleteIt,
            IncompleteSettings::IncompleteGenericVaccine,
        )?;
        let booster_it = booster_it.into_complete(
            Generic,
            VaccineStartDayBoosterIt,
            VaccineEndDayBoosterIt,
            IncompleteSettings::IncompleteGenericVaccine,
        )?;
        let complete_not_it = complete_not_it.into_complete(
            Generic,
            VaccineStartDayCompleteNotIt,
            VaccineEndDayCompleteNotIt,
            IncompleteSettings::IncompleteGenericVaccine,
        )?;
        let booster_not_it = booster_not_it.into_complete(
            Generic,
            VaccineStartDayBoosterNotIt,
            VaccineEndDayBoosterNotIt,
            IncompleteSettings::IncompleteGenericVaccine,
        )?;

        Ok(GenericVaccine {
            complete_it,
            booster_it,
            complete_not_it,
            booster_not_it,
        })
    }
}

/// A interval in days for vaccine validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interval {
    /// The days that must pass from the test for its validity.
    pub start_day: u16,

    /// The days after which the test is not valid anymore.
    pub end_day: u16,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
struct PartialInterval {
    pub start_day: Option<u16>,
    pub end_day: Option<u16>,
}

impl PartialInterval {
    fn into_complete<F>(
        self,
        setting: SettingType,
        start_name: SettingName,
        end_name: SettingName,
        err_fn: F,
    ) -> Result<Interval, IncompleteSettings>
    where
        F: FnOnce(IncompleteSetting) -> IncompleteSettings + Copy,
    {
        let Self { start_day, end_day } = self;

        let start_day = start_day.ok_or_else(|| {
            err_fn(IncompleteSetting {
                setting,
                missing_field: start_name,
            })
        })?;

        let end_day = end_day.ok_or_else(|| {
            err_fn(IncompleteSetting {
                setting,
                missing_field: end_name,
            })
        })?;

        Ok(Interval { start_day, end_day })
    }
}

/// The setting types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[non_exhaustive]
pub enum SettingType {
    /// COVID-19 vaccine Janssen (EU/1/20/1525)
    #[serde(rename = "EU/1/20/1525")]
    JanssenVaccine,

    /// Vaxzevria vaccine (EU/1/21/1529)
    #[serde(rename = "EU/1/21/1529")]
    VaxzevriaVaccine,

    /// Spikevax vaccine (EU/1/20/1507)
    #[serde(rename = "EU/1/20/1507")]
    SpikevaxVaccine,

    /// Comirnaty vaccine (EU/1/20/1528)
    #[serde(rename = "EU/1/20/1528")]
    ComirnatyVaccine,

    /// A generic setting.
    #[serde(rename = "GENERIC")]
    Generic,

    /// Minimal app versions by OS.
    #[serde(rename = "APP_MIN_VERSION")]
    AppMinVersion,

    /// Covishield vaccine
    #[serde(rename = "Covishield")]
    CovishieldVaccine,

    /// R-CoVI vaccine
    #[serde(rename = "R-COVI")]
    RCoviVaccine,

    /// Covid-19 (recombinant) vaccine
    #[serde(rename = "Covid-19-recombinant")]
    RecombinantVaccine,

    /// A list of Unique Vaccination Certificate/Assertion Identifiers (UVCIs) that must be
    /// considered invalid.
    #[serde(rename = "black_list_uvci")]
    DenyList,

    /// Sputnik-V vaccine
    #[serde(rename = "Sputnik-V")]
    SputnikVVaccine,
}

impl fmt::Display for SettingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SettingType::*;
        let s = match self {
            JanssenVaccine => "Janssen Vaccine (EU/1/20/1525)",
            VaxzevriaVaccine => "Vaxzevria Vaccine (EU/1/21/1529)",
            SpikevaxVaccine => "Spikevax Vaccine (EU/1/20/1507)",
            ComirnatyVaccine => "Comirnaty Vaccine (EU/1/20/1528)",
            Generic => "Generic (GENERIC)",
            AppMinVersion => "App minimum version (APP_MIN_VERSION)",
            CovishieldVaccine => "Covishield Vaccine (Covishield)",
            RCoviVaccine => "R-CoVI (R-COVI)",
            RecombinantVaccine => "Covid-19 vaccine-recombinant (Covid-19-recombinant)",
            DenyList => "Deny list (black_list_uvci)",
            SputnikVVaccine => "Sputnik V Vaccine (Sputnik-V)",
        };
        f.write_str(s)
    }
}

/// The setting names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[allow(missing_docs)]
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
    /// Get a static string representation for the setting name.
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

/// An error for incomplete settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncompleteSettings {
    /// Vaccines section is incomplete.
    IncompleteVaccine(IncompleteSetting),

    /// UVCI deny list is missing.
    MissingDenyList,

    /// Minimal app versions section is incomplete.
    IncompleteMinVersion(IncompleteSetting),

    /// Tests section is incomplete.
    IncompleteTest(IncompleteSetting),

    /// Recovery section is incomplete.
    IncompleteRecovery(IncompleteSetting),

    /// Generic vaccine section is incomplete.
    IncompleteGenericVaccine(IncompleteSetting),
}

impl fmt::Display for IncompleteSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IncompleteSettings::*;

        match self {
            MissingDenyList => f.write_str("UVCI deny list is missing"),
            IncompleteVaccine(incomplete)
            | IncompleteMinVersion(incomplete)
            | IncompleteTest(incomplete)
            | IncompleteRecovery(incomplete)
            | IncompleteGenericVaccine(incomplete) => match self {
                IncompleteVaccine(_) => write!(f, "incomplete vaccines, {}", incomplete),
                IncompleteMinVersion(_) => write!(f, "incomplete app min versions, {}", incomplete),
                IncompleteTest(_) => write!(f, "incomplete tests, {}", incomplete),
                IncompleteRecovery(_) => write!(f, "incomplete recovery, {}", incomplete),
                IncompleteGenericVaccine(_) => {
                    write!(f, "incomplete generic vaccine, {}", incomplete)
                }
                MissingDenyList => unreachable!(),
            },
        }
    }
}

/// Helper structure to identify which pair of setting type and setting name is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IncompleteSetting {
    /// The setting type.
    pub setting: SettingType,

    /// The setting name.
    pub missing_field: SettingName,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_field_try_set() {
        let mut value = Some(42);
        let mut inner_field = InnerField::U8(&mut value);

        assert_eq!(inner_field.try_set("24"), Ok(Some(InnerFieldOwned::U8(42))));
        assert_eq!(inner_field, InnerField::U8(&mut Some(24)));

        assert_eq!(inner_field.try_set("12a"), Err(InnerFieldError::U8));
        assert_eq!(inner_field, InnerField::U8(&mut Some(24)));
        assert_eq!(value, Some(24));

        let mut value = Some("hello world");
        let mut inner_field = InnerField::Str(&mut value);

        assert_eq!(
            inner_field.try_set("12a"),
            Ok(Some(InnerFieldOwned::Str("hello world")))
        );
        assert_eq!(inner_field, InnerField::Str(&mut Some("12a")));
        assert_eq!(value, Some("12a"));

        let mut value = None;
        let mut inner_field = InnerField::U16(&mut value);

        assert_eq!(inner_field.try_set("24"), Ok(None));
        assert_eq!(inner_field, InnerField::U16(&mut Some(24)));
    }

    #[test]
    fn deserialize_setting() {
        let data = r#"{
            "name": "vaccine_start_day_complete",
            "type": "EU/1/20/1525",
            "value": "0"
        }"#;

        let setting: Setting = serde_json::from_str(data).unwrap();
        assert_eq!(
            setting,
            Setting::Parsed {
                name: SettingName::VaccineStartDayComplete,
                ty: SettingType::JanssenVaccine,
                value: "0"
            }
        );
    }

    #[test]
    fn deserialize_invalid_setting() {
        let data = r#"{
            "name": "vaccine_start_day_complet",
            "type": "EU/1/20/1525",
            "value": "0"
        }"#;

        let setting: Setting = serde_json::from_str(data).unwrap();
        assert_eq!(
            setting,
            Setting::Raw(RawSetting {
                name: "vaccine_start_day_complet".into(),
                ty: "EU/1/20/1525".into(),
                value: "0".into(),
            })
        );

        let data = r#"{
            "name": "vaccine_start_day_complete",
            "type": "EU/1/20/1525",
            "value": 0
        }"#;
        assert!(serde_json::from_str::<Setting>(data).is_err());

        let data = r#"{
            "name": "vaccine_start_day_complete",
            "name": "vaccine_start_day_complete",
            "type": "EU/1/20/1525",
            "value": "0"
        }"#;
        assert!(serde_json::from_str::<Setting>(data).is_err());

        let data = r#"{
            "name": "vaccine_start_day_complete",
            "type": "EU/1/20/1525",
            "type": "EU/1/20/1525",
            "value": "0"
        }"#;
        assert!(serde_json::from_str::<Setting>(data).is_err());

        let data = r#"{
            "name": "vaccine_start_day_complete",
            "type": "EU/1/20/1525",
            "value": "0",
            "value": "0"
        }"#;
        assert!(serde_json::from_str::<Setting>(data).is_err());

        let data = r#"{
            "type": "EU/1/20/1525",
            "value": "0"
        }"#;
        assert!(serde_json::from_str::<Setting>(data).is_err());

        let data = r#"{
            "name": "vaccine_start_day_complete",
            "value": "0"
        }"#;
        assert!(serde_json::from_str::<Setting>(data).is_err());

        let data = r#"{
            "name": "vaccine_start_day_complete",
            "type": "EU/1/20/1525"
        }"#;
        assert!(serde_json::from_str::<Setting>(data).is_err());
    }

    #[test]
    fn partial_vaccine_settings_into_complete() {
        assert_eq!(
            PartialVaccineSettings {
                complete: PartialInterval {
                    start_day: Some(0),
                    end_day: Some(1)
                },
                not_complete: PartialInterval {
                    start_day: Some(2),
                    end_day: Some(3)
                },
            }
            .into_complete(SettingType::SpikevaxVaccine)
            .unwrap(),
            VaccineSettings {
                complete: Interval {
                    start_day: 0,
                    end_day: 1
                },
                not_complete: Interval {
                    start_day: 2,
                    end_day: 3
                }
            }
        );

        assert_eq!(
            PartialVaccineSettings {
                complete: PartialInterval {
                    start_day: None,
                    end_day: Some(1)
                },
                not_complete: PartialInterval {
                    start_day: Some(2),
                    end_day: Some(3)
                },
            }
            .into_complete(SettingType::SpikevaxVaccine)
            .unwrap_err(),
            IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: SettingType::SpikevaxVaccine,
                missing_field: SettingName::VaccineStartDayComplete,
            })
        );

        assert_eq!(
            PartialVaccineSettings {
                complete: PartialInterval {
                    start_day: Some(0),
                    end_day: None
                },
                not_complete: PartialInterval {
                    start_day: Some(2),
                    end_day: Some(3)
                },
            }
            .into_complete(SettingType::SpikevaxVaccine)
            .unwrap_err(),
            IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: SettingType::SpikevaxVaccine,
                missing_field: SettingName::VaccineEndDayComplete,
            })
        );

        assert_eq!(
            PartialVaccineSettings {
                complete: PartialInterval {
                    start_day: Some(0),
                    end_day: Some(1)
                },
                not_complete: PartialInterval {
                    start_day: None,
                    end_day: Some(3)
                },
            }
            .into_complete(SettingType::SpikevaxVaccine)
            .unwrap_err(),
            IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: SettingType::SpikevaxVaccine,
                missing_field: SettingName::VaccineStartDayNotComplete,
            })
        );

        assert_eq!(
            PartialVaccineSettings {
                complete: PartialInterval {
                    start_day: Some(0),
                    end_day: Some(1)
                },
                not_complete: PartialInterval {
                    start_day: Some(2),
                    end_day: None
                },
            }
            .into_complete(SettingType::SpikevaxVaccine)
            .unwrap_err(),
            IncompleteSettings::IncompleteVaccine(IncompleteSetting {
                setting: SettingType::SpikevaxVaccine,
                missing_field: SettingName::VaccineEndDayNotComplete,
            })
        );
    }

    #[test]
    fn partial_min_versions_into_complete() {
        assert_eq!(
            PartialMinVersions {
                ios: Some("ios"),
                android: Some("android")
            }
            .into_complete()
            .unwrap(),
            MinVersions {
                ios: "ios".into(),
                android: "android".into(),
            },
        );

        assert_eq!(
            PartialMinVersions {
                ios: None,
                android: Some("android"),
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteMinVersion(IncompleteSetting {
                setting: SettingType::AppMinVersion,
                missing_field: SettingName::Ios,
            })
        );

        assert_eq!(
            PartialMinVersions {
                ios: Some("ios"),
                android: None,
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteMinVersion(IncompleteSetting {
                setting: SettingType::AppMinVersion,
                missing_field: SettingName::Android,
            })
        );
    }

    #[test]
    fn partial_tests_into_complete() {
        assert_eq!(
            PartialTests {
                rapid: PartialTestData {
                    start_hours: Some(1),
                    end_hours: Some(2),
                },
                molecular: PartialTestData {
                    start_hours: Some(3),
                    end_hours: Some(4),
                }
            }
            .into_complete()
            .unwrap(),
            Tests {
                rapid: TestData {
                    start_hours: 1,
                    end_hours: 2,
                },
                molecular: TestData {
                    start_hours: 3,
                    end_hours: 4,
                }
            },
        );

        assert_eq!(
            PartialTests {
                rapid: PartialTestData {
                    start_hours: Some(1),
                    end_hours: None,
                },
                molecular: PartialTestData {
                    start_hours: Some(3),
                    end_hours: Some(4),
                }
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteTest(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RapidTestEndHours
            })
        );

        assert_eq!(
            PartialTests {
                rapid: PartialTestData {
                    start_hours: Some(1),
                    end_hours: Some(2),
                },
                molecular: PartialTestData {
                    start_hours: None,
                    end_hours: Some(4),
                }
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteTest(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::MolecularTestStartHours,
            })
        );

        assert_eq!(
            PartialTests {
                rapid: PartialTestData {
                    start_hours: Some(1),
                    end_hours: Some(2),
                },
                molecular: PartialTestData {
                    start_hours: Some(3),
                    end_hours: None,
                }
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteTest(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::MolecularTestEndHours,
            })
        );
    }

    #[test]
    fn partial_recovery_into_complete() {
        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap(),
            Recovery {
                cert: Interval {
                    start_day: 1,
                    end_day: 2,
                },
                pv_cert: Interval {
                    start_day: 3,
                    end_day: 4,
                },
                cert_it: Interval {
                    start_day: 5,
                    end_day: 6,
                },
                cert_not_it: Interval {
                    start_day: 7,
                    end_day: 8,
                },
            }
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: None,
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryCertStartDay,
            })
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: None,
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryCertEndDay,
            })
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: None,
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryPvCertStartDay,
            })
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: None,
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryPvCertEndDay,
            })
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: None,
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryCertStartDayIt,
            })
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: None,
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryCertEndDayIt,
            })
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: None,
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryCertStartDayNotIt,
            })
        );

        assert_eq!(
            PartialRecovery {
                cert: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                pv_cert: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                cert_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                cert_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: None,
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteRecovery(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::RecoveryCertEndDayNotIt,
            })
        );
    }

    #[test]
    fn partial_generic_vaccine_into_complete() {
        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap(),
            GenericVaccine {
                complete_it: Interval {
                    start_day: 1,
                    end_day: 2,
                },
                booster_it: Interval {
                    start_day: 3,
                    end_day: 4
                },
                complete_not_it: Interval {
                    start_day: 5,
                    end_day: 6,
                },
                booster_not_it: Interval {
                    start_day: 7,
                    end_day: 8,
                },
            }
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: None,
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineStartDayCompleteIt,
            })
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: None,
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineEndDayCompleteIt,
            })
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: None,
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineStartDayBoosterIt,
            })
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: None,
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineEndDayBoosterIt,
            })
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: None,
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineStartDayCompleteNotIt,
            })
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: None,
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineEndDayCompleteNotIt,
            })
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: None,
                    end_day: Some(8),
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineStartDayBoosterNotIt,
            })
        );

        assert_eq!(
            PartialGenericVaccine {
                complete_it: PartialInterval {
                    start_day: Some(1),
                    end_day: Some(2),
                },
                booster_it: PartialInterval {
                    start_day: Some(3),
                    end_day: Some(4),
                },
                complete_not_it: PartialInterval {
                    start_day: Some(5),
                    end_day: Some(6),
                },
                booster_not_it: PartialInterval {
                    start_day: Some(7),
                    end_day: None,
                },
            }
            .into_complete()
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::Generic,
                missing_field: SettingName::VaccineEndDayBoosterNotIt,
            })
        );
    }

    #[test]
    fn partial_interval_into_complete() {
        assert_eq!(
            PartialInterval {
                start_day: Some(1),
                end_day: Some(2),
            }
            .into_complete(
                SettingType::RCoviVaccine,
                SettingName::Ios,
                SettingName::Android,
                IncompleteSettings::IncompleteGenericVaccine,
            )
            .unwrap(),
            Interval {
                start_day: 1,
                end_day: 2,
            }
        );

        assert_eq!(
            PartialInterval {
                start_day: None,
                end_day: Some(2),
            }
            .into_complete(
                SettingType::RCoviVaccine,
                SettingName::Ios,
                SettingName::Android,
                IncompleteSettings::IncompleteGenericVaccine,
            )
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::RCoviVaccine,
                missing_field: SettingName::Ios,
            })
        );

        assert_eq!(
            PartialInterval {
                start_day: Some(1),
                end_day: None,
            }
            .into_complete(
                SettingType::RCoviVaccine,
                SettingName::Ios,
                SettingName::Android,
                IncompleteSettings::IncompleteGenericVaccine,
            )
            .unwrap_err(),
            IncompleteSettings::IncompleteGenericVaccine(IncompleteSetting {
                setting: SettingType::RCoviVaccine,
                missing_field: SettingName::Android,
            })
        );
    }

    #[test]
    fn setting_name_as_str_matches_deserialize() {
        use SettingName::*;

        const SETTING_NAMES: [SettingName; 27] = [
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
            RecoveryCertStartDayIt,
            RecoveryCertEndDayIt,
            RecoveryCertStartDayNotIt,
            RecoveryCertEndDayNotIt,
            VaccineStartDayCompleteIt,
            VaccineEndDayCompleteIt,
            VaccineStartDayCompleteNotIt,
            VaccineEndDayCompleteNotIt,
            VaccineStartDayBoosterIt,
            VaccineEndDayBoosterIt,
            VaccineStartDayBoosterNotIt,
            VaccineEndDayBoosterNotIt,
        ];

        for setting_name in SETTING_NAMES {
            assert_eq!(
                SettingName::deserialize::<StrDeserializer<de::value::Error>>(
                    setting_name.as_str().into_deserializer()
                )
                .unwrap(),
                setting_name,
            );
        }
    }
}
