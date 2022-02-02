use std::borrow::Cow;

use dgc_italy_core::settings::*;

#[test]
fn settings() {
    const RAW_SETTINGS: &str = include_str!("data/settings.json");

    assert_eq!(
        serde_json::from_str::<Settings>(RAW_SETTINGS).unwrap(),
        Settings {
            vaccines: Vaccines {
                jensen: VaccineSettings {
                    start_day_complete: 15,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 180,
                },
                vaxzevria: VaccineSettings {
                    start_day_complete: 0,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 84,
                },
                spikevax: VaccineSettings {
                    start_day_complete: 0,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 42,
                },
                comirnaty: VaccineSettings {
                    start_day_complete: 0,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 42,
                },
                covi_shield: VaccineSettings {
                    start_day_complete: 0,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 84,
                },
                r_covi: VaccineSettings {
                    start_day_complete: 0,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 84,
                },
                recombinant: VaccineSettings {
                    start_day_complete: 0,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 84,
                },
                sputnik: VaccineSettings {
                    start_day_complete: 0,
                    end_day_complete: 180,
                    start_day_not_complete: 15,
                    end_day_not_complete: 21,
                }
            },
            deny_list: DenyList(Cow::Borrowed(
                "URN:UVCI:01:FR:W7V2BE46QSBJ#L;URN:UVCI:01:FR:T5DWTJYS4ZR8#4"
            )),
            min_versions: MinVersions {
                ios: Cow::Borrowed("1.2.0"),
                android: Cow::Borrowed("1.2.0")
            },
            tests: Tests {
                rapid: TestData {
                    start_hours: 0,
                    end_hours: 48,
                },
                molecular: TestData {
                    start_hours: 0,
                    end_hours: 72
                }
            },
            recovery: Recovery {
                cert: Interval {
                    start_day: 0,
                    end_day: 180
                },
                pv_cert: Interval {
                    start_day: 0,
                    end_day: 180
                },
                cert_it: Interval {
                    start_day: 0,
                    end_day: 180
                },
                cert_not_it: Interval {
                    start_day: 0,
                    end_day: 180
                },
            },
            generic_vaccine: GenericVaccine {
                complete_it: Interval {
                    start_day: 0,
                    end_day: 180,
                },
                booster_it: Interval {
                    start_day: 0,
                    end_day: 180,
                },
                complete_not_it: Interval {
                    start_day: 0,
                    end_day: 270,
                },
                booster_not_it: Interval {
                    start_day: 0,
                    end_day: 270,
                }
            },
            unknown: Vec::new(),
        }
    );
}
