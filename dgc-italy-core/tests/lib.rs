use std::borrow::Cow;

use dgc_italy_core::settings::*;

#[test]
fn settings() {
    const RAW_SETTINGS: &str = include_str!("data/settings.json");

    assert_eq!(
        serde_json::from_str::<Settings>(RAW_SETTINGS).unwrap(),
        Settings {
            vaccines: Vaccines {
                janssen: VaccineSettings {
                    complete: Interval {
                        start_day: 15,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 180,
                    }
                },
                vaxzevria: VaccineSettings {
                    complete: Interval {
                        start_day: 0,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 84,
                    }
                },
                spikevax: VaccineSettings {
                    complete: Interval {
                        start_day: 0,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 42,
                    }
                },
                comirnaty: VaccineSettings {
                    complete: Interval {
                        start_day: 0,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 42,
                    }
                },
                covishield: VaccineSettings {
                    complete: Interval {
                        start_day: 0,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 84,
                    }
                },
                r_covi: VaccineSettings {
                    complete: Interval {
                        start_day: 0,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 84,
                    }
                },
                recombinant: VaccineSettings {
                    complete: Interval {
                        start_day: 0,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 84,
                    }
                },
                sputnik_v: VaccineSettings {
                    complete: Interval {
                        start_day: 0,
                        end_day: 180,
                    },
                    not_complete: Interval {
                        start_day: 15,
                        end_day: 21,
                    }
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
