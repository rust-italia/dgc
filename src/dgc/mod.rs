// https://github.com/ehn-dcc-development/ehn-dcc-schema

pub mod r;
pub mod t;
pub mod v;
pub mod valuesets;

pub enum CertType {
    Test,
    Vaccination,
    Recovery,
}
