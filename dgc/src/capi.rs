use crate::{DgcContainer, ParseError, SignatureValidity, TrustList};

/// Decodes the certificate and returns the [`DgcContainer`] data contained in it.
///
/// This function is recommended when you don't want to validate the signature but you
/// are just interested in reading the content of the certificate.
#[no_mangle]
pub extern "C" fn dgc_decode(
    data: *const u8,
    len: usize,
    container: *mut *mut DgcContainer,
) -> *const ParseError {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_container_free(container: *mut *mut DgcContainer) {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_trustlist_new() -> *mut TrustList {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_trustlist_default() -> *mut TrustList {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_trustlist_add_from_certificate(
    list: *mut TrustList,
    cert: *mut u8,
    len: usize,
) -> bool {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_trustlist_free(list: *mut *mut TrustList) {
    todo!()
}

/// Parses and validates a given certificate.
///
/// This function is a high level helper that allows you to extract the data from a
/// certificate and at the same time it tries to validate the signature against a given
/// trustlist.
///
/// This function will return an error if the certificate cannot be parsed or is invalid.
/// If the certificate can be parsed correctly, this function returns a tuple containing a
/// [`DgcContainer`] and a [`SignatureValidity`].
///
/// This design allows for permissive validation of the certificate signature.
/// In fact, `SignatureValidity` can be used to determine if the signature is valid and even if it is
/// invalid (or the validity cannot be assessed) you could still access all the information
/// in the certificate.
#[no_mangle]
pub extern "C" fn dgc_validate(
    data: *const u8,
    len: usize,
    trustlist: *const TrustList,
    container: *mut *mut DgcContainer,
    validity: *mut *mut SignatureValidity,
) -> *const ParseError {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_signature_is_valid(error: *const SignatureValidity) -> bool {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_container_to_json(container: *const DgcContainer) -> *mut u8 {
    todo!()
}

#[no_mangle]
pub extern "C" fn dgc_json_free(json: *mut *mut u8) {
    todo!()
}
