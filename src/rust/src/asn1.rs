// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use asn1::SimpleAsn1Readable;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::{DssSignature, SubjectPublicKeyInfo, Time};
use cryptography_x509::name::Name;
use pyo3::prelude::PyAnyMethods;
use pyo3::prelude::PyModuleMethods;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::IntoPyDict;
use pyo3::ToPyObject;

use crate::error::{CryptographyError, CryptographyResult};
use crate::types;

pub(crate) fn py_oid_to_oid(
    py_oid: pyo3::Bound<'_, pyo3::PyAny>,
) -> pyo3::PyResult<asn1::ObjectIdentifier> {
    Ok(py_oid
        .downcast::<crate::oid::ObjectIdentifier>()?
        .get()
        .oid
        .clone())
}

pub(crate) fn oid_to_py_oid<'p>(
    py: pyo3::Python<'p>,
    oid: &asn1::ObjectIdentifier,
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    Ok(pyo3::Bound::new(py, crate::oid::ObjectIdentifier { oid: oid.clone() })?.into_any())
}

#[pyo3::prelude::pyfunction]
fn parse_spki_for_data<'p>(
    py: pyo3::Python<'p>,
    data: &[u8],
) -> Result<pyo3::Bound<'p, pyo3::types::PyBytes>, CryptographyError> {
    let spki = asn1::parse_single::<SubjectPublicKeyInfo<'_>>(data)?;
    if spki.subject_public_key.padding_bits() != 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Invalid public key encoding").into());
    }

    Ok(pyo3::types::PyBytes::new_bound(
        py,
        spki.subject_public_key.as_bytes(),
    ))
}

pub(crate) fn big_byte_slice_to_py_int<'p>(
    py: pyo3::Python<'p>,
    v: &'_ [u8],
) -> pyo3::PyResult<pyo3::Bound<'p, pyo3::PyAny>> {
    let int_type = py.get_type_bound::<pyo3::types::PyLong>();
    let kwargs = [("signed", true)].into_py_dict_bound(py);
    int_type.call_method(pyo3::intern!(py, "from_bytes"), (v, "big"), Some(&kwargs))
}

#[pyo3::prelude::pyfunction]
fn decode_dss_signature(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<pyo3::PyObject, CryptographyError> {
    let sig = asn1::parse_single::<DssSignature<'_>>(data)?;

    Ok((
        big_byte_slice_to_py_int(py, sig.r.as_bytes())?,
        big_byte_slice_to_py_int(py, sig.s.as_bytes())?,
    )
        .to_object(py))
}

pub(crate) fn py_uint_to_big_endian_bytes<'p>(
    py: pyo3::Python<'p>,
    v: pyo3::Bound<'p, pyo3::types::PyLong>,
) -> pyo3::PyResult<PyBackedBytes> {
    if v.lt(0)? {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Negative integers are not supported",
        ));
    }

    // Round the length up so that we prefix an extra \x00. This ensures that
    // integers that'd have the high bit set in their first octet are not
    // encoded as negative in DER.
    let n = v
        .call_method0(pyo3::intern!(py, "bit_length"))?
        .extract::<usize>()?
        / 8
        + 1;
    v.call_method1(pyo3::intern!(py, "to_bytes"), (n, "big"))?
        .extract()
}

pub(crate) fn encode_der_data<'p>(
    py: pyo3::Python<'p>,
    pem_tag: String,
    data: Vec<u8>,
    encoding: &pyo3::Bound<'p, pyo3::PyAny>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    if encoding.is(&types::ENCODING_DER.get(py)?) {
        Ok(pyo3::types::PyBytes::new_bound(py, &data))
    } else if encoding.is(&types::ENCODING_PEM.get(py)?) {
        Ok(pyo3::types::PyBytes::new_bound(
            py,
            &pem::encode_config(
                &pem::Pem::new(pem_tag, data),
                pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            )
            .into_bytes(),
        ))
    } else {
        Err(
            pyo3::exceptions::PyTypeError::new_err("encoding must be Encoding.DER or Encoding.PEM")
                .into(),
        )
    }
}

#[pyo3::prelude::pyfunction]
fn encode_dss_signature<'p>(
    py: pyo3::Python<'p>,
    r: pyo3::Bound<'_, pyo3::types::PyLong>,
    s: pyo3::Bound<'_, pyo3::types::PyLong>,
) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
    let r_bytes = py_uint_to_big_endian_bytes(py, r)?;
    let s_bytes = py_uint_to_big_endian_bytes(py, s)?;
    let sig = DssSignature {
        r: asn1::BigUint::new(&r_bytes).unwrap(),
        s: asn1::BigUint::new(&s_bytes).unwrap(),
    };
    let result = asn1::write_single(&sig)?;
    Ok(pyo3::types::PyBytes::new_bound(py, &result))
}

#[pyo3::prelude::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
struct TestCertificate {
    #[pyo3(get)]
    not_before_tag: u8,
    #[pyo3(get)]
    not_after_tag: u8,
    #[pyo3(get)]
    issuer_value_tags: Vec<u8>,
    #[pyo3(get)]
    subject_value_tags: Vec<u8>,
}

fn parse_name_value_tags(rdns: &Name<'_>) -> Vec<u8> {
    let mut tags = vec![];
    for rdn in rdns.unwrap_read().clone() {
        let mut attributes = rdn.collect::<Vec<_>>();
        assert_eq!(attributes.len(), 1);

        tags.push(attributes.pop().unwrap().value.tag().as_u8().unwrap());
    }
    tags
}

fn time_tag(t: &Time) -> u8 {
    match t {
        Time::UtcTime(_) => asn1::UtcTime::TAG.as_u8().unwrap(),
        Time::GeneralizedTime(_) => asn1::GeneralizedTime::TAG.as_u8().unwrap(),
    }
}

#[pyo3::prelude::pyfunction]
fn test_parse_certificate(data: &[u8]) -> Result<TestCertificate, CryptographyError> {
    let cert = asn1::parse_single::<Certificate<'_>>(data)?;

    Ok(TestCertificate {
        not_before_tag: time_tag(&cert.tbs_cert.validity.not_before),
        not_after_tag: time_tag(&cert.tbs_cert.validity.not_after),
        issuer_value_tags: parse_name_value_tags(&cert.tbs_cert.issuer),
        subject_value_tags: parse_name_value_tags(&cert.tbs_cert.subject),
    })
}

pub(crate) fn create_submodule(
    py: pyo3::Python<'_>,
) -> pyo3::PyResult<pyo3::Bound<'_, pyo3::prelude::PyModule>> {
    let submod = pyo3::prelude::PyModule::new_bound(py, "asn1")?;
    submod.add_function(pyo3::wrap_pyfunction_bound!(parse_spki_for_data, &submod)?)?;

    submod.add_function(pyo3::wrap_pyfunction_bound!(decode_dss_signature, &submod)?)?;
    submod.add_function(pyo3::wrap_pyfunction_bound!(encode_dss_signature, &submod)?)?;

    submod.add_function(pyo3::wrap_pyfunction_bound!(
        test_parse_certificate,
        &submod
    )?)?;

    Ok(submod)
}
