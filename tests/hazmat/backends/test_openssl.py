# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import itertools
import os

import pytest

from cryptography.exceptions import InternalError, _Reasons
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from ...doubles import (
    DummyAsymmetricPadding,
    DummyCipherAlgorithm,
    DummyHashAlgorithm,
    DummyMode,
)
from ...hazmat.primitives.test_rsa import rsa_key_2048
from ...utils import (
    load_vectors_from_file,
    raises_unsupported_algorithm,
)

# Make ruff happy since we're importing fixtures that pytest patches in as
# func args
__all__ = ["rsa_key_2048"]


class DummyMGF(padding.MGF):
    _salt_length = 0
    _algorithm = hashes.SHA1()


class TestOpenSSL:
    def test_backend_exists(self):
        assert backend

    def test_is_default_backend(self):
        assert backend is default_backend()

    def test_openssl_version_text(self):
        """
        This test checks the value of OPENSSL_VERSION_TEXT.

        Unfortunately, this define does not appear to have a
        formal content definition, so for now we'll test to see
        if it starts with OpenSSL or LibreSSL as that appears
        to be true for every OpenSSL-alike.
        """
        version = backend.openssl_version_text()
        assert version.startswith(("OpenSSL", "LibreSSL", "BoringSSL"))

        # Verify the correspondence between these two. And do it in a way that
        # ensures coverage.
        if version.startswith("LibreSSL"):
            assert rust_openssl.CRYPTOGRAPHY_IS_LIBRESSL
        if rust_openssl.CRYPTOGRAPHY_IS_LIBRESSL:
            assert version.startswith("LibreSSL")

        if version.startswith("BoringSSL"):
            assert rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
        if rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL:
            assert version.startswith("BoringSSL")

    def test_openssl_version_number(self):
        assert backend.openssl_version_number() > 0

    def test_supports_cipher(self):
        assert (
            backend.cipher_supported(DummyCipherAlgorithm(), DummyMode())
            is False
        )

    def test_openssl_assert(self):
        backend.openssl_assert(True)
        with pytest.raises(InternalError):
            backend.openssl_assert(False)

    def test_consume_errors(self):
        for i in range(10):
            backend._lib.ERR_put_error(
                backend._lib.ERR_LIB_EVP, 0, 0, b"test_openssl.py", -1
            )

        assert backend._lib.ERR_peek_error() != 0

        errors = backend._consume_errors()

        assert backend._lib.ERR_peek_error() == 0
        assert len(errors) == 10

    def test_ssl_ciphers_registered(self):
        meth = backend._lib.TLS_method()
        ctx = backend._lib.SSL_CTX_new(meth)
        assert ctx != backend._ffi.NULL
        backend._lib.SSL_CTX_free(ctx)

    def test_evp_ciphers_registered(self):
        cipher = backend._lib.EVP_get_cipherbyname(b"aes-256-cbc")
        assert cipher != backend._ffi.NULL

<<<<<<< HEAD
    def test_error_strings_loaded(self):
        # returns a value in a static buffer
        err = backend._lib.ERR_error_string(101183626, backend._ffi.NULL)
        assert backend._ffi.string(err) == (
            b"error:0607F08A:digital envelope routines:EVP_EncryptFinal_ex:"
            b"data not multiple of block length"
        )

    def test_unknown_error_in_cipher_finalize(self):
        cipher = Cipher(AES(b"\0" * 16), CBC(b"\0" * 16), backend=backend)
        enc = cipher.encryptor()
        enc.update(b"\0")
        backend._lib.ERR_put_error(0, 0, 1,
                                   b"test_openssl.py", -1)
        with pytest.raises(InternalError):
            enc.finalize()

    def test_large_key_size_on_new_openssl(self):
        parameters = dsa.generate_parameters(2048, backend)
        param_num = parameters.parameter_numbers()
        assert utils.bit_length(param_num.p) == 2048
        parameters = dsa.generate_parameters(3072, backend)
        param_num = parameters.parameter_numbers()
        assert utils.bit_length(param_num.p) == 3072

    def test_int_to_bn(self):
        value = (2 ** 4242) - 4242
        bn = backend._int_to_bn(value)
        assert bn != backend._ffi.NULL
        bn = backend._ffi.gc(bn, backend._lib.BN_free)

        assert bn
        assert backend._bn_to_int(bn) == value

    def test_int_to_bn_inplace(self):
        value = (2 ** 4242) - 4242
        bn_ptr = backend._lib.BN_new()
        assert bn_ptr != backend._ffi.NULL
        bn_ptr = backend._ffi.gc(bn_ptr, backend._lib.BN_free)
        bn = backend._int_to_bn(value, bn_ptr)

        assert bn == bn_ptr
        assert backend._bn_to_int(bn_ptr) == value

    def test_bn_to_int(self):
        bn = backend._int_to_bn(0)
        assert backend._bn_to_int(bn) == 0

    def test_actual_osrandom_bytes(self, monkeypatch):
        skip_if_libre_ssl(backend.openssl_version_text())
        sample_data = (b"\x01\x02\x03\x04" * 4)
        length = len(sample_data)

        def notrandom(size):
            assert size == length
            return sample_data
        monkeypatch.setattr(os, "urandom", notrandom)
        buf = backend._ffi.new("unsigned char[]", length)
        backend._lib.RAND_bytes(buf, length)
        assert backend._ffi.buffer(buf)[0:length] == sample_data


class TestOpenSSLRandomEngine(object):
    def setup(self):
        # The default RAND engine is global and shared between
        # tests. We make sure that the default engine is osrandom
        # before we start each test and restore the global state to
        # that engine in teardown.
        current_default = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(current_default)
        assert name == backend._binding._osrandom_engine_name

    def teardown(self):
        # we need to reset state to being default. backend is a shared global
        # for all these tests.
        backend.activate_osrandom_engine()
        current_default = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(current_default)
        assert name == backend._binding._osrandom_engine_name

    @pytest.mark.skipif(sys.executable is None,
                        reason="No Python interpreter available.")
    def test_osrandom_engine_is_default(self, tmpdir):
        engine_printer = textwrap.dedent(
            """
            import sys
            from cryptography.hazmat.backends.openssl.backend import backend

            e = backend._lib.ENGINE_get_default_RAND()
            name = backend._lib.ENGINE_get_name(e)
            sys.stdout.write(backend._ffi.string(name).decode('ascii'))
            res = backend._lib.ENGINE_free(e)
            assert res == 1
            """
        )
        engine_name = tmpdir.join('engine_name')

        # If we're running tests via ``python setup.py test`` in a clean
        # environment then all of our dependencies are going to be installed
        # into either the current directory or the .eggs directory. However the
        # subprocess won't know to activate these dependencies, so we'll get it
        # to do so by passing our entire sys.path into the subprocess via the
        # PYTHONPATH environment variable.
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(sys.path)

        with engine_name.open('w') as out:
            subprocess.check_call(
                [sys.executable, "-c", engine_printer],
                env=env,
                stdout=out,
                stderr=subprocess.PIPE,
            )

        osrandom_engine_name = backend._ffi.string(
            backend._binding._osrandom_engine_name
        )

        assert engine_name.read().encode('ascii') == osrandom_engine_name

    def test_osrandom_sanity_check(self):
        # This test serves as a check against catastrophic failure.
        buf = backend._ffi.new("unsigned char[]", 500)
        res = backend._lib.RAND_bytes(buf, 500)
        assert res == 1
        assert backend._ffi.buffer(buf)[:] != "\x00" * 500

    def test_activate_osrandom_no_default(self):
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL
        backend.activate_osrandom_engine()
        e = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1

    def test_activate_builtin_random(self):
        e = backend._lib.ENGINE_get_default_RAND()
        assert e != backend._ffi.NULL
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL

    def test_activate_builtin_random_already_active(self):
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL
        backend.activate_builtin_random()
        e = backend._lib.ENGINE_get_default_RAND()
        assert e == backend._ffi.NULL

    def test_activate_osrandom_already_default(self):
        e = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1
        backend.activate_osrandom_engine()
        e = backend._lib.ENGINE_get_default_RAND()
        name = backend._lib.ENGINE_get_name(e)
        assert name == backend._binding._osrandom_engine_name
        res = backend._lib.ENGINE_free(e)
        assert res == 1


class TestOpenSSLRSA(object):
    def test_generate_rsa_parameters_supported(self):
        assert backend.generate_rsa_parameters_supported(1, 1024) is False
        assert backend.generate_rsa_parameters_supported(4, 1024) is False
        assert backend.generate_rsa_parameters_supported(3, 1024) is True
        assert backend.generate_rsa_parameters_supported(3, 511) is False

    def test_generate_bad_public_exponent(self):
        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=1, key_size=2048)

        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=4, key_size=2048)

    def test_cant_generate_insecure_tiny_key(self):
        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=65537,
                                             key_size=511)

        with pytest.raises(ValueError):
            backend.generate_rsa_private_key(public_exponent=65537,
                                             key_size=256)

    @pytest.mark.skipif(
        backend._lib.CRYPTOGRAPHY_OPENSSL_101_OR_GREATER,
        reason="Requires an older OpenSSL. Must be < 1.0.1"
    )
    def test_non_sha1_pss_mgf1_hash_algorithm_on_old_openssl(self):
        private_key = RSA_KEY_512.private_key(backend)
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            private_key.signer(
                padding.PSS(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256(),
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )
        public_key = private_key.public_key()
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            public_key.verifier(
                b"sig",
                padding.PSS(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256(),
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )
=======
>>>>>>> main

class TestOpenSSLRSA:
    def test_rsa_padding_unsupported_pss_mgf1_hash(self):
        assert (
            backend.rsa_padding_supported(
                padding.PSS(
                    mgf=padding.MGF1(DummyHashAlgorithm()), salt_length=0
                )
            )
            is False
        )

    def test_rsa_padding_unsupported(self):
        assert backend.rsa_padding_supported(DummyAsymmetricPadding()) is False

    def test_rsa_padding_supported_pkcs1v15(self):
        assert backend.rsa_padding_supported(padding.PKCS1v15()) is True

    def test_rsa_padding_supported_pss(self):
        assert (
            backend.rsa_padding_supported(
                padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=0)
            )
            is True
        )

    def test_rsa_padding_supported_oaep(self):
        assert (
            backend.rsa_padding_supported(
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            is True
        )

    def test_rsa_padding_supported_oaep_sha2_combinations(self):
        hashalgs = [
            hashes.SHA1(),
            hashes.SHA224(),
            hashes.SHA256(),
            hashes.SHA384(),
            hashes.SHA512(),
        ]
        for mgf1alg, oaepalg in itertools.product(hashalgs, hashalgs):
            if backend._fips_enabled and (
                isinstance(mgf1alg, hashes.SHA1)
                or isinstance(oaepalg, hashes.SHA1)
            ):
                continue

            assert (
                backend.rsa_padding_supported(
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=mgf1alg),
                        algorithm=oaepalg,
                        label=None,
                    ),
                )
                is True
            )

    def test_rsa_padding_unsupported_mgf(self):
        assert (
            backend.rsa_padding_supported(
                padding.OAEP(
                    mgf=DummyMGF(),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
            is False
        )

        assert (
            backend.rsa_padding_supported(
                padding.PSS(mgf=DummyMGF(), salt_length=0)
            )
            is False
        )

    def test_unsupported_mgf1_hash_algorithm_md5_decrypt(self, rsa_key_2048):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_PADDING):
            rsa_key_2048.decrypt(
                b"0" * 256,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.MD5()),
                    algorithm=hashes.MD5(),
                    label=None,
                ),
            )


class TestOpenSSLSerializationWithOpenSSL:
    def test_very_long_pem_serialization_password(self):
        password = b"x" * 1025

        with pytest.raises(ValueError, match="Passwords longer than"):
            load_vectors_from_file(
                os.path.join(
                    "asymmetric",
                    "Traditional_OpenSSL_Serialization",
                    "key1.pem",
                ),
                lambda pemfile: (
                    serialization.load_pem_private_key(
                        pemfile.read().encode(),
                        password,
                        unsafe_skip_rsa_key_validation=False,
                    )
                ),
            )


class TestRSAPEMSerialization:
    def test_password_length_limit(self, rsa_key_2048):
        password = b"x" * 1024
        with pytest.raises(ValueError):
            rsa_key_2048.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password),
            )


@pytest.mark.skipif(
    backend._lib.Cryptography_HAS_EVP_PKEY_DHX == 1,
    reason="Requires OpenSSL without EVP_PKEY_DHX",
)
@pytest.mark.supported(
    only_if=lambda backend: backend.dh_supported(),
    skip_message="Requires DH support",
)
class TestOpenSSLDHSerialization:
    @pytest.mark.parametrize(
        ("key_path", "loader_func"),
        [
            (
                os.path.join("asymmetric", "DH", "dhkey_rfc5114_2.pem"),
                serialization.load_pem_private_key,
            ),
            (
                os.path.join("asymmetric", "DH", "dhkey_rfc5114_2.der"),
                serialization.load_der_private_key,
            ),
        ],
    )
    def test_private_load_dhx_unsupported(
        self, key_path, loader_func, backend
    ):
        key_bytes = load_vectors_from_file(
            key_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        with pytest.raises(ValueError):
<<<<<<< HEAD
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "Traditional_OpenSSL_Serialization",
                    "key1.pem"
                ),
                lambda pemfile: (
                    backend.load_pem_private_key(
                        pemfile.read().encode(), password
                    )
                )
            )


class DummyLibrary(object):
    Cryptography_HAS_EC = 0


class TestOpenSSLEllipticCurve(object):
    def test_elliptic_curve_supported(self, monkeypatch):
        monkeypatch.setattr(backend, "_lib", DummyLibrary())

        assert backend.elliptic_curve_supported(None) is False

    def test_elliptic_curve_signature_algorithm_supported(self, monkeypatch):
        monkeypatch.setattr(backend, "_lib", DummyLibrary())

        assert backend.elliptic_curve_signature_algorithm_supported(
            None, None
        ) is False

    def test_sn_to_elliptic_curve_not_supported(self):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE):
            _sn_to_elliptic_curve(backend, b"fake")

    def test_elliptic_curve_exchange_algorithm_supported(self, monkeypatch):
        monkeypatch.setattr(backend, "_lib", DummyLibrary())
        assert not backend.elliptic_curve_exchange_algorithm_supported(
            ec.ECDH(), ec.SECP256R1()
        )


@pytest.mark.requires_backend_interface(interface=RSABackend)
class TestRSAPEMSerialization(object):
    def test_password_length_limit(self):
        password = b"x" * 1024
        key = RSA_KEY_2048.private_key(backend)
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password)
            )


class TestGOSTCertificate(object):
    def test_numeric_string_x509_name_entry(self):
        cert = _load_cert(
            os.path.join("x509", "e-trust.ru.der"),
            x509.load_der_x509_certificate,
            backend
        )
        if (
            backend._lib.CRYPTOGRAPHY_OPENSSL_LESS_THAN_102I or
            backend._lib.CRYPTOGRAPHY_IS_LIBRESSL
        ):
            with pytest.raises(ValueError) as exc:
                cert.subject

            # We assert on the message in this case because if the certificate
            # fails to load it will also raise a ValueError and this test could
            # erroneously pass.
            assert str(exc.value) == "Unsupported ASN1 string type. Type: 18"
        else:
            assert cert.subject.get_attributes_for_oid(
                x509.ObjectIdentifier("1.2.643.3.131.1.1")
            )[0].value == "007710474375"
=======
            loader_func(key_bytes, None, backend)
>>>>>>> main
