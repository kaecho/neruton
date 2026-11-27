//! RFC 9180 Base-mode HPKE client provider implemented on top of `ring` 0.17.
//!
//! Supplies `rustls::crypto::hpke::Hpke` + `HpkeSealer` for TLS 1.3 Encrypted Client Hello (ECH)
//! without pulling in `aws-lc-rs` / CMake / NASM build toolchains.

use std::fmt::{self, Debug, Formatter};

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};
use ring::hmac::{self, HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::{EchConfigPayload, HpkeSymmetricCipherSuite};
use rustls::Error;
use zeroize::Zeroize;

const AES_128_KEY_LEN: usize = 16;
const AES_256_KEY_LEN: usize = 32;
const CHACHA20_KEY_LEN: usize = 32;
const SHA256_LEN: usize = 32;

/// All RFC 9180 Base-mode HPKE suites supported by our `ring` provider.
///
/// X25519 suites are ordered first since major ECH deployments (e.g. Cloudflare) advertise
/// `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `AES-128-GCM`.
pub static ALL_SUPPORTED_SUITES: &[&'static dyn Hpke] = &[
    DHKEM_X25519_HKDF_SHA256_AES_128_GCM,
    DHKEM_X25519_HKDF_SHA256_AES_256_GCM,
    DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
    DHKEM_P256_HKDF_SHA256_AES_128_GCM,
    DHKEM_P256_HKDF_SHA256_AES_256_GCM,
    DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
];

pub static DHKEM_X25519_HKDF_SHA256_AES_128_GCM: &RingHpke<AES_128_KEY_LEN> = &RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        },
    },
    kem_alg: &agreement::X25519,
    aead_alg: &aead::AES_128_GCM,
};

pub static DHKEM_X25519_HKDF_SHA256_AES_256_GCM: &RingHpke<AES_256_KEY_LEN> = &RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_256_GCM,
        },
    },
    kem_alg: &agreement::X25519,
    aead_alg: &aead::AES_256_GCM,
};

pub static DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305: &RingHpke<CHACHA20_KEY_LEN> = &RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::CHACHA20_POLY_1305,
        },
    },
    kem_alg: &agreement::X25519,
    aead_alg: &aead::CHACHA20_POLY1305,
};

pub static DHKEM_P256_HKDF_SHA256_AES_128_GCM: &RingHpke<AES_128_KEY_LEN> = &RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_P256_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        },
    },
    kem_alg: &agreement::ECDH_P256,
    aead_alg: &aead::AES_128_GCM,
};

pub static DHKEM_P256_HKDF_SHA256_AES_256_GCM: &RingHpke<AES_256_KEY_LEN> = &RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_P256_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_256_GCM,
        },
    },
    kem_alg: &agreement::ECDH_P256,
    aead_alg: &aead::AES_256_GCM,
};

pub static DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305: &RingHpke<CHACHA20_KEY_LEN> = &RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_P256_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::CHACHA20_POLY_1305,
        },
    },
    kem_alg: &agreement::ECDH_P256,
    aead_alg: &aead::CHACHA20_POLY1305,
};

/// Inspect an `ECHConfigList` wire payload and return the outer `public_name` of the first
/// configuration compatible with [`ALL_SUPPORTED_SUITES`] (matching `rustls::client::EchConfig::new`).
pub fn select_ech_public_name(ech_config_list: &[u8]) -> Option<String> {
    let configs = Vec::<EchConfigPayload>::read(&mut Reader::init(ech_config_list)).ok()?;
    for config in configs {
        let single_list = vec![config.clone()].get_encoding();
        if rustls::client::EchConfig::new(
            rustls::pki_types::EchConfigListBytes::from(single_list.as_slice()),
            ALL_SUPPORTED_SUITES,
        )
        .is_ok()
        {
            if let EchConfigPayload::V18(contents) = config {
                return Some(contents.public_name.as_ref().to_string());
            }
        }
    }
    None
}

/// Encode a list of RFC 9849 `retry_configs` received from rustls back into wire `ECHConfigList` bytes.
pub fn encode_ech_config_list(configs: &[EchConfigPayload]) -> Vec<u8> {
    configs.to_vec().get_encoding()
}

/// Concrete `ring`-backed RFC 9180 Base-mode HPKE suite.
pub struct RingHpke<const KEY_SIZE: usize> {
    suite: HpkeSuite,
    kem_alg: &'static agreement::Algorithm,
    aead_alg: &'static aead::Algorithm,
}

impl<const KEY_SIZE: usize> Debug for RingHpke<KEY_SIZE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingHpke")
            .field("suite", &self.suite)
            .finish()
    }
}

struct OutputLen(usize);

impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy)]
enum SuiteId {
    Kem(HpkeKem),
    Hpke(HpkeSuite),
}

impl SuiteId {
    fn write_into(&self, out: &mut Vec<u8>) {
        match self {
            SuiteId::Kem(kem) => {
                out.extend_from_slice(b"KEM");
                out.extend_from_slice(&u16::from(*kem).to_be_bytes());
            }
            SuiteId::Hpke(suite) => {
                out.extend_from_slice(b"HPKE");
                out.extend_from_slice(&u16::from(suite.kem).to_be_bytes());
                out.extend_from_slice(&u16::from(suite.sym.kdf_id).to_be_bytes());
                out.extend_from_slice(&u16::from(suite.sym.aead_id).to_be_bytes());
            }
        }
    }
}

/// RFC 9180 §4 `LabeledExtract(salt, label, ikm)` returning raw 32-byte PRK bytes.
fn labeled_extract_bytes(
    suite_id: SuiteId,
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> [u8; SHA256_LEN] {
    let mut labeled_ikm = Vec::with_capacity(7 + 10 + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    suite_id.write_into(&mut labeled_ikm);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let key = hmac::Key::new(HMAC_SHA256, salt);
    let tag = hmac::sign(&key, &labeled_ikm);
    labeled_ikm.zeroize();

    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// RFC 9180 §4 `LabeledExtract(salt, label, ikm)` returning a `ring::hkdf::Prk`.
fn labeled_extract_prk(suite_id: SuiteId, salt: &[u8], label: &[u8], ikm: &[u8]) -> Prk {
    let mut labeled_ikm = Vec::with_capacity(7 + 10 + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    suite_id.write_into(&mut labeled_ikm);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let prk = Salt::new(HKDF_SHA256, salt).extract(&labeled_ikm);
    labeled_ikm.zeroize();
    prk
}

/// RFC 9180 §4 `LabeledExpand(prk, label, info, L)`.
fn labeled_expand<const L: usize>(
    suite_id: SuiteId,
    prk: &Prk,
    label: &[u8],
    info: &[u8],
) -> Result<[u8; L], Error> {
    let len_be = (L as u16).to_be_bytes();
    let mut suite_bytes = Vec::with_capacity(10);
    suite_id.write_into(&mut suite_bytes);

    let info_slices: [&[u8]; 5] = [&len_be, b"HPKE-v1", &suite_bytes, label, info];
    let okm = prk
        .expand(&info_slices, OutputLen(L))
        .map_err(|_| Error::General("HPKE HKDF-Expand failed".into()))?;
    let mut out = [0u8; L];
    okm.fill(&mut out)
        .map_err(|_| Error::General("HPKE HKDF-Expand fill failed".into()))?;
    Ok(out)
}

struct ZeroizingSecret<const N: usize>([u8; N]);

impl<const N: usize> Drop for ZeroizingSecret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const KEY_SIZE: usize> RingHpke<KEY_SIZE> {
    /// RFC 9180 §4.1 `Encap(pkR)` using the supplied CSPRNG (or fixed test RNG in unit tests).
    fn encap_with_rng(
        &self,
        recipient: &HpkePublicKey,
        rng: &dyn SecureRandom,
    ) -> Result<(ZeroizingSecret<SHA256_LEN>, EncapsulatedSecret), Error> {
        let sk_e = EphemeralPrivateKey::generate(self.kem_alg, rng)
            .map_err(|_| Error::General("HPKE ephemeral key generation failed".into()))?;
        let pk_e = sk_e
            .compute_public_key()
            .map_err(|_| Error::General("HPKE ephemeral public key computation failed".into()))?;
        let enc_bytes = pk_e.as_ref().to_vec();

        let peer_pk = UnparsedPublicKey::new(self.kem_alg, &recipient.0);

        let mut kem_context = Vec::with_capacity(enc_bytes.len() + recipient.0.len());
        kem_context.extend_from_slice(&enc_bytes);
        kem_context.extend_from_slice(&recipient.0);

        let kem_suite_id = SuiteId::Kem(self.suite.kem);
        let shared_secret_res = agreement::agree_ephemeral(sk_e, &peer_pk, |dh| {
            let eae_prk = labeled_extract_prk(kem_suite_id, &[], b"eae_prk", dh);
            labeled_expand::<SHA256_LEN>(kem_suite_id, &eae_prk, b"shared_secret", &kem_context)
        })
        .map_err(|_| Error::General("HPKE ECDH agreement failed".into()))?;

        let shared_secret = shared_secret_res?;
        Ok((
            ZeroizingSecret(shared_secret),
            EncapsulatedSecret(enc_bytes),
        ))
    }

    /// RFC 9180 §5.1 `KeyScheduleS(mode_base, shared_secret, info, "", "")`.
    fn key_schedule(
        &self,
        shared_secret: &ZeroizingSecret<SHA256_LEN>,
        info: &[u8],
    ) -> Result<RingSealer<KEY_SIZE>, Error> {
        let hpke_suite_id = SuiteId::Hpke(self.suite);

        let psk_id_hash = labeled_extract_bytes(hpke_suite_id, &[], b"psk_id_hash", &[]);
        let info_hash = labeled_extract_bytes(hpke_suite_id, &[], b"info_hash", info);

        let mut key_schedule_context = Vec::with_capacity(1 + SHA256_LEN * 2);
        key_schedule_context.push(0x00); // mode_base
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);

        let secret = labeled_extract_prk(hpke_suite_id, &shared_secret.0, b"secret", &[]);

        let key =
            labeled_expand::<KEY_SIZE>(hpke_suite_id, &secret, b"key", &key_schedule_context)?;
        let base_nonce = labeled_expand::<NONCE_LEN>(
            hpke_suite_id,
            &secret,
            b"base_nonce",
            &key_schedule_context,
        )?;

        Ok(RingSealer {
            aead_alg: self.aead_alg,
            key: ZeroizingSecret(key),
            base_nonce: ZeroizingSecret(base_nonce),
            seq: 0,
        })
    }

    fn setup_sealer_with_rng(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
        rng: &dyn SecureRandom,
    ) -> Result<(EncapsulatedSecret, RingSealer<KEY_SIZE>), Error> {
        let (shared_secret, enc) = self.encap_with_rng(pub_key, rng)?;
        let sealer = self.key_schedule(&shared_secret, info)?;
        Ok((enc, sealer))
    }
}

impl<const KEY_SIZE: usize> Hpke for RingHpke<KEY_SIZE> {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sealer) = self.setup_sealer(info, pub_key)?;
        let ct = sealer.seal(aad, plaintext)?;
        Ok((enc, ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let rng = SystemRandom::new();
        let (enc, sealer) = self.setup_sealer_with_rng(info, pub_key, &rng)?;
        Ok((enc, Box::new(sealer)))
    }

    fn open(
        &self,
        _enc: &EncapsulatedSecret,
        _info: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
        _secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::General(
            "HPKE open is not supported by client-only ring HPKE provider".into(),
        ))
    }

    fn setup_opener(
        &self,
        _enc: &EncapsulatedSecret,
        _info: &[u8],
        _secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        Err(Error::General(
            "HPKE setup_opener is not supported by client-only ring HPKE provider".into(),
        ))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        Err(Error::General(
            "HPKE generate_key_pair is not supported by client-only ring HPKE provider".into(),
        ))
    }

    fn fips(&self) -> bool {
        false
    }

    fn suite(&self) -> HpkeSuite {
        self.suite
    }
}

struct RingSealer<const KEY_SIZE: usize> {
    aead_alg: &'static aead::Algorithm,
    key: ZeroizingSecret<KEY_SIZE>,
    base_nonce: ZeroizingSecret<NONCE_LEN>,
    seq: u64,
}

impl<const KEY_SIZE: usize> Debug for RingSealer<KEY_SIZE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingSealer")
            .field("seq", &self.seq)
            .finish()
    }
}

impl<const KEY_SIZE: usize> RingSealer<KEY_SIZE> {
    /// RFC 9180 §5.2 `ComputeNonce(seq) = xor(base_nonce, I2OSP(seq, Nn))`.
    fn compute_nonce(&self) -> Nonce {
        let mut nonce = self.base_nonce.0;
        let seq_be = self.seq.to_be_bytes();
        let offset = NONCE_LEN - seq_be.len();
        for (dst, &src) in nonce[offset..].iter_mut().zip(seq_be.iter()) {
            *dst ^= src;
        }
        Nonce::assume_unique_for_key(nonce)
    }

    fn increment_seq(&mut self) -> Result<(), Error> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::General("HPKE sequence number overflow".into()))?;
        Ok(())
    }
}

impl<const KEY_SIZE: usize> HpkeSealer for RingSealer<KEY_SIZE> {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let unbound = UnboundKey::new(self.aead_alg, &self.key.0)
            .map_err(|_| Error::General("HPKE AEAD key init failed".into()))?;
        let key = LessSafeKey::new(unbound);

        let nonce = self.compute_nonce();
        self.increment_seq()?;

        let mut buf = Vec::with_capacity(plaintext.len() + self.aead_alg.tag_len());
        buf.extend_from_slice(plaintext);
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| Error::EncryptError)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(clean.len() % 2, 0);
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn check_rfc9180_vector<const KEY_SIZE: usize>(
        hpke: &RingHpke<KEY_SIZE>,
        info_hex: &str,
        pk_rm_hex: &str,
        sk_em_hex: &str,
        expected_enc_hex: &str,
        expected_shared_secret_hex: &str,
        expected_key_hex: &str,
        expected_base_nonce_hex: &str,
        encryptions: &[(u64, &str, &str, &str)],
    ) {
        let info = unhex(info_hex);
        let pk_r = HpkePublicKey(unhex(pk_rm_hex));
        let sk_em = unhex(sk_em_hex);
        let expected_enc = unhex(expected_enc_hex);
        let expected_ss = unhex(expected_shared_secret_hex);
        let expected_key = unhex(expected_key_hex);
        let expected_base_nonce = unhex(expected_base_nonce_hex);

        #[allow(deprecated)]
        let rng = ring::test::rand::FixedSliceRandom { bytes: &sk_em };
        let (shared_secret, enc) = hpke.encap_with_rng(&pk_r, &rng).unwrap();
        assert_eq!(enc.0, expected_enc, "enc mismatch");
        assert_eq!(
            shared_secret.0.as_slice(),
            expected_ss.as_slice(),
            "shared_secret mismatch"
        );

        let mut sealer = hpke.key_schedule(&shared_secret, &info).unwrap();
        assert_eq!(
            sealer.key.0.as_slice(),
            expected_key.as_slice(),
            "key mismatch"
        );
        assert_eq!(
            sealer.base_nonce.0.as_slice(),
            expected_base_nonce.as_slice(),
            "base_nonce mismatch"
        );

        for &(seq, aad_hex, pt_hex, expected_ct_hex) in encryptions {
            sealer.seq = seq;
            let aad = unhex(aad_hex);
            let pt = unhex(pt_hex);
            let expected_ct = unhex(expected_ct_hex);
            let ct = sealer.seal(&aad, &pt).unwrap();
            assert_eq!(ct, expected_ct, "ciphertext mismatch at seq={seq}");
            assert_eq!(sealer.seq, seq + 1);
        }
    }

    /// Official RFC 9180 Appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
    #[test]
    fn rfc9180_appendix_a1_x25519_aes128gcm() {
        let pt = "4265617574792069732074727574682c20747275746820626561757479";
        check_rfc9180_vector(
            DHKEM_X25519_HKDF_SHA256_AES_128_GCM,
            "4f6465206f6e2061204772656369616e2055726e",
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
            "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
            "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
            "4531685d41d65f03dc48f6b8302c05b0",
            "56d890e5accaaf011cff4b7d",
            &[
                (0, "436f756e742d30", pt, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
                (1, "436f756e742d31", pt, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
                (2, "436f756e742d32", pt, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
                (4, "436f756e742d34", pt, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"),
                (255, "436f756e742d323535", pt, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"),
                (256, "436f756e742d323536", pt, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"),
            ],
        );
    }

    /// Official RFC 9180 Appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
    #[test]
    fn rfc9180_appendix_a2_x25519_chacha20poly1305() {
        let pt = "4265617574792069732074727574682c20747275746820626561757479";
        check_rfc9180_vector(
            DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
            "4f6465206f6e2061204772656369616e2055726e",
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
            "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
            "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
            "5c4d98150661b848853b547f",
            &[
                (0, "436f756e742d30", pt, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
                (1, "436f756e742d31", pt, "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"),
                (256, "436f756e742d323536", pt, "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b"),
            ],
        );
    }

    /// Official RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
    #[test]
    fn rfc9180_appendix_a3_p256_aes128gcm() {
        let pt = "4265617574792069732074727574682c20747275746820626561757479";
        check_rfc9180_vector(
            DHKEM_P256_HKDF_SHA256_AES_128_GCM,
            "4f6465206f6e2061204772656369616e2055726e",
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
            "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
            "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
            "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
            "868c066ef58aae6dc589b6cfdd18f97e",
            "4e0bc5018beba4bf004cca59",
            &[
                (0, "436f756e742d30", pt, "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"),
                (1, "436f756e742d31", pt, "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82"),
                (2, "436f756e742d32", pt, "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec"),
                (4, "436f756e742d34", pt, "8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f"),
                (255, "436f756e742d323535", pt, "2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd"),
                (256, "436f756e742d323536", pt, "10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2"),
            ],
        );
    }

    /// Official RFC 9180 Appendix A.5.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
    #[test]
    fn rfc9180_appendix_a5_p256_chacha20poly1305() {
        let pt = "4265617574792069732074727574682c20747275746820626561757479";
        check_rfc9180_vector(
            DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
            "4f6465206f6e2061204772656369616e2055726e",
            "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006",
            "7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689",
            "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291",
            "806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850",
            "a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc",
            "726b4390ed2209809f58c693",
            &[
                (0, "436f756e742d30", pt, "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b"),
                (1, "436f756e742d31", pt, "f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374"),
                (256, "436f756e742d323536", pt, "b45b69d419a9be7219d8c94365b89ad6951caf4576ea4774ea40e9b7047a09d6537d1aa2f7c12d6ae4b729b4d0"),
            ],
        );
    }

    /// Smoke-test all 6 suites (including AES-256-GCM) with live random ephemeral keys and receiver-side decryption.
    #[test]
    fn all_six_suites_roundtrip_with_receiver_decap() {
        let rng = SystemRandom::new();
        for &suite in ALL_SUPPORTED_SUITES {
            let kem_alg = match suite.suite().kem {
                HpkeKem::DHKEM_X25519_HKDF_SHA256 => &agreement::X25519,
                HpkeKem::DHKEM_P256_HKDF_SHA256 => &agreement::ECDH_P256,
                other => panic!("unexpected KEM {other:?}"),
            };
            let sk_r = EphemeralPrivateKey::generate(kem_alg, &rng).unwrap();
            let pk_r = sk_r.compute_public_key().unwrap();
            let pk_r_bytes = pk_r.as_ref().to_vec();

            let info = b"tls ech\0dummy-config";
            let aad = b"client-hello-aad";
            let pt = b"inner-client-hello-secret-sni";

            let (enc, ct) = suite
                .seal(info, aad, pt, &HpkePublicKey(pk_r_bytes.clone()))
                .unwrap();

            // Independently decap on receiver side and decrypt with ring AEAD.
            let kem_suite_id = SuiteId::Kem(suite.suite().kem);
            let mut kem_ctx = Vec::new();
            kem_ctx.extend_from_slice(&enc.0);
            kem_ctx.extend_from_slice(&pk_r_bytes);
            let peer_enc = UnparsedPublicKey::new(kem_alg, &enc.0);
            let ss = agreement::agree_ephemeral(sk_r, &peer_enc, |dh| {
                let prk = labeled_extract_prk(kem_suite_id, &[], b"eae_prk", dh);
                labeled_expand::<SHA256_LEN>(kem_suite_id, &prk, b"shared_secret", &kem_ctx)
                    .unwrap()
            })
            .unwrap();

            let hpke_id = SuiteId::Hpke(suite.suite());
            let psk_id_hash = labeled_extract_bytes(hpke_id, &[], b"psk_id_hash", &[]);
            let info_hash = labeled_extract_bytes(hpke_id, &[], b"info_hash", info);
            let mut ks_ctx = vec![0x00];
            ks_ctx.extend_from_slice(&psk_id_hash);
            ks_ctx.extend_from_slice(&info_hash);
            let secret = labeled_extract_prk(hpke_id, &ss, b"secret", &[]);
            let base_nonce =
                labeled_expand::<NONCE_LEN>(hpke_id, &secret, b"base_nonce", &ks_ctx).unwrap();

            let (aead_alg, key_bytes): (&'static aead::Algorithm, Vec<u8>) =
                match suite.suite().sym.aead_id {
                    HpkeAead::AES_128_GCM => (
                        &aead::AES_128_GCM,
                        labeled_expand::<16>(hpke_id, &secret, b"key", &ks_ctx)
                            .unwrap()
                            .to_vec(),
                    ),
                    HpkeAead::AES_256_GCM => (
                        &aead::AES_256_GCM,
                        labeled_expand::<32>(hpke_id, &secret, b"key", &ks_ctx)
                            .unwrap()
                            .to_vec(),
                    ),
                    HpkeAead::CHACHA20_POLY_1305 => (
                        &aead::CHACHA20_POLY1305,
                        labeled_expand::<32>(hpke_id, &secret, b"key", &ks_ctx)
                            .unwrap()
                            .to_vec(),
                    ),
                    other => panic!("unexpected AEAD {other:?}"),
                };

            let opening_key = LessSafeKey::new(UnboundKey::new(aead_alg, &key_bytes).unwrap());
            let mut buf = ct;
            let decrypted = opening_key
                .open_in_place(
                    Nonce::assume_unique_for_key(base_nonce),
                    Aad::from(aad),
                    &mut buf,
                )
                .unwrap();
            assert_eq!(decrypted, pt);
            assert!(!suite.fips());
        }
    }

    #[test]
    fn invalid_public_key_fails_cleanly() {
        for &suite in ALL_SUPPORTED_SUITES {
            assert!(suite.setup_sealer(b"info", &HpkePublicKey(vec![])).is_err());
        }

        // Low-order X25519 all-zero point must be rejected (RFC 7748 §6.1 / RFC 9180 §7.1.4).
        for &suite in &[
            DHKEM_X25519_HKDF_SHA256_AES_128_GCM as &dyn Hpke,
            DHKEM_X25519_HKDF_SHA256_AES_256_GCM as &dyn Hpke,
            DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305 as &dyn Hpke,
        ] {
            assert!(
                suite
                    .setup_sealer(b"info", &HpkePublicKey(vec![0u8; 32]))
                    .is_err(),
                "all-zero X25519 pubkey must fail"
            );
            assert!(
                suite
                    .setup_sealer(b"info", &HpkePublicKey(vec![0x42u8; 31]))
                    .is_err(),
                "short X25519 pubkey must fail"
            );
        }

        // P-256: reject compressed (33B), wrong-length, all-zero, and off-curve uncompressed points.
        let mut compressed_p256 = vec![0x02u8];
        compressed_p256.extend_from_slice(&[0x11u8; 32]);
        let mut off_curve_p256 = vec![0x04u8];
        off_curve_p256.extend_from_slice(&[0x01u8; 64]); // (x, y) not on secp256r1
        let mut zero_uncompressed_p256 = vec![0x04u8];
        zero_uncompressed_p256.extend_from_slice(&[0x00u8; 64]);

        for &suite in &[
            DHKEM_P256_HKDF_SHA256_AES_128_GCM as &dyn Hpke,
            DHKEM_P256_HKDF_SHA256_AES_256_GCM as &dyn Hpke,
            DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305 as &dyn Hpke,
        ] {
            for bad in [
                compressed_p256.clone(),
                off_curve_p256.clone(),
                zero_uncompressed_p256.clone(),
                vec![0x04u8; 64], // 1 byte short
            ] {
                assert!(
                    suite.setup_sealer(b"info", &HpkePublicKey(bad)).is_err(),
                    "malformed P-256 pubkey must fail"
                );
            }
        }
    }

    #[test]
    fn sealer_seq_overflow_fails_without_wrap() {
        let mut sealer = RingSealer {
            aead_alg: &aead::AES_128_GCM,
            key: ZeroizingSecret([0x11u8; AES_128_KEY_LEN]),
            base_nonce: ZeroizingSecret([0x22u8; NONCE_LEN]),
            seq: u64::MAX,
        };
        assert!(
            sealer.seal(b"aad", b"pt").is_err(),
            "sealing at seq == u64::MAX must fail with overflow"
        );
        assert_eq!(sealer.seq, u64::MAX);
    }

    #[test]
    fn select_ech_public_name_handles_malformed_inputs_without_panic() {
        assert_eq!(select_ech_public_name(&[]), None);
        assert_eq!(select_ech_public_name(&[0x00, 0x00]), None);
        assert_eq!(select_ech_public_name(&[0xFF, 0xFF, 0x01, 0x02]), None);
        // Unsupported ECH version (0xfe0c)
        let unsupported_ver = [0x00, 0x06, 0xfe, 0x0c, 0x00, 0x02, 0xaa, 0xbb];
        assert_eq!(select_ech_public_name(&unsupported_ver), None);
    }
}
