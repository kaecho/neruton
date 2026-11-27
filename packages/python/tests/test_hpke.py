"""Unit tests for RFC 9180 Base-mode HPKE and RFC 9849 ECHConfigList parsing/selection."""

from __future__ import annotations

import base64
import struct
import unittest
from typing import Sequence, Tuple

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from neruton.hpke import (
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
    AEAD_EXPORT_ONLY,
    ECH_VERSION_V18,
    KEM_DHKEM_P256_HKDF_SHA256,
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    MAX_SEQ,
    SUPPORTED_SUITES,
    HpkeError,
    HpkeSealer,
    decap,
    decode_ech_config_list_base64,
    encap,
    encode_ech_config,
    encode_ech_config_list,
    parse_ech_config_list,
    select_ech_config,
    select_ech_public_name,
    setup_base_r,
    setup_base_s,
)


def _unhex(s: str) -> bytes:
    return bytes.fromhex("".join(s.split()))


class TestRfc9180OfficialVectors(unittest.TestCase):
    """Official RFC 9180 Appendix A.1.1, A.2.1, A.3.1, and A.5.1 Base-mode test vectors."""

    def _verify_vector(
        self,
        *,
        kem_id: int,
        kdf_id: int,
        aead_id: int,
        info_hex: str,
        pk_rm_hex: str,
        sk_rm_hex: str,
        sk_em_hex: str,
        expected_enc_hex: str,
        expected_ss_hex: str,
        expected_key_hex: str,
        expected_base_nonce_hex: str,
        encryptions: Sequence[Tuple[int, str, str, str]],
    ) -> None:
        info = _unhex(info_hex)
        pk_r = _unhex(pk_rm_hex)
        sk_r = _unhex(sk_rm_hex)
        sk_e = _unhex(sk_em_hex)
        expected_enc = _unhex(expected_enc_hex)
        expected_ss = _unhex(expected_ss_hex)
        expected_key = _unhex(expected_key_hex)
        expected_base_nonce = _unhex(expected_base_nonce_hex)

        ss, enc = encap(kem_id, pk_r, ephemeral_sk_bytes=sk_e)
        self.assertEqual(enc, expected_enc)
        self.assertEqual(ss, expected_ss)

        # Receiver-side decap must produce the exact same shared secret!
        ss_r = decap(kem_id, enc, sk_r)
        self.assertEqual(ss_r, expected_ss)

        enc2, sealer = setup_base_s(
            kem_id, kdf_id, aead_id, pk_r, info, ephemeral_sk_bytes=sk_e
        )
        self.assertEqual(enc2, expected_enc)
        self.assertEqual(sealer.key, expected_key)
        self.assertEqual(sealer.base_nonce, expected_base_nonce)

        opener = setup_base_r(kem_id, kdf_id, aead_id, enc2, sk_r, info)
        self.assertEqual(opener.key, expected_key)
        self.assertEqual(opener.base_nonce, expected_base_nonce)

        for seq, aad_hex, pt_hex, expected_ct_hex in encryptions:
            sealer._seq = seq
            opener._seq = seq
            aad = _unhex(aad_hex)
            pt = _unhex(pt_hex)
            expected_ct = _unhex(expected_ct_hex)

            ct = sealer.seal(aad, pt)
            self.assertEqual(ct, expected_ct, f"ciphertext mismatch at seq={seq}")
            self.assertEqual(sealer.seq, seq + 1)

            opened = opener.open(aad, ct)
            self.assertEqual(opened, pt, f"plaintext mismatch at seq={seq}")
            self.assertEqual(opener.seq, seq + 1)

    def test_appendix_a1_1_x25519_aes128gcm(self) -> None:
        pt = "4265617574792069732074727574682c20747275746820626561757479"
        self._verify_vector(
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            kdf_id=KDF_HKDF_SHA256,
            aead_id=AEAD_AES_128_GCM,
            info_hex="4f6465206f6e2061204772656369616e2055726e",
            pk_rm_hex="3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
            sk_rm_hex="4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
            sk_em_hex="52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
            expected_enc_hex="37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
            expected_ss_hex="fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
            expected_key_hex="4531685d41d65f03dc48f6b8302c05b0",
            expected_base_nonce_hex="56d890e5accaaf011cff4b7d",
            encryptions=[
                (0, "436f756e742d30", pt, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
                (1, "436f756e742d31", pt, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
                (2, "436f756e742d32", pt, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
                (4, "436f756e742d34", pt, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"),
                (255, "436f756e742d323535", pt, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"),
                (256, "436f756e742d323536", pt, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"),
            ],
        )

    def test_appendix_a2_1_x25519_chacha20poly1305(self) -> None:
        pt = "4265617574792069732074727574682c20747275746820626561757479"
        self._verify_vector(
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            kdf_id=KDF_HKDF_SHA256,
            aead_id=AEAD_CHACHA20_POLY1305,
            info_hex="4f6465206f6e2061204772656369616e2055726e",
            pk_rm_hex="4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
            sk_rm_hex="8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            sk_em_hex="f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
            expected_enc_hex="1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
            expected_ss_hex="0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
            expected_key_hex="ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
            expected_base_nonce_hex="5c4d98150661b848853b547f",
            encryptions=[
                (0, "436f756e742d30", pt, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
                (1, "436f756e742d31", pt, "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"),
                (256, "436f756e742d323536", pt, "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b"),
            ],
        )

    def test_appendix_a3_1_p256_aes128gcm(self) -> None:
        pt = "4265617574792069732074727574682c20747275746820626561757479"
        self._verify_vector(
            kem_id=KEM_DHKEM_P256_HKDF_SHA256,
            kdf_id=KDF_HKDF_SHA256,
            aead_id=AEAD_AES_128_GCM,
            info_hex="4f6465206f6e2061204772656369616e2055726e",
            pk_rm_hex="04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
            sk_rm_hex="f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
            sk_em_hex="4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
            expected_enc_hex="04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
            expected_ss_hex="c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
            expected_key_hex="868c066ef58aae6dc589b6cfdd18f97e",
            expected_base_nonce_hex="4e0bc5018beba4bf004cca59",
            encryptions=[
                (0, "436f756e742d30", pt, "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"),
                (1, "436f756e742d31", pt, "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82"),
                (2, "436f756e742d32", pt, "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec"),
                (4, "436f756e742d34", pt, "8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f"),
                (255, "436f756e742d323535", pt, "2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd"),
                (256, "436f756e742d323536", pt, "10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2"),
            ],
        )

    def test_appendix_a5_1_p256_chacha20poly1305(self) -> None:
        pt = "4265617574792069732074727574682c20747275746820626561757479"
        self._verify_vector(
            kem_id=KEM_DHKEM_P256_HKDF_SHA256,
            kdf_id=KDF_HKDF_SHA256,
            aead_id=AEAD_CHACHA20_POLY1305,
            info_hex="4f6465206f6e2061204772656369616e2055726e",
            pk_rm_hex="04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006",
            sk_rm_hex="a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b",
            sk_em_hex="7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689",
            expected_enc_hex="04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291",
            expected_ss_hex="806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850",
            expected_key_hex="a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc",
            expected_base_nonce_hex="726b4390ed2209809f58c693",
            encryptions=[
                (0, "436f756e742d30", pt, "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b"),
                (1, "436f756e742d31", pt, "f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374"),
                (256, "436f756e742d323536", pt, "b45b69d419a9be7219d8c94365b89ad6951caf4576ea4774ea40e9b7047a09d6537d1aa2f7c12d6ae4b729b4d0"),
            ],
        )


class TestHpkeValidationAndEchConfigList(unittest.TestCase):
    def test_all_six_suites_roundtrip_and_tamper_does_not_advance_seq(self) -> None:
        for kem_id, kdf_id, aead_id in SUPPORTED_SUITES:
            if kem_id == KEM_DHKEM_X25519_HKDF_SHA256:
                sk = x25519.X25519PrivateKey.generate()
                sk_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            else:
                sk_ec = ec.generate_private_key(ec.SECP256R1())
                sk_bytes = sk_ec.private_numbers().private_value.to_bytes(32, "big")
                pk_bytes = sk_ec.public_key().public_bytes(
                    Encoding.X962, PublicFormat.UncompressedPoint
                )

            info = b"tls ech\x00dummy-raw-config"
            enc, sealer = setup_base_s(kem_id, kdf_id, aead_id, pk_bytes, info)
            opener = setup_base_r(kem_id, kdf_id, aead_id, enc, sk_bytes, info)

            ct0 = sealer.seal(b"aad-0", b"inner-client-hello-0")
            # Tampered AAD fails WITHOUT advancing opener.seq!
            with self.assertRaises(HpkeError):
                opener.open(b"aad-wrong", ct0)
            self.assertEqual(opener.seq, 0)

            self.assertEqual(opener.open(b"aad-0", ct0), b"inner-client-hello-0")
            self.assertEqual(opener.seq, 1)

            # Second message (HRR seq=1)
            ct1 = sealer.seal(b"aad-1", b"inner-client-hello-1")
            self.assertEqual(opener.open(b"aad-1", ct1), b"inner-client-hello-1")
            self.assertEqual(sealer.seq, 2)
            self.assertEqual(opener.seq, 2)

    def test_invalid_peer_public_keys_rejected(self) -> None:
        # Generate a VALID compressed 33-byte P-256 point to make sure we reject compressed form!
        valid_p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
        compressed_valid_p256 = valid_p256.public_bytes(
            Encoding.X962, PublicFormat.CompressedPoint
        )
        self.assertEqual(len(compressed_valid_p256), 33)

        for aead_id in (AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305):
            # X25519 bad keys: empty, short, and ALL 14 Curve25519 low-order points (MSB 0 and MSB 1)
            low_order_base = (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
                "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            )
            bad_x_keys = [b"", b"\x42" * 31]
            for h in low_order_base:
                raw = bytes.fromhex(h)
                bad_x_keys.append(raw)
                msb1 = bytearray(raw)
                msb1[31] |= 0x80
                bad_x_keys.append(bytes(msb1))

            for bad_x in bad_x_keys:
                with self.assertRaises(HpkeError, msg=f"X25519 should reject {bad_x.hex()}"):
                    setup_base_s(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, aead_id, bad_x, b"info")

            # P-256 bad keys: empty, valid compressed (33B), off-curve, all-zero, short
            for bad_p in (
                b"",
                compressed_valid_p256,
                b"\x04" + b"\x01" * 64,
                b"\x04" + b"\x00" * 64,
                b"\x04" * 64,
            ):
                with self.assertRaises(HpkeError, msg=f"P-256 should reject len={len(bad_p)}"):
                    setup_base_s(KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, aead_id, bad_p, b"info")

    def test_seq_overflow_fails_without_wrap(self) -> None:
        sealer = HpkeSealer(
            aead_id=AEAD_AES_128_GCM,
            key=b"\x11" * 16,
            base_nonce=b"\x22" * 12,
            exporter_secret=b"\x33" * 32,
        )
        sealer._seq = MAX_SEQ
        with self.assertRaises(HpkeError):
            sealer.seal(b"aad", b"pt")
        self.assertEqual(sealer.seq, MAX_SEQ)

    def test_ech_config_list_parsing_selection_and_rejections(self) -> None:
        x_pk = x25519.X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        p_pk = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        # Build a list with:
        # 1) unsupported version 0xFE0C
        # 2) unknown mandatory extension 0x8001
        # 3) valid config with EXPORT_ONLY first, then supported AES-256-GCM
        # 4) valid P-256 config
        cfg_old = encode_ech_config(
            config_id=1,
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            public_key=x_pk,
            cipher_suites=[(KDF_HKDF_SHA256, AEAD_AES_128_GCM)],
            public_name="old.example",
            version=0xFE0C,
        )
        cfg_mandatory = encode_ech_config(
            config_id=2,
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            public_key=x_pk,
            cipher_suites=[(KDF_HKDF_SHA256, AEAD_AES_128_GCM)],
            public_name="mandatory.example",
            extensions=[(0x8001, b"\x01")],
        )
        cfg_good = encode_ech_config(
            config_id=7,
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            public_key=x_pk,
            cipher_suites=[
                (KDF_HKDF_SHA256, AEAD_EXPORT_ONLY),
                (KDF_HKDF_SHA256, AEAD_AES_256_GCM),
            ],
            maximum_name_length=64,
            public_name="cloudflare-ech.com",
            extensions=[(0x0001, b"\xaa")],  # optional unknown ext: ignored cleanly
        )
        cfg_p256 = encode_ech_config(
            config_id=8,
            kem_id=KEM_DHKEM_P256_HKDF_SHA256,
            public_key=p_pk,
            cipher_suites=[(KDF_HKDF_SHA256, AEAD_CHACHA20_POLY1305)],
            public_name="p256-ech.example",
        )

        wire = encode_ech_config_list([cfg_old, cfg_mandatory, cfg_good, cfg_p256])
        parsed = parse_ech_config_list(wire)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].config_id, 7)
        self.assertEqual(parsed[0].raw_config, cfg_good)

        sel = select_ech_config(wire)
        self.assertIsNotNone(sel)
        assert sel is not None
        self.assertEqual(sel.config_id, 7)
        self.assertEqual(sel.aead_id, AEAD_AES_256_GCM)
        self.assertEqual(sel.public_name, "cloudflare-ech.com")
        self.assertEqual(sel.hpke_info, b"tls ech\x00" + cfg_good)
        self.assertEqual(select_ech_public_name(wire), "cloudflare-ech.com")

        # Duplicate extensions -> rejected!
        cfg_dup = encode_ech_config(
            config_id=9,
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            public_key=x_pk,
            cipher_suites=[(KDF_HKDF_SHA256, AEAD_AES_128_GCM)],
            public_name="dup.example",
            extensions=[(0x0010, b""), (0x0010, b"")],
        )
        with self.assertRaises(HpkeError):
            parse_ech_config_list(encode_ech_config_list([cfg_dup]))

        # Malformed list lengths / trailing bytes
        self.assertIsNone(select_ech_config(b""))
        self.assertIsNone(select_ech_config(b"\x00\x00"))
        self.assertIsNone(select_ech_config(wire + b"\x00"))

        # Base64 decode strictness
        b64 = base64.b64encode(wire).decode("ascii")
        self.assertEqual(decode_ech_config_list_base64(f"  {b64}\n"), wire)
        with self.assertRaises(HpkeError):
            decode_ech_config_list_base64("!!!not-base64!!!")
        with self.assertRaises(HpkeError):
            decode_ech_config_list_base64("   ")

        # select_ech_config MUST skip low-order X25519 point (u=1) and select the next valid config!
        low_order_u1 = b"\x01" + b"\x00" * 31
        cfg_low_order = encode_ech_config(
            config_id=1,
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            public_key=low_order_u1,
            cipher_suites=[(KDF_HKDF_SHA256, AEAD_AES_128_GCM)],
            public_name="low-order.example",
        )
        cfg_valid_next = encode_ech_config(
            config_id=2,
            kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
            public_key=x_pk,
            cipher_suites=[(KDF_HKDF_SHA256, AEAD_AES_128_GCM)],
            public_name="valid-next.example",
        )
        sel_skip = select_ech_config(encode_ech_config_list([cfg_low_order, cfg_valid_next]))
        self.assertIsNotNone(sel_skip)
        assert sel_skip is not None
        self.assertEqual(sel_skip.config_id, 2)
        self.assertEqual(sel_skip.public_name, "valid-next.example")

        # Trailing dot or IP literal public_name must not be selected
        for bad_pub in ("cloudflare-ech.com.", "1.1.1.1"):
            bad_cfg = encode_ech_config(
                config_id=10,
                kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                public_key=x_pk,
                cipher_suites=[(KDF_HKDF_SHA256, AEAD_AES_128_GCM)],
                public_name=bad_pub,
            )
            self.assertIsNone(select_ech_config(encode_ech_config_list([bad_cfg])))


if __name__ == "__main__":
    unittest.main()
