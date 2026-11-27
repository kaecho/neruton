import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ALL_SUPPORTED_HPKE_SUITES,
  ECH_VERSION,
  HPKE_AEAD_AES_128_GCM,
  HPKE_AEAD_AES_256_GCM,
  HPKE_AEAD_CHACHA20_POLY1305,
  HPKE_AEAD_EXPORT_ONLY,
  HPKE_KDF_HKDF_SHA256,
  HPKE_KEM_P256_SHA256,
  HPKE_KEM_X25519_SHA256,
  HpkeSealer,
  MAX_HPKE_SEQ,
  decodeEchConfigBase64,
  encodeEchConfig,
  encodeEchConfigList,
  generateHpkeKeyPair,
  parseEchConfigList,
  selectEchConfig,
  selectEchPublicName,
  setupBaseR,
  setupBaseS,
  validateKemPublicKey,
  validateX25519PublicKey,
} from '../dist/esm/index.js';

function unhex(s) {
  return Buffer.from(s.replace(/\s+/g, ''), 'hex');
}

function checkRfc9180Vector({
  suite,
  infoHex,
  pkRmHex,
  skEmHex,
  expectedEncHex,
  expectedSharedSecretHex,
  expectedKeyHex,
  expectedBaseNonceHex,
  encryptions,
}) {
  const info = unhex(infoHex);
  const pkR = unhex(pkRmHex);
  const skEm = unhex(skEmHex);

  const res = setupBaseS(suite, pkR, info, skEm);
  assert.deepEqual(res.enc, unhex(expectedEncHex), 'enc mismatch');
  assert.deepEqual(res.sharedSecret, unhex(expectedSharedSecretHex), 'shared_secret mismatch');
  assert.deepEqual(res.key, unhex(expectedKeyHex), 'key mismatch');
  assert.deepEqual(res.baseNonce, unhex(expectedBaseNonceHex), 'base_nonce mismatch');

  for (const [seq, aadHex, ptHex, expectedCtHex] of encryptions) {
    res.sealer.setSeq(BigInt(seq));
    const ct = res.sealer.seal(unhex(aadHex), unhex(ptHex));
    assert.deepEqual(ct, unhex(expectedCtHex), `ciphertext mismatch at seq=${seq}`);
    assert.equal(res.sealer.seq, BigInt(seq) + 1n);
  }
}

test('RFC 9180 Appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM', () => {
  const pt = '4265617574792069732074727574682c20747275746820626561757479';
  checkRfc9180Vector({
    suite: {
      kemId: HPKE_KEM_X25519_SHA256,
      kdfId: HPKE_KDF_HKDF_SHA256,
      aeadId: HPKE_AEAD_AES_128_GCM,
    },
    infoHex: '4f6465206f6e2061204772656369616e2055726e',
    pkRmHex: '3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d',
    skEmHex: '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736',
    expectedEncHex: '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431',
    expectedSharedSecretHex: 'fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc',
    expectedKeyHex: '4531685d41d65f03dc48f6b8302c05b0',
    expectedBaseNonceHex: '56d890e5accaaf011cff4b7d',
    encryptions: [
      [0, '436f756e742d30', pt, 'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a'],
      [1, '436f756e742d31', pt, 'af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84'],
      [2, '436f756e742d32', pt, '498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180'],
      [4, '436f756e742d34', pt, '583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d'],
      [255, '436f756e742d323535', pt, '7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a'],
      [256, '436f756e742d323536', pt, '957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2'],
    ],
  });
});

test('RFC 9180 Appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305', () => {
  const pt = '4265617574792069732074727574682c20747275746820626561757479';
  checkRfc9180Vector({
    suite: {
      kemId: HPKE_KEM_X25519_SHA256,
      kdfId: HPKE_KDF_HKDF_SHA256,
      aeadId: HPKE_AEAD_CHACHA20_POLY1305,
    },
    infoHex: '4f6465206f6e2061204772656369616e2055726e',
    pkRmHex: '4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a',
    skEmHex: 'f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600',
    expectedEncHex: '1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a',
    expectedSharedSecretHex: '0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7',
    expectedKeyHex: 'ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91',
    expectedBaseNonceHex: '5c4d98150661b848853b547f',
    encryptions: [
      [0, '436f756e742d30', pt, '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28'],
      [1, '436f756e742d31', pt, '6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c'],
      [256, '436f756e742d323536', pt, '7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b'],
    ],
  });
});

test('RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM', () => {
  const pt = '4265617574792069732074727574682c20747275746820626561757479';
  checkRfc9180Vector({
    suite: {
      kemId: HPKE_KEM_P256_SHA256,
      kdfId: HPKE_KDF_HKDF_SHA256,
      aeadId: HPKE_AEAD_AES_128_GCM,
    },
    infoHex: '4f6465206f6e2061204772656369616e2055726e',
    pkRmHex: '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
    skEmHex: '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
    expectedEncHex: '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
    expectedSharedSecretHex: 'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8',
    expectedKeyHex: '868c066ef58aae6dc589b6cfdd18f97e',
    expectedBaseNonceHex: '4e0bc5018beba4bf004cca59',
    encryptions: [
      [0, '436f756e742d30', pt, '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'],
      [1, '436f756e742d31', pt, 'fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82'],
      [2, '436f756e742d32', pt, '895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec'],
      [4, '436f756e742d34', pt, '8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f'],
      [255, '436f756e742d323535', pt, '2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd'],
      [256, '436f756e742d323536', pt, '10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2'],
    ],
  });
});

test('RFC 9180 Appendix A.5.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305', () => {
  const pt = '4265617574792069732074727574682c20747275746820626561757479';
  checkRfc9180Vector({
    suite: {
      kemId: HPKE_KEM_P256_SHA256,
      kdfId: HPKE_KDF_HKDF_SHA256,
      aeadId: HPKE_AEAD_CHACHA20_POLY1305,
    },
    infoHex: '4f6465206f6e2061204772656369616e2055726e',
    pkRmHex: '04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006',
    skEmHex: '7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689',
    expectedEncHex: '04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291',
    expectedSharedSecretHex: '806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850',
    expectedKeyHex: 'a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc',
    expectedBaseNonceHex: '726b4390ed2209809f58c693',
    encryptions: [
      [0, '436f756e742d30', pt, '6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b'],
      [1, '436f756e742d31', pt, 'f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc546c9d114374'],
      [256, '436f756e742d323536', pt, 'b45b69d419a9be7219d8c94365b89ad6951caf4576ea4774ea40e9b7047a09d6537d1aa2f7c12d6ae4b729b4d0'],
    ],
  });
});

test('All 6 HPKE suites round-trip setupBaseS/seal -> setupBaseR/open across multiple messages', () => {
  assert.equal(ALL_SUPPORTED_HPKE_SUITES.length, 6);
  const info = Buffer.from('tls ech\0dummy-ech-config');
  const aad0 = Buffer.from('client-hello-outer-aad-0');
  const aad1 = Buffer.from('client-hello-outer-aad-1');
  const pt0 = Buffer.from('inner-client-hello-0');
  const pt1 = Buffer.from('inner-client-hello-1-post-hrr');

  for (const suite of ALL_SUPPORTED_HPKE_SUITES) {
    const kp = generateHpkeKeyPair(suite.kemId);
    const { enc, sealer } = setupBaseS(suite, kp.publicKey, info);
    const opener = setupBaseR(suite, enc, kp.privateKey, info);

    const ct0 = sealer.seal(aad0, pt0);
    const ct1 = sealer.seal(aad1, pt1);
    assert.deepEqual(opener.open(aad0, ct0), pt0);
    assert.deepEqual(opener.open(aad1, ct1), pt1);

    // Tampered AAD or ciphertext must fail cleanly
    const tampered = Buffer.from(ct0);
    tampered[0] ^= 0xff;
    const opener2 = setupBaseR(suite, enc, kp.privateKey, info);
    assert.throws(() => opener2.open(aad0, tampered), /decryption failed/i);
    assert.throws(() => opener2.open(Buffer.from('wrong-aad'), ct0), /decryption failed/i);

    sealer.destroy();
    opener.destroy();
    opener2.destroy();
  }
});

test('HPKE strictly rejects all 14 low-order X25519 encodings (including in validateKemPublicKey/selectEchConfig), off-curve P-256, seq overflow, and post-destroy use', () => {
  const x25519Suite = ALL_SUPPORTED_HPKE_SUITES[0];
  const p256Suite = ALL_SUPPORTED_HPKE_SUITES[3];

  // All 7 masked Curve25519 low-order u-coordinates × both MSB values (0x00 / 0x80) = all 14 encodings
  const lowOrderBase7 = [
    unhex('0000000000000000000000000000000000000000000000000000000000000000'), // 0
    unhex('0100000000000000000000000000000000000000000000000000000000000000'), // 1
    unhex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'), // order 8
    unhex('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'), // order 8
    unhex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), // p - 1
    unhex('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), // p
    unhex('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), // p + 1
  ];
  const all14LowOrder = [];
  for (const base of lowOrderBase7) {
    for (const msb of [0x00, 0x80]) {
      const k = Buffer.from(base);
      k[31] |= msb;
      all14LowOrder.push(k);
    }
  }
  assert.equal(all14LowOrder.length, 14);

  const badX25519Keys = [
    Buffer.alloc(0),
    Buffer.alloc(31, 0x42),
    Buffer.alloc(33, 0x42),
    ...all14LowOrder,
  ];
  const validKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);

  for (const bad of badX25519Keys) {
    assert.throws(
      () => validateX25519PublicKey(bad),
      (e) => e.code === 'HPKE_INVALID_KEY',
      `validateX25519PublicKey must reject ${bad.toString('hex')}`,
    );
    assert.throws(
      () => validateKemPublicKey(HPKE_KEM_X25519_SHA256, bad),
      (e) => e.code === 'HPKE_INVALID_KEY',
      `validateKemPublicKey must reject ${bad.toString('hex')}`,
    );
    assert.throws(
      () => setupBaseS(x25519Suite, bad, Buffer.from('info')),
      (e) => e.code === 'HPKE_INVALID_KEY',
      `setupBaseS must reject ${bad.toString('hex')}`,
    );
    assert.throws(
      () => setupBaseR(x25519Suite, bad, validKp.privateKey, Buffer.from('info')),
      (e) => e.code === 'HPKE_INVALID_KEY',
      `setupBaseR must reject ${bad.toString('hex')}`,
    );
  }

  // selectEchConfig MUST skip every low-order X25519 entry and select the subsequent valid config
  const lowOrderConfigs = all14LowOrder.map((badPk, idx) =>
    encodeEchConfig({
      configId: idx + 1,
      kemId: HPKE_KEM_X25519_SHA256,
      publicKey: badPk,
      cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
      publicName: 'low-order.example.com',
    }),
  );
  const goodCfg = encodeEchConfig({
    configId: 99,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: validKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    publicName: 'valid-after-low-order.example.com',
  });
  const selected = selectEchConfig(encodeEchConfigList([...lowOrderConfigs, goodCfg]));
  assert.ok(selected);
  assert.equal(selected.config.configId, 99);
  assert.equal(selected.config.publicName, 'valid-after-low-order.example.com');

  // Malformed / compressed / off-curve P-256 points
  const badP256Keys = [
    Buffer.alloc(0),
    Buffer.alloc(64, 0x04),
    Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, 0x11)]), // compressed
    Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0x00)]), // (0,0)
    Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0x01)]), // off-curve
    Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xff)]), // >= p
  ];
  for (const bad of badP256Keys) {
    assert.throws(
      () => setupBaseS(p256Suite, bad, Buffer.from('info')),
      (e) => e.code === 'HPKE_INVALID_KEY',
      `expected bad P-256 key (len=${bad.length}) to fail`,
    );
  }

  // Sequence number overflow must fail without wrapping or mutating seq
  const sealer = new HpkeSealer(
    x25519Suite,
    Buffer.alloc(16, 0x11),
    Buffer.alloc(12, 0x22),
    MAX_HPKE_SEQ,
  );
  assert.throws(
    () => sealer.seal(Buffer.from('aad'), Buffer.from('pt')),
    (e) => e.code === 'HPKE_SEQ_OVERFLOW',
  );
  assert.equal(sealer.seq, MAX_HPKE_SEQ);

  // Destroyed sealer rejects further calls
  sealer.destroy();
  assert.throws(() => sealer.seal(Buffer.from('aad'), Buffer.from('pt')), (e) => e.code === 'HPKE_ERROR');

  // Non-ASCII high-bit bytes in public_name MUST NOT be masked to ASCII and accepted
  const nonAsciiCfg = Buffer.from(goodCfg);
  const nameIdx = nonAsciiCfg.indexOf(Buffer.from('valid-after-low-order.example.com', 'ascii'));
  assert.ok(nameIdx > 0);
  nonAsciiCfg[nameIdx] |= 0x80;
  assert.equal(parseEchConfigList(encodeEchConfigList([nonAsciiCfg])).length, 0);
});

test('ECHConfigList parsing skips unsupported versions, EXPORT_ONLY, mandatory unknown extensions, and duplicate extensions', () => {
  const x25519Kp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const p256Kp = generateHpkeKeyPair(HPKE_KEM_P256_SHA256);

  // 1. Unsupported version (0xfe0c)
  const oldVerCfg = encodeEchConfig({
    version: 0xfe0c,
    configId: 1,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: x25519Kp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    publicName: 'old.example.com',
  });

  // 2. Unknown mandatory extension (high bit 0x8000 set)
  const mandatoryExtCfg = encodeEchConfig({
    configId: 2,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: x25519Kp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    publicName: 'mandatory.example.com',
    extensions: [{ type: 0x8001, data: Buffer.from([1, 2]) }],
  });

  // 3. Duplicate extension type
  const dupExtCfg = encodeEchConfig({
    configId: 3,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: x25519Kp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    publicName: 'dup.example.com',
    extensions: [
      { type: 0x0001, data: Buffer.from([1]) },
      { type: 0x0001, data: Buffer.from([2]) },
    ],
  });

  // 4. Valid P-256 config with EXPORT_ONLY listed first, followed by supported AES-256-GCM
  const validCfg = encodeEchConfig({
    configId: 7,
    kemId: HPKE_KEM_P256_SHA256,
    publicKey: p256Kp.publicKey,
    cipherSuites: [
      { kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_EXPORT_ONLY },
      { kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_256_GCM },
    ],
    maximumNameLength: 64,
    publicName: 'cloudflare-ech.com',
    extensions: [{ type: 0x0011, data: Buffer.from([0xaa]) }], // optional non-mandatory ext
  });

  const list = encodeEchConfigList([oldVerCfg, mandatoryExtCfg, dupExtCfg, validCfg]);
  const parsed = parseEchConfigList(list);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].version, ECH_VERSION);
  assert.equal(parsed[0].configId, 7);
  assert.equal(parsed[0].publicName, 'cloudflare-ech.com');
  assert.deepEqual(parsed[0].rawConfig, validCfg);

  const selected = selectEchConfig(list);
  assert.ok(selected);
  assert.equal(selected.config.publicName, 'cloudflare-ech.com');
  assert.equal(selected.suite.kemId, HPKE_KEM_P256_SHA256);
  assert.equal(selected.suite.aeadId, HPKE_AEAD_AES_256_GCM);
  assert.equal(selectEchPublicName(list), 'cloudflare-ech.com');

  // Base64 decode round-trip & malformed inputs
  const decodedB64 = decodeEchConfigBase64(list.toString('base64'));
  assert.deepEqual(decodedB64, list);
  assert.throws(() => decodeEchConfigBase64('not valid base64!!!'), (e) => e.code === 'ECH_INVALID_CONFIG');
  assert.equal(selectEchPublicName(Buffer.alloc(0)), null);
  assert.equal(selectEchPublicName(Buffer.from([0x00, 0x00])), null);
  assert.equal(selectEchPublicName(Buffer.from([0xff, 0xff, 0x01, 0x02])), null);
});
