import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import {
  DEFAULT_SERVER_URL,
  PrefixError,
  RESERVED_PREFIXES,
  VERSION,
  buildTunnelWsUrl,
  configPath,
  generateUuidPrefix,
  loadConfig,
  normalizeTargetUrl,
  parseConfigToml,
  resolveConnectionSettings,
  runCli,
  saveConfig,
  serializeConfigToml,
  validatePrefix,
  validatePrefixFormat,
} from '../dist/esm/index.js';

function captureStream() {
  const s = new PassThrough();
  const chunks = [];
  s.on('data', (c) => chunks.push(Buffer.from(c)));
  return {
    stream: s,
    text: () => Buffer.concat(chunks).toString('utf8'),
  };
}

test('Prefix validation matches Rust neruton-proto rules', () => {
  const uuid = generateUuidPrefix();
  assert.equal(uuid.length, 36);
  assert.equal(validatePrefix(uuid), uuid);

  assert.equal(validatePrefix('a'), 'a');
  assert.equal(validatePrefix('0'), '0');
  assert.equal(validatePrefix('Test-Test'), 'test-test');
  assert.equal(validatePrefix('  my-app-123  '), 'my-app-123');
  const maxLen = 'a'.repeat(63);
  assert.equal(validatePrefix(maxLen), maxLen);

  assert.throws(() => validatePrefix(''), (e) => e instanceof PrefixError && e.kind === 'empty');
  assert.throws(() => validatePrefix('   '), (e) => e instanceof PrefixError && e.kind === 'empty');
  assert.throws(
    () => validatePrefix('a'.repeat(64)),
    (e) => e instanceof PrefixError && e.kind === 'too_long',
  );
  for (const bad of ['-abc', 'abc-', 'foo.bar', 'foo_bar']) {
    assert.throws(
      () => validatePrefix(bad),
      (e) => e instanceof PrefixError && e.kind === 'invalid_format',
    );
  }
  for (const reserved of RESERVED_PREFIXES) {
    assert.throws(
      () => validatePrefix(reserved),
      (e) => e instanceof PrefixError && e.kind === 'reserved',
    );
  }
  assert.throws(
    () => validatePrefix('staging', ['staging']),
    (e) => e instanceof PrefixError && e.kind === 'reserved',
  );
  // validatePrefixFormat skips reserved list
  assert.equal(validatePrefixFormat('admin'), 'admin');
});

test('URL normalization matches Rust neruton-proto rules', () => {
  assert.equal(
    buildTunnelWsUrl('https://neruton.moer.eu.org').toString(),
    'wss://neruton.moer.eu.org/_neruton/tunnel',
  );
  assert.equal(
    buildTunnelWsUrl('http://127.0.0.1:8080').toString(),
    'ws://127.0.0.1:8080/_neruton/tunnel',
  );
  assert.equal(
    buildTunnelWsUrl('neruton.moer.eu.org:443').toString(),
    'wss://neruton.moer.eu.org/_neruton/tunnel',
  );
  assert.equal(
    buildTunnelWsUrl('wss://neruton.moer.eu.org/_neruton/tunnel').toString(),
    'wss://neruton.moer.eu.org/_neruton/tunnel',
  );
  assert.equal(
    buildTunnelWsUrl('https://example.com/subpath/').toString(),
    'wss://example.com/subpath/_neruton/tunnel',
  );
  assert.throws(() => buildTunnelWsUrl('ftp://example.com'));

  assert.equal(normalizeTargetUrl('3000').toString(), 'http://127.0.0.1:3000/');
  assert.equal(normalizeTargetUrl(3000).toString(), 'http://127.0.0.1:3000/');
  assert.equal(normalizeTargetUrl('localhost:8080').toString(), 'http://localhost:8080/');
  assert.equal(
    normalizeTargetUrl('https://localhost:8443/app').toString(),
    'https://localhost:8443/app',
  );
  assert.throws(() => normalizeTargetUrl('ftp://example.com'));
  assert.throws(() => normalizeTargetUrl(70000));
});

test('Config TOML read/write, 0600 permissions, and env precedence', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-node-cfg-'));
  const cfgFile = path.join(tmpDir, 'nested', 'config.toml');

  try {
    assert.deepEqual(loadConfig(cfgFile), {});

    const savedPath = saveConfig(
      { server: 'https://tunnel.example.com', token: 'ntk_secret_value_123' },
      cfgFile,
    );
    assert.equal(savedPath, cfgFile);

    if (process.platform !== 'win32') {
      const mode = fs.statSync(cfgFile).mode & 0o777;
      assert.equal(mode, 0o600, `expected 0600, got ${mode.toString(8)}`);
    }

    const raw = fs.readFileSync(cfgFile, 'utf8');
    assert.match(raw, /server = "https:\/\/tunnel\.example\.com"/);
    assert.match(raw, /token = "ntk_secret_value_123"/);

    const loaded = loadConfig(cfgFile);
    assert.deepEqual(loaded, {
      server: 'https://tunnel.example.com',
      token: 'ntk_secret_value_123',
    });

    // Comments, single quotes, and escapes
    const parsed = parseConfigToml(`
# comment line
server = 'http://127.0.0.1:8080' # inline comment
token = "ntk_escaped_\\"quote\\"_\\\\slash"

[ignored_section]
server = "should_not_override"
`);
    assert.equal(parsed.server, 'http://127.0.0.1:8080');
    assert.equal(parsed.token, 'ntk_escaped_"quote"_\\slash');

    const roundtrip = parseConfigToml(serializeConfigToml(parsed));
    assert.deepEqual(roundtrip, parsed);

    // Env precedence: explicit > NERUTON_TOKEN > NERUTON_AUTH_TOKEN > config.toml
    const fromFile = resolveConnectionSettings({ configPath: cfgFile, env: {} });
    assert.equal(fromFile.server, 'https://tunnel.example.com');
    assert.equal(fromFile.token, 'ntk_secret_value_123');

    const fromAuthEnv = resolveConnectionSettings({
      configPath: cfgFile,
      env: { NERUTON_AUTH_TOKEN: 'master-tok' },
    });
    assert.equal(fromAuthEnv.token, 'master-tok');

    const fromTokenEnv = resolveConnectionSettings({
      configPath: cfgFile,
      env: {
        NERUTON_SERVER: 'https://env.example.com',
        NERUTON_TOKEN: 'env-tok',
        NERUTON_AUTH_TOKEN: 'master-tok',
      },
    });
    assert.equal(fromTokenEnv.server, 'https://env.example.com');
    assert.equal(fromTokenEnv.token, 'env-tok');

    const fromExplicit = resolveConnectionSettings({
      server: 'http://localhost:9000',
      token: 'explicit-tok',
      configPath: cfgFile,
      env: { NERUTON_SERVER: 'https://env.example.com', NERUTON_TOKEN: 'env-tok' },
    });
    assert.equal(fromExplicit.server, 'http://localhost:9000');
    assert.equal(fromExplicit.token, 'explicit-tok');

    // Default fallback
    const defaultOnly = resolveConnectionSettings({
      configPath: path.join(tmpDir, 'missing.toml'),
      env: {},
    });
    assert.equal(defaultOnly.server, DEFAULT_SERVER_URL);
    assert.equal(defaultOnly.token, undefined);

    // Default configPath ends with .config/neruton/config.toml on Unix
    if (process.platform !== 'win32') {
      assert.ok(configPath().endsWith(path.join('.config', 'neruton', 'config.toml')));
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('CLI commands: version, config path/set/show, and validation errors', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-node-cli-'));
  const cfgFile = path.join(tmpDir, 'config.toml');

  try {
    const outVer = captureStream();
    const codeVer = await runCli(['version'], { stdout: outVer.stream });
    assert.equal(codeVer, 0);
    assert.match(outVer.text(), new RegExp(`^neruton ${VERSION} \\(`));

    const outPath = captureStream();
    assert.equal(
      await runCli(['config', 'path', '--config', cfgFile], { stdout: outPath.stream }),
      0,
    );
    assert.equal(outPath.text().trim(), cfgFile);

    const outSet = captureStream();
    assert.equal(
      await runCli(
        ['config', 'set', '--server', 'https://srv.test', '--token', 'ntk_abc', '--config', cfgFile],
        { stdout: outSet.stream },
      ),
      0,
    );
    assert.match(outSet.text(), /Saved configuration to/);

    const outShow = captureStream();
    assert.equal(
      await runCli(['config', 'show', '--config', cfgFile], { stdout: outShow.stream, env: {} }),
      0,
    );
    const showText = outShow.text();
    assert.match(showText, /Effective server: https:\/\/srv\.test/);
    assert.match(showText, /Saved token:\s+<configured>/);
    assert.ok(!showText.includes('ntk_abc'), 'config show must never print raw token');

    const errMissing = captureStream();
    assert.equal(await runCli(['tunnel'], { stderr: errMissing.stream }), 1);
    assert.match(errMissing.text(), /--url/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
