import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, '..');
const require = createRequire(import.meta.url);

test('Dual ESM and CJS package imports expose identical public API', async () => {
  const esm = await import('../dist/esm/index.js');
  const cjs = require('../dist/cjs/index.js');

  const expectedExports = [
    'VERSION',
    'connect',
    'forward',
    'http',
    'Tunnel',
    'loadConfig',
    'saveConfig',
    'configPath',
    'parseConfigToml',
    'serializeConfigToml',
    'resolveConnectionSettings',
    'buildTunnelWsUrl',
    'normalizeTargetUrl',
    'validatePrefix',
    'validatePrefixFormat',
    'generateUuidPrefix',
    'YamuxSession',
    'YamuxStream',
    'YamuxFrameDecoder',
    'encodeYamuxHeader',
    'decodeYamuxHeader',
    'encodeYamuxFrame',
    'YamuxFrameType',
    'YamuxFlag',
    'YamuxGoAwayCode',
    'WsByteStream',
    'LocalForwarder',
    'AuthenticationError',
    'RegistrationError',
    'PrefixError',
    'YamuxError',
    'ConfigError',
    'DohError',
    'NerutonError',
    'DEFAULT_DOH_ENDPOINTS',
    'VALID_SNI_MODES',
    'parseDohOption',
    'shouldSkipDoh',
    'encodeDnsQuery',
    'decodeDnsResponse',
    'parseHttpsRdata',
    'resolveHostWithDoh',
    'parseSniMode',
    'assertSniModeSupported',
    'planStealthTls',
    'findClientHelloSplitPoints',
    'ClientHelloFragmentDuplex',
    'connectTcpWithFailover',
    'createStealthTlsSocket',
    'formatTransportSummary',
    'setupBaseS',
    'setupBaseR',
    'HpkeSealer',
    'HpkeOpener',
    'parseEchConfigList',
    'selectEchConfig',
    'encodeEchConfig',
    'encodeEchConfigList',
    'Tls13RecordCipher',
    'Tls13EchDuplex',
    'TlsProtocolError',
    'EchRejectedError',
    'verifyX509Chain',
    'performTls13EchHandshake',
    'connectTls13EchWithRetry',
    'runCli',
  ];

  for (const key of expectedExports) {
    assert.notEqual(esm[key], undefined, `ESM missing export: ${key}`);
    assert.notEqual(cjs[key], undefined, `CJS missing export: ${key}`);
  }

  assert.equal(esm.VERSION, '0.4.0');
  assert.equal(cjs.VERSION, '0.4.0');

  // Verify self-referencing package exports via `import('neruton')` and `require('neruton')`
  const esmByName = await import('neruton');
  const cjsByName = require('neruton');
  assert.equal(esmByName.VERSION, '0.4.0');
  assert.equal(cjsByName.VERSION, '0.4.0');
  assert.equal(typeof esmByName.connect, 'function');
  assert.equal(typeof cjsByName.connect, 'function');
  assert.equal(typeof cjsByName.forward, 'function');
  assert.equal(typeof cjsByName.http, 'function');
});

test('CLI bin executes cleanly via node and reports version/help', () => {
  const binPath = path.join(pkgRoot, 'dist', 'esm', 'bin.js');

  const verOut = execFileSync(process.execPath, [binPath, 'version'], { encoding: 'utf8' });
  assert.match(verOut, /^neruton 0\.4\.0 \(/);

  const helpOut = execFileSync(process.execPath, [binPath, '--help'], { encoding: 'utf8' });
  assert.match(helpOut, /Commands:/);
  assert.match(helpOut, /tunnel/);
  assert.match(helpOut, /http/);
  assert.match(helpOut, /config/);
});
