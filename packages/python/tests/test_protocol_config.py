"""Unit tests for protocol helpers, prefix validation, URL builders, and config.toml."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from neruton.config import (
    Config,
    config_path,
    load_config,
    resolve_server_and_token,
    save_config,
)
from neruton.errors import PrefixError
from neruton.protocol import (
    RESERVED_PREFIXES,
    RegisterRequest,
    RegisterResponse,
    build_tunnel_ws_url,
    format_401_error,
    generate_uuid_prefix,
    is_non_retryable_rejection,
    normalize_target_url,
    validate_prefix,
)


class TestProtocolHelpers(unittest.TestCase):
    def test_uuid_prefix_is_valid(self) -> None:
        uid = generate_uuid_prefix()
        self.assertEqual(len(uid), 36)
        self.assertEqual(validate_prefix(uid), uid)

    def test_valid_prefixes(self) -> None:
        self.assertEqual(validate_prefix("a"), "a")
        self.assertEqual(validate_prefix("0"), "0")
        self.assertEqual(validate_prefix("Test-Test"), "test-test")
        self.assertEqual(validate_prefix("  my-app-123  "), "my-app-123")
        max_len = "a" * 63
        self.assertEqual(validate_prefix(max_len), max_len)

    def test_invalid_and_reserved_prefixes(self) -> None:
        with self.assertRaises(PrefixError) as cm:
            validate_prefix("")
        self.assertEqual(cm.exception.code, "empty")

        with self.assertRaises(PrefixError) as cm:
            validate_prefix("   ")
        self.assertEqual(cm.exception.code, "empty")

        with self.assertRaises(PrefixError) as cm:
            validate_prefix("a" * 64)
        self.assertEqual(cm.exception.code, "too_long")

        for bad in ("-abc", "abc-", "foo.bar", "foo_bar", "café"):
            with self.assertRaises(PrefixError) as cm:
                validate_prefix(bad)
            self.assertEqual(cm.exception.code, "invalid_format")

        for reserved in RESERVED_PREFIXES:
            with self.assertRaises(PrefixError) as cm:
                validate_prefix(reserved)
            self.assertEqual(cm.exception.code, "reserved")

        with self.assertRaises(PrefixError) as cm:
            validate_prefix("staging", extra_reserved=["staging"])
        self.assertEqual(cm.exception.code, "reserved")

    def test_build_tunnel_ws_url(self) -> None:
        self.assertEqual(
            build_tunnel_ws_url("https://neruton.moer.eu.org"),
            "wss://neruton.moer.eu.org/_neruton/tunnel",
        )
        self.assertEqual(
            build_tunnel_ws_url("http://127.0.0.1:8080"),
            "ws://127.0.0.1:8080/_neruton/tunnel",
        )
        self.assertEqual(
            build_tunnel_ws_url("neruton.moer.eu.org:443"),
            "wss://neruton.moer.eu.org/_neruton/tunnel",
        )
        self.assertEqual(
            build_tunnel_ws_url("wss://neruton.moer.eu.org/_neruton/tunnel"),
            "wss://neruton.moer.eu.org/_neruton/tunnel",
        )
        self.assertEqual(
            build_tunnel_ws_url("https://example.com/subpath/"),
            "wss://example.com/subpath/_neruton/tunnel",
        )
        with self.assertRaises(ValueError):
            build_tunnel_ws_url("ftp://example.com")
        with self.assertRaises(ValueError):
            build_tunnel_ws_url("   ")

    def test_normalize_target_url(self) -> None:
        self.assertEqual(normalize_target_url(3000), "http://127.0.0.1:3000/")
        self.assertEqual(normalize_target_url("3000"), "http://127.0.0.1:3000/")
        self.assertEqual(normalize_target_url("localhost:8080"), "http://localhost:8080/")
        self.assertEqual(
            normalize_target_url("https://localhost:8443/app"),
            "https://localhost:8443/app",
        )
        with self.assertRaises(ValueError):
            normalize_target_url("ftp://example.com")
        with self.assertRaises(ValueError):
            normalize_target_url("")
        with self.assertRaises(ValueError):
            normalize_target_url(70000)

    def test_register_request_and_response_json(self) -> None:
        req = RegisterRequest(
            prefix="my-app",
            target_url="http://127.0.0.1:3000/",
            client_version="0.4.0",
            client_os="linux/x86_64",
        )
        encoded = req.to_json()
        decoded = RegisterRequest.from_json(encoded)
        self.assertEqual(decoded, req)

        resp_json = (
            '{"ok":true,"tunnel_id":"tid-1","prefix":"my-app",'
            '"public_url":"https://my-app.moer.eu.org",'
            '"path_url":"https://neruton.moer.eu.org/t/my-app/",'
            '"preview_url":"https://neruton.moer.eu.org/preview/my-app",'
            '"dashboard_url":"https://neruton.moer.eu.org/",'
            '"error":null,"owner_username":"admin","token_name":"Default CLI Token"}'
        )
        resp = RegisterResponse.from_json(resp_json)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.prefix, "my-app")
        self.assertEqual(resp.owner_username, "admin")
        self.assertEqual(resp.token_name, "Default CLI Token")

    def test_401_and_non_retryable_helpers(self) -> None:
        msg, srv = format_401_error(b'{"error":"Tunnel token is disabled."}', had_token=True)
        self.assertEqual(srv, "Tunnel token is disabled.")
        self.assertIn("401 Unauthorized", msg)
        self.assertIn("Tunnel token is disabled.", msg)

        msg2, srv2 = format_401_error(None, had_token=False)
        self.assertIsNone(srv2)
        self.assertIn("NERUTON_TOKEN", msg2)

        self.assertTrue(is_non_retryable_rejection("prefix 'api' is reserved"))
        self.assertTrue(is_non_retryable_rejection("prefix 'x' is not permitted by this token"))
        self.assertTrue(is_non_retryable_rejection("tunnel limit reached (2 max)"))
        self.assertFalse(is_non_retryable_rejection("prefix 'app' is already in use"))


class TestConfig(unittest.TestCase):
    def test_load_missing_and_save_roundtrip_with_0600_perms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "nested" / "config.toml"
            self.assertEqual(config_path(cfg_file), cfg_file)
            empty = load_config(cfg_file)
            self.assertIsNone(empty.server)
            self.assertIsNone(empty.token)

            saved = save_config(
                Config(server="https://example.org", token='ntk_abc"\\123'),
                cfg_file,
            )
            self.assertEqual(saved, cfg_file)
            self.assertTrue(cfg_file.exists())

            if os.name != "nt":
                mode = stat.S_IMODE(cfg_file.stat().st_mode)
                self.assertEqual(mode, 0o600)

            loaded = load_config(cfg_file)
            self.assertEqual(loaded.server, "https://example.org")
            self.assertEqual(loaded.token, 'ntk_abc"\\123')

    def test_resolve_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "config.toml"
            save_config(server="https://file.example", token="ntk_file", path=cfg_file)

            with mock.patch.dict(os.environ, {}, clear=True):
                s, t = resolve_server_and_token(config_file=cfg_file)
                self.assertEqual((s, t), ("https://file.example", "ntk_file"))

            with mock.patch.dict(
                os.environ,
                {"NERUTON_SERVER": "https://env.example", "NERUTON_AUTH_TOKEN": "master_tok"},
                clear=True,
            ):
                s, t = resolve_server_and_token(config_file=cfg_file)
                self.assertEqual((s, t), ("https://env.example", "master_tok"))

            with mock.patch.dict(
                os.environ,
                {
                    "NERUTON_SERVER": "https://env.example",
                    "NERUTON_TOKEN": "ntk_env",
                    "NERUTON_AUTH_TOKEN": "master_tok",
                },
                clear=True,
            ):
                s, t = resolve_server_and_token(config_file=cfg_file)
                self.assertEqual((s, t), ("https://env.example", "ntk_env"))

                s2, t2 = resolve_server_and_token(
                    server="https://arg.example",
                    token="ntk_arg",
                    config_file=cfg_file,
                )
                self.assertEqual((s2, t2), ("https://arg.example", "ntk_arg"))


if __name__ == "__main__":
    unittest.main()
