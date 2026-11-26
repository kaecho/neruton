/// Styled `502 Bad Gateway` HTML page returned when a requested tunnel prefix is not online.
pub fn offline_page_html(prefix: &str, dashboard_url: &str, base_domain: &str) -> String {
    let escaped_prefix = escape_html(prefix);
    let escaped_dashboard = escape_html(dashboard_url);
    let escaped_domain = escape_html(base_domain);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>502 Tunnel Offline — {escaped_prefix} · Neruton</title>
  <style>
    :root {{ color-scheme: dark; }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at top, #0f172a, #020617 70%);
      color: #e2e8f0;
      padding: 24px;
    }}
    .card {{
      width: 100%;
      max-width: 540px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 16px;
      padding: 32px;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 4px 12px;
      border-radius: 999px;
      background: rgba(239, 68, 68, 0.14);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.35);
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      margin-bottom: 18px;
    }}
    h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 10px; color: #f8fafc; }}
    p {{ color: #94a3b8; line-height: 1.6; font-size: 14px; margin-bottom: 18px; }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: rgba(30, 41, 59, 0.9);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 6px;
      padding: 2px 6px;
      color: #38bdf8;
      font-size: 13px;
    }}
    pre {{
      background: #020617;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 10px;
      padding: 12px 14px;
      overflow-x: auto;
      font-size: 12.5px;
      color: #7dd3fc;
      margin-bottom: 22px;
    }}
    .actions {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    a.btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 18px;
      border-radius: 10px;
      background: linear-gradient(135deg, #06b6d4, #10b981);
      color: #020617;
      font-weight: 600;
      font-size: 14px;
      text-decoration: none;
    }}
    a.btn:hover {{ opacity: 0.92; }}
  </style>
</head>
<body>
  <main class="card">
    <div class="badge">502 Bad Gateway · Tunnel Offline</div>
    <h1>Tunnel <code>{escaped_prefix}</code> is not connected</h1>
    <p>
      No active Neruton tunnel client is currently bound to
      <code>{escaped_prefix}.{escaped_domain}</code>.
      Start the CLI client on your machine to bring this endpoint online:
    </p>
    <pre>neruton tunnel --url http://localhost:3000 --subdomain {escaped_prefix}</pre>
    <div class="actions">
      <a class="btn" href="{escaped_dashboard}">Open Neruton Dashboard</a>
    </div>
  </main>
</body>
</html>"#
    )
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Inject `<base href="/t/<prefix>/">` after `<head>` (or at start of HTML) when no `<base` tag
/// is already present so relative assets resolve cleanly through the path proxy.
pub fn inject_base_tag(html: &str, prefix: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if has_base_tag(&lower) {
        return html.to_string();
    }

    let base_tag = format!(r#"<base href="/t/{}/">"#, escape_html(prefix));
    if let Some(insert_pos) = find_head_open_end(&lower) {
        let mut out = String::with_capacity(html.len() + base_tag.len());
        out.push_str(&html[..insert_pos]);
        out.push_str(&base_tag);
        out.push_str(&html[insert_pos..]);
        out
    } else {
        format!("{base_tag}{html}")
    }
}

fn has_base_tag(lower_html: &str) -> bool {
    let bytes = lower_html.as_bytes();
    let mut start = 0;
    while let Some(idx) = lower_html[start..].find("<base") {
        let pos = start + idx + 5;
        if pos < bytes.len() {
            let next = bytes[pos];
            if next.is_ascii_whitespace() || next == b'>' || next == b'/' {
                return true;
            }
        }
        start = pos;
    }
    false
}

fn find_head_open_end(lower_html: &str) -> Option<usize> {
    let bytes = lower_html.as_bytes();
    let mut start = 0;
    while let Some(idx) = lower_html[start..].find("<head") {
        let after = start + idx + 5;
        if after < bytes.len() {
            let next = bytes[after];
            if next == b'>' {
                return Some(after + 1);
            }
            if next.is_ascii_whitespace() {
                if let Some(close_rel) = lower_html[after..].find('>') {
                    return Some(after + close_rel + 1);
                }
            }
        }
        start = after;
    }
    None
}

/// Remove any `frame-ancestors` directive from a `Content-Security-Policy` header value so the
/// embedded `/preview/<prefix>` iframe can display tunneled pages.
pub fn strip_csp_frame_ancestors(csp: &str) -> Option<String> {
    let kept: Vec<&str> = csp
        .split(';')
        .map(str::trim)
        .filter(|dir| {
            if dir.is_empty() {
                return false;
            }
            let name = dir
                .split_ascii_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            name != "frame-ancestors"
        })
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

/// Rewrite root-relative redirect `Location: /foo` headers to `/t/<prefix>/foo`.
pub fn rewrite_location_header(location: &str, prefix: &str) -> Option<String> {
    if !location.starts_with('/') || location.starts_with("//") {
        return None;
    }
    let mount_slash = format!("/t/{prefix}/");
    let mount_exact = format!("/t/{prefix}");
    if location.starts_with(&mount_slash) || location == mount_exact {
        return None;
    }
    Some(format!("/t/{prefix}{location}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_base_after_head() {
        let html =
            "<!doctype html><html><HEAD lang=\"en\"><title>Hi</title></HEAD><body></body></html>";
        let out = inject_base_tag(html, "demo");
        assert_eq!(
            out,
            "<!doctype html><html><HEAD lang=\"en\"><base href=\"/t/demo/\"><title>Hi</title></HEAD><body></body></html>"
        );
    }

    #[test]
    fn skips_injection_if_base_exists() {
        let html = "<html><head><base href=\"/custom/\"><title>Hi</title></head></html>";
        assert_eq!(inject_base_tag(html, "demo"), html);
    }

    #[test]
    fn prepends_base_when_no_head() {
        let html = "<h1>Hello</h1>";
        assert_eq!(
            inject_base_tag(html, "demo"),
            "<base href=\"/t/demo/\"><h1>Hello</h1>"
        );
    }

    #[test]
    fn strips_frame_ancestors_from_csp() {
        assert_eq!(strip_csp_frame_ancestors("frame-ancestors 'none'"), None);
        assert_eq!(
            strip_csp_frame_ancestors("default-src 'self'; frame-ancestors 'self'; img-src *"),
            Some("default-src 'self'; img-src *".to_string())
        );
    }

    #[test]
    fn rewrites_relative_locations() {
        assert_eq!(
            rewrite_location_header("/login?next=/", "app"),
            Some("/t/app/login?next=/".to_string())
        );
        assert_eq!(rewrite_location_header("/t/app/home", "app"), None);
        assert_eq!(rewrite_location_header("https://example.com/", "app"), None);
        assert_eq!(rewrite_location_header("//cdn.example.com/a", "app"), None);
    }
}
