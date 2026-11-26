use chrono::Local;
use neruton_proto::{RegisterResponse, VERSION};

fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

fn c(code: &str, text: &str) -> String {
    if use_color() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn print_banner(resp: &RegisterResponse, target_url: &str) {
    let auth_label = match (resp.owner_username.as_deref(), resp.token_name.as_deref()) {
        (Some(owner), Some(token)) => format!("{owner} ({token})"),
        (Some(owner), None) => owner.to_string(),
        (None, Some(token)) => token.to_string(),
        (None, None) => "anonymous (open mode)".to_string(),
    };

    let rows = [
        ("Wildcard URL", resp.public_url.as_str(), "1;36"),
        ("Web Preview", resp.preview_url.as_str(), "1;32"),
        ("Path URL", resp.path_url.as_str(), "36"),
        ("Dashboard", resp.dashboard_url.as_str(), "34"),
        ("Forwarding", target_url, "33"),
        ("Prefix", resp.prefix.as_str(), "1;35"),
        ("Auth", auth_label.as_str(), "37"),
    ];

    let label_width = rows.iter().map(|(l, _, _)| l.len()).max().unwrap_or(12);
    let val_width = rows.iter().map(|(_, v, _)| v.len()).max().unwrap_or(24);
    let title = format!(" Neruton Tunnel v{VERSION} · Online ");
    let inner_width = (label_width + 3 + val_width).max(title.len()) + 2;

    let top_fill = inner_width.saturating_sub(title.len());
    let left_fill = 2.min(top_fill);
    let right_fill = top_fill.saturating_sub(left_fill);

    println!();
    println!(
        "{}{}{}{}",
        c("36", &format!("╭{}", "─".repeat(left_fill))),
        c("1;32", &title),
        c("36", &"─".repeat(right_fill)),
        c("36", "╮")
    );

    for (label, value, color) in rows {
        let pad_label = " ".repeat(label_width.saturating_sub(label.len()));
        let content_len = label_width + 3 + value.len();
        let pad_right = " ".repeat(inner_width.saturating_sub(content_len + 2));
        println!(
            "{} {}{} {} {}{} {}",
            c("36", "│"),
            c("2", label),
            pad_label,
            c("2", "→"),
            c(color, value),
            pad_right,
            c("36", "│")
        );
    }

    println!("{}", c("36", &format!("╰{}╯", "─".repeat(inner_width))));
    println!("{}", c("2", "Press Ctrl+C to close the tunnel.\n"));
}

pub fn log_request(method: &str, path: &str, status: u16, duration_ms: u64) {
    let now = Local::now().format("%H:%M:%S").to_string();
    let status_color = match status {
        101 => "1;35",
        200..=299 => "1;32",
        300..=399 => "1;36",
        400..=499 => "1;33",
        _ => "1;31",
    };
    let status_text = format!("{status:3}");
    let method_text = format!("{method:<7}");
    println!(
        "{}  {}  {}  {}  {}",
        c("2", &now),
        c(status_color, &status_text),
        c("1", &method_text),
        path,
        c("2", &format!("({duration_ms}ms)"))
    );
}

pub fn log_info(msg: &str) {
    let now = Local::now().format("%H:%M:%S").to_string();
    println!("{}  {}  {msg}", c("2", &now), c("1;36", "INFO"));
}

pub fn log_warn(msg: &str) {
    let now = Local::now().format("%H:%M:%S").to_string();
    eprintln!("{}  {}  {msg}", c("2", &now), c("1;33", "WARN"));
}

pub fn log_error(msg: &str) {
    let now = Local::now().format("%H:%M:%S").to_string();
    eprintln!("{}  {}  {msg}", c("2", &now), c("1;31", "ERR "));
}
