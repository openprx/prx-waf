use waf_common::RequestCtx;

/// Default HTML block page template.
///
/// Placeholders:
/// - `{{req_id}}`    — unique request identifier
/// - `{{rule_name}}` — the WAF rule that triggered the block
/// - `{{client_ip}}` — the client's IP address
const DEFAULT_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>403 Forbidden — Request Blocked</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #f4f4f5; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #fff; border-radius: 8px; padding: 40px 56px;
          box-shadow: 0 4px 24px rgba(0,0,0,.10); max-width: 480px; text-align: center; }
  h1 { font-size: 2rem; color: #dc2626; margin: 0 0 8px; }
  p  { color: #6b7280; margin: 8px 0; }
  .detail { background: #f9fafb; border-radius: 4px; padding: 12px;
            font-size: .85rem; color: #374151; word-break: break-all; }
  .ref { font-size: .8rem; color: #9ca3af; margin-top: 20px; }
</style>
</head>
<body>
<div class="card">
  <h1>&#128683; 403 Forbidden</h1>
  <p>Your request has been blocked by the security policy.</p>
  <div class="detail">
    <strong>Reason:</strong> {{rule_name}}<br>
    <strong>Your IP:</strong> {{client_ip}}
  </div>
  <p class="ref">Request&nbsp;ID:&nbsp;<code>{{req_id}}</code></p>
</div>
</body>
</html>"#;

/// Escape a string for safe inclusion in HTML content.
///
/// Replaces `&`, `<`, `>`, `"`, and `'` with their HTML entity equivalents.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
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

/// Render the block page for the given request context and rule name.
///
/// Uses the per-host custom template if configured, otherwise falls back
/// to the built-in default template. All dynamic values are HTML-escaped
/// to prevent reflected XSS.
pub fn render_block_page(ctx: &RequestCtx, rule_name: &str) -> String {
    let template = ctx
        .host_config
        .block_page_template
        .as_deref()
        .unwrap_or(DEFAULT_TEMPLATE);

    template
        .replace("{{req_id}}", &html_escape(&ctx.req_id))
        .replace("{{rule_name}}", &html_escape(rule_name))
        .replace("{{client_ip}}", &html_escape(&ctx.client_ip.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn make_ctx(req_id: &str, ip: &str) -> RequestCtx {
        RequestCtx {
            req_id: req_id.to_string(),
            client_ip: ip.parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
        }
    }

    #[test]
    fn renders_default_template() {
        let ctx = make_ctx("abc-123", "1.2.3.4");
        let page = render_block_page(&ctx, "SQL Injection");
        assert!(page.contains("abc-123"));
        assert!(page.contains("1.2.3.4"));
        assert!(page.contains("SQL Injection"));
    }

    #[test]
    fn renders_custom_template() {
        let ctx_arc = Arc::new(HostConfig {
            block_page_template: Some("blocked: {{rule_name}} | {{req_id}} | {{client_ip}}".to_string()),
            ..HostConfig::default()
        });
        let mut ctx = make_ctx("req-xyz", "5.6.7.8");
        ctx.host_config = ctx_arc;
        let page = render_block_page(&ctx, "XSS");
        assert_eq!(page, "blocked: XSS | req-xyz | 5.6.7.8");
    }
}
