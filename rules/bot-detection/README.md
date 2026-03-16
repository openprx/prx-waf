# Bot Detection Rules

This directory contains WAF rules for detecting malicious bots, scrapers, credential stuffing tools, and automated abuse.

## Rule Files

| File | Coverage |
|------|----------|
| `crawlers.yaml` | Bad bot UAs, headless browsers, WebDriver detection |
| `scraping.yaml` | Scrapers, AI training bots, automated tools |
| `credential-stuffing.yaml` | Account takeover tools, login abuse patterns |

## ID Namespace

All rules use the `BOT-` prefix.

- `BOT-CRAWL-*` — Malicious crawlers and headless browsers
- `BOT-SCRAPE-*` — Content scrapers and AI training bots
- `BOT-CRED-*` — Credential stuffing and account enumeration

## Strategy

Bot detection works best in layers:

1. **Block** known-bad UAs unconditionally (paranoia 1)
2. **Log** suspicious patterns for analysis (paranoia 2-3)
3. **Challenge** ambiguous clients (paranoia 3-4)

## False Positive Guidance

- `BOT-CRAWL-*` rules targeting UAs are safe to block
- `BOT-SCRAPE-*` rules for curl/wget may affect developer tools — use `log` in dev environments
- `BOT-CRED-*` rules should be paired with rate limiting, not used in isolation

## References

- https://owasp.org/www-project-automated-threats-to-web-applications/
- https://github.com/nicowillis/bad-bot-list
- https://darkvisitors.com/
- https://github.com/ai-robots-txt/ai.robots.txt
