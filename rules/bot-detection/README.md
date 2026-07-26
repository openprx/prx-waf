> ## NOT LOADED — audited 2026-07-26
>
> The running proxy does not load this directory and never has; it reads only
> `rules/owasp-crs/` from a hardcoded path
> (`crates/waf-engine/src/checks/owasp.rs:53`). **Do not point the loader at
> it.** 42 rules declared, all 42 compile, and none blocked any of 52 benign
> requests — but 25 are `action: log`, which cannot block.
>
> The reason to leave it off is not false positives on ordinary traffic; it is
> that the directory duplicates two compiled-in detectors more weakly, fights
> one of them, and tries to express two things a stateless check cannot.
>
> * **`BOT-CRAWL-009` scores `AhrefsBot`, `SemrushBot`, `Sogou` and
>   `YandexBot` at `high` + `block`. All four are on the engine's own good-bot
>   allowlist** (`crates/waf-engine/src/checks/bot.rs`) — and that allowlist
>   does not protect them, because `BotCheck` returning `None` means "I did not
>   block", not "stop evaluating": the pipeline continues to the OWASP phase.
>   4 points is one `warning`-level CRS hit away from a 403 for the crawlers
>   this WAF deliberately welcomes.
> * **~20 of 42 duplicate `bot.rs` or `scanner.rs`** — headless browsers,
>   PhantomJS, Selenium, Nikto, the scanner-UA list, curl, python-requests,
>   Go-http-client — and duplicate them at `log` where the built-in blocks. A
>   YAML copy of a compiled-in rule adds nothing but a second place to look.
> * **Structurally dead**: `BOT-CRAWL-006/010/011`, `BOT-SCRAPE-012`,
>   `BOT-CRED-003/007/011` all match a literal `Header-Name:`, but
>   `field: headers` hands the matcher the name and the value separately
>   (`owasp.rs:1033`). `BOT-CRAWL-001` matches an empty user-agent, which is
>   not the same thing as a **missing** one — a missing header yields `None`
>   and the rule never runs.
> * **Scraping and credential stuffing are volumetric.** A rule that matches
>   `/forgot-password` detects the endpoint existing, not being abused.
>   `crates/waf-engine/src/checks/cc.rs` is the mechanism that can see rate,
>   and it is on by default.
> * `BOT-CRED-004` matches bare `Hydra` and `Medusa` at `critical`, which are
>   also the names of a media manager and a Meta configuration library that
>   ship them in their user-agents.
>
> Worth keeping if this directory is ever revisited: the AI-crawler table in
> `scraping.yaml` (`BOT-SCRAPE-001`..`007`) is genuinely new — nothing built in
> covers GPTBot/ClaudeBot/CCBot — and it is already `action: log`. Treat it as
> a policy list, not a security control.

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

- `BOT-CRAWL-*` rules targeting UAs are **not** all safe to block, whatever this
  line used to say: `BOT-CRAWL-009` blocks four crawlers the engine's own
  good-bot allowlist welcomes (`AhrefsBot`, `SemrushBot`, `Sogou`, `YandexBot`),
  and `BOT-CRAWL-002`'s bare `headless` branch matches any UA containing that
  word
- `BOT-SCRAPE-*` rules for curl/wget may affect developer tools — use `log` in dev environments
- `BOT-CRED-*` rules should be paired with rate limiting, not used in isolation

## References

- https://owasp.org/www-project-automated-threats-to-web-applications/
- https://github.com/nicowillis/bad-bot-list
- https://darkvisitors.com/
- https://github.com/ai-robots-txt/ai.robots.txt
