//! Deterministic per-request `DoS` work budget (plan v2.2 §12).
//!
//! [`ContentInspectionState`] is the **single cross-phase owner** of the Lane 2
//! work budget (plan §12.3). It is defined here in `waf-engine` and threaded
//! through the engine via an explicit `&mut ContentInspectionState` parameter:
//!
//! * HTTP/1.1 stores one instance in `gateway::GatewayCtx` so the header and
//!   body phases of a request share the same budget;
//! * HTTP/3 (which has no `GatewayCtx`) uses a local instance reused across the
//!   two phases.
//!
//! Both entry points reach the same owner type, resolving codex must-fix P1-2
//! (`GatewayCtx` alone could not cover HTTP/3).
//!
//! The time softness (an `Instant` deadline cannot preempt a running parse) is
//! handled at the detector layer; this module is the deterministic *work-count*
//! half. Exceeding any cap sets [`ContentInspectionState::degraded`]. This module
//! only *records* exhaustion; the fail-open itself is enforced in
//! [`super::scoring::score`], which returns **no** recommendation for a degraded
//! request so Lane 2 never overwrites the legacy verdict (plan §12.4).

use waf_common::content_security_config::SemanticBudgetConfig;

/// Immutable work-budget caps for one request (compiled from
/// [`SemanticBudgetConfig`]).
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_fields_per_phase: u32,
    pub max_views_per_field: u32,
    pub max_ast_attempts_per_request: u32,
    pub max_ast_input_bytes_total: usize,
    pub max_html_parse_attempts_per_request: u32,
    pub max_html_parse_input_bytes_total: usize,
    pub max_tokens_per_view: u32,
    pub max_list_items: u32,
    pub max_preprocess_output_bytes_total: usize,
    pub max_field_input_bytes: usize,
    pub max_decode_rounds: u8,
}

impl Default for Budget {
    fn default() -> Self {
        Self::from_config(&SemanticBudgetConfig::default())
    }
}

impl Budget {
    /// Compile the serializable config into immutable caps.
    #[must_use]
    pub const fn from_config(cfg: &SemanticBudgetConfig) -> Self {
        Self {
            max_fields_per_phase: cfg.max_fields_per_phase,
            max_views_per_field: cfg.max_views_per_field,
            max_ast_attempts_per_request: cfg.max_ast_attempts_per_request,
            max_ast_input_bytes_total: cfg.max_ast_input_bytes_total,
            max_html_parse_attempts_per_request: cfg.max_html_parse_attempts_per_request,
            max_html_parse_input_bytes_total: cfg.max_html_parse_input_bytes_total,
            max_tokens_per_view: cfg.max_tokens_per_view,
            max_list_items: cfg.max_list_items,
            max_preprocess_output_bytes_total: cfg.max_preprocess_output_bytes_total,
            max_field_input_bytes: cfg.max_field_input_bytes,
            max_decode_rounds: cfg.max_decode_rounds,
        }
    }
}

/// Mutable per-request Lane 2 work-accounting state (plan §12.3).
///
/// Counters are cumulative across the header and body phases of one request so
/// a request cannot double its worst-case work by splitting payloads between the
/// two phases. `fields_used` is the only per-phase counter (reset between
/// phases via [`Self::begin_phase`]); everything else is per-request.
#[derive(Debug, Clone)]
pub struct ContentInspectionState {
    budget: Budget,
    fields_used: u32,
    ast_attempts_used: u32,
    ast_input_bytes_used: usize,
    html_parse_attempts_used: u32,
    html_parse_input_bytes_used: usize,
    preprocess_output_bytes_used: usize,
    degraded: bool,
    /// Telemetry: number of Lane 2 evaluations performed on this request
    /// (per-phase). Used for the observation/pipeline counters (plan §3.4).
    semantic_evaluations: u32,
    /// Per-view scratch channel for the two-detector XSS corroboration (P-XSS-2).
    ///
    /// The XSS DOM detector — which already HTML-parses each view exactly once —
    /// stashes the JS **execution contexts** it extracted from that single parse
    /// (event-handler attribute values + `javascript:` / `vbscript:` URL script
    /// bodies) here; the lightweight [`super::xss_js::XssJsTokenDetector`],
    /// registered immediately after it, drains them and classifies dangerous JS
    /// tokens. The token detector therefore never parses HTML itself — no second
    /// parse, no extra parse budget — and it inspects only genuinely-parsed
    /// attributes (never a text node), so `element.onerror = eval(x)` prose or
    /// `<textarea>`/`<template>` inert content never reaches it. The DOM detector
    /// overwrites this on every view it inspects (with the extracted values, or an
    /// empty vec), so a previous view's contexts can never leak forward.
    xss_js_contexts: Vec<String>,
}

impl Default for ContentInspectionState {
    fn default() -> Self {
        Self::new(Budget::default())
    }
}

impl ContentInspectionState {
    #[must_use]
    pub const fn new(budget: Budget) -> Self {
        Self {
            budget,
            fields_used: 0,
            ast_attempts_used: 0,
            ast_input_bytes_used: 0,
            html_parse_attempts_used: 0,
            html_parse_input_bytes_used: 0,
            preprocess_output_bytes_used: 0,
            degraded: false,
            semantic_evaluations: 0,
            xss_js_contexts: Vec::new(),
        }
    }

    /// Reset the per-phase field counter at the start of a phase. Per-request
    /// counters (AST attempts / bytes / degraded) are intentionally preserved.
    pub const fn begin_phase(&mut self) {
        self.fields_used = 0;
        self.semantic_evaluations = self.semantic_evaluations.saturating_add(1);
    }

    #[must_use]
    pub const fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Whether the budget has been exhausted at any point this request.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Force the degraded flag (e.g. a soft time-deadline breach at the detector
    /// layer). Idempotent.
    pub const fn mark_degraded(&mut self) {
        self.degraded = true;
    }

    #[must_use]
    pub const fn semantic_evaluations(&self) -> u32 {
        self.semantic_evaluations
    }

    /// Stash the JS execution contexts the XSS DOM detector extracted from the
    /// **current view** (P-XSS-2). Called by the DOM detector on every view it
    /// inspects — with the extracted event-handler / `javascript:`-URL bodies, or
    /// an empty vec — so the token detector, which drains this immediately after,
    /// can never read a previous view's contexts.
    pub fn stash_xss_js_contexts(&mut self, contexts: Vec<String>) {
        self.xss_js_contexts = contexts;
    }

    /// Drain the stashed XSS JS contexts, leaving the channel empty (P-XSS-2).
    /// The token detector classifies dangerous JS tokens inside them.
    #[must_use]
    pub fn take_xss_js_contexts(&mut self) -> Vec<String> {
        std::mem::take(&mut self.xss_js_contexts)
    }

    /// Try to admit one more field in the current phase. Returns `false` (and
    /// marks degraded) once `max_fields_per_phase` is reached.
    #[must_use]
    pub const fn try_take_field(&mut self) -> bool {
        if self.fields_used >= self.budget.max_fields_per_phase {
            self.degraded = true;
            return false;
        }
        self.fields_used += 1;
        true
    }

    /// Admit a single field's raw **input** length against the per-field cap
    /// (plan §12.2, codex A-2). This is checked on a borrowed view **before**
    /// any clone / decode / normalise allocation, so an oversized field is
    /// rejected without doing the work. Non-cumulative: it bounds one field's
    /// size, not the request total. Marks degraded and returns `false` when the
    /// field exceeds `max_field_input_bytes`.
    #[must_use]
    pub const fn try_admit_field_input(&mut self, n: usize) -> bool {
        if n > self.budget.max_field_input_bytes {
            self.degraded = true;
            return false;
        }
        true
    }

    /// Try to admit one more AST parse attempt for this request.
    #[must_use]
    pub const fn try_take_ast_attempt(&mut self) -> bool {
        if self.ast_attempts_used >= self.budget.max_ast_attempts_per_request {
            self.degraded = true;
            return false;
        }
        self.ast_attempts_used += 1;
        true
    }

    /// Try to reserve `n` bytes against the total AST input budget.
    #[must_use]
    pub const fn try_take_ast_input_bytes(&mut self, n: usize) -> bool {
        match self.ast_input_bytes_used.checked_add(n) {
            Some(next) if next <= self.budget.max_ast_input_bytes_total => {
                self.ast_input_bytes_used = next;
                true
            }
            _ => {
                self.degraded = true;
                false
            }
        }
    }

    /// Try to admit one more HTML5 fragment-parse attempt for this request
    /// (XSS DOM detector, P-XSS-1). Mirrors [`Self::try_take_ast_attempt`].
    #[must_use]
    pub const fn try_take_html_parse_attempt(&mut self) -> bool {
        if self.html_parse_attempts_used >= self.budget.max_html_parse_attempts_per_request {
            self.degraded = true;
            return false;
        }
        self.html_parse_attempts_used += 1;
        true
    }

    /// Try to reserve `n` bytes against the total HTML-parse input budget.
    #[must_use]
    pub const fn try_take_html_parse_input_bytes(&mut self, n: usize) -> bool {
        match self.html_parse_input_bytes_used.checked_add(n) {
            Some(next) if next <= self.budget.max_html_parse_input_bytes_total => {
                self.html_parse_input_bytes_used = next;
                true
            }
            _ => {
                self.degraded = true;
                false
            }
        }
    }

    /// Try to reserve `n` bytes against the total preprocessor-output budget.
    #[must_use]
    pub const fn try_take_preprocess_bytes(&mut self, n: usize) -> bool {
        match self.preprocess_output_bytes_used.checked_add(n) {
            Some(next) if next <= self.budget.max_preprocess_output_bytes_total => {
                self.preprocess_output_bytes_used = next;
                true
            }
            _ => {
                self.degraded = true;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_budget() -> Budget {
        Budget {
            max_fields_per_phase: 2,
            max_views_per_field: 2,
            max_ast_attempts_per_request: 1,
            max_ast_input_bytes_total: 8,
            max_html_parse_attempts_per_request: 1,
            max_html_parse_input_bytes_total: 8,
            max_tokens_per_view: 4,
            max_list_items: 4,
            max_preprocess_output_bytes_total: 8,
            max_field_input_bytes: 8,
            max_decode_rounds: 2,
        }
    }

    #[test]
    fn field_budget_caps_and_degrades() {
        let mut st = ContentInspectionState::new(tiny_budget());
        assert!(st.try_take_field());
        assert!(st.try_take_field());
        assert!(!st.try_take_field(), "third field must be rejected");
        assert!(st.is_degraded());
    }

    #[test]
    fn field_counter_resets_per_phase_but_degraded_persists() {
        let mut st = ContentInspectionState::new(tiny_budget());
        assert!(st.try_take_field());
        assert!(st.try_take_field());
        assert!(!st.try_take_field());
        assert!(st.is_degraded());
        st.begin_phase();
        // Fields free again in the new phase...
        assert!(st.try_take_field());
        // ...but the request-level degraded flag stays set (honest miss window).
        assert!(st.is_degraded());
    }

    #[test]
    fn byte_budgets_reject_overflow() {
        let mut st = ContentInspectionState::new(tiny_budget());
        assert!(st.try_take_preprocess_bytes(8));
        assert!(!st.try_take_preprocess_bytes(1));
        assert!(st.is_degraded());
    }

    #[test]
    fn field_input_cap_rejects_oversized_field_and_degrades() {
        let mut st = ContentInspectionState::new(tiny_budget());
        // 8-byte cap: an 8-byte field is admitted, a 9-byte one is rejected
        // (before any allocation) and marks the request degraded.
        assert!(st.try_admit_field_input(8));
        assert!(!st.is_degraded());
        assert!(
            !st.try_admit_field_input(9),
            "field over the per-field cap must be rejected"
        );
        assert!(st.is_degraded());
    }

    #[test]
    fn ast_attempt_budget_caps() {
        let mut st = ContentInspectionState::new(tiny_budget());
        assert!(st.try_take_ast_attempt());
        assert!(!st.try_take_ast_attempt());
    }

    #[test]
    fn default_budget_matches_config_defaults() {
        let b = Budget::default();
        assert_eq!(b.max_fields_per_phase, 64);
        assert_eq!(b.max_ast_attempts_per_request, 6);
        assert_eq!(b.max_decode_rounds, 3);
    }
}
