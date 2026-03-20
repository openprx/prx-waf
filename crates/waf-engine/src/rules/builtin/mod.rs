//! Built-in rules compiled into the binary.

pub mod bot;
pub mod owasp;
pub mod scanner;

use super::registry::Rule;

/// Load all built-in rules into a combined list.
pub fn all_builtin_rules(enable_owasp: bool, enable_bot: bool, enable_scanner: bool) -> Vec<Rule> {
    let mut rules = Vec::new();
    if enable_owasp {
        rules.extend(owasp::rules());
    }
    if enable_bot {
        rules.extend(bot::rules());
    }
    if enable_scanner {
        rules.extend(scanner::rules());
    }
    rules
}
