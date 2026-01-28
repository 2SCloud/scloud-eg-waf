mod rules;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::rules::{RuleAction, RuleType};

static LAST_REASON: OnceLock<Mutex<String>> = OnceLock::new();

fn reason_mutex() -> &'static Mutex<String> {
    LAST_REASON.get_or_init(|| Mutex::new(String::new()))
}

pub fn set_last_reason(s: &str) {
    if let Ok(mut g) = reason_mutex().lock() {
        g.clear();
        g.push_str(s);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn last_reason() -> u64 {
    let s = match reason_mutex().lock() {
        Ok(g) => g.clone(),
        Err(_) => String::new(),
    };

    let bytes = s.as_bytes();

    let mut buf = Vec::<u8>::with_capacity(bytes.len());
    buf.extend_from_slice(bytes);

    let ptr = buf.as_mut_ptr() as u32;
    let len = buf.len() as u32;

    std::mem::forget(buf);

    ((ptr as u64) << 32) | (len as u64)
}

#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: i32) -> i32 {
    let mut buf = Vec::<u8>::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn dealloc(ptr: i32, len: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize);
    }
}

fn read_bytes(ptr: i32, len: i32) -> &'static [u8] {
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) }
}

const RC_ALLOW: i32 = 0;
const RC_BLOCK: i32 = 1;
const RC_ERROR: i32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub path: String,

    #[serde(default)]
    pub raw_path: String,

    pub method: String,

    #[serde(default)]
    pub host: String,

    #[serde(default)]
    pub scheme: String,

    #[serde(default)]
    pub ip: String,

    #[serde(default)]
    pub remote_addr: String,

    #[serde(default)]
    pub user_agent: String,

    #[serde(default)]
    pub referer: String,

    #[serde(default)]
    pub headers: HashMap<String, Vec<String>>,

    #[serde(default)]
    pub query: HashMap<String, Vec<String>>,
}

// inline: { "config": {...}, "request": {...} }
#[derive(Debug, Serialize, Deserialize)]
pub struct InlinePayload {
    pub config: WafConfig,
    pub request: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    #[serde(default = "default_mode")]
    pub mode: String, // "block" | "log" | "disabled"

    #[serde(default)]
    pub log: bool,

    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,

    #[serde(default)]
    pub normalize_path: bool,

    #[serde(default)]
    pub rules_path: Option<String>,

    #[serde(default)]
    pub rules_reload_seconds: Option<u64>,
}

fn default_mode() -> String {
    "block".into()
}

fn default_allowed_methods() -> Vec<String> {
    ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

// static configuration if 'config_mode' = 'init'
static CONFIG: OnceLock<WafConfig> = OnceLock::new();

// ======================
// WAF logic
// ======================

fn normalize_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut prev_slash = false;
    for ch in p.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            out.push(ch);
        }
    }
    if out.is_empty() { "/".into() } else { out }
}

fn method_allowed(req: &Request, cfg: &WafConfig) -> bool {
    cfg.allowed_methods.iter().any(|m| m == &req.method)
}

fn build_haystack(req: &Request, path: &str) -> String {
    let mut s = String::new();
    s.push_str(path);
    s.push(' ');
    s.push_str((&req.user_agent).as_ref());
    s.push(' ');

    for (k, vs) in &req.query {
        s.push_str(k.as_ref());
        s.push('=');
        for v in vs {
            s.push_str(v.as_ref());
            s.push('&');
        }
        s.push(' ');
    }
    s
}

fn apply_rules(req: &Request, path: &str, cfg: &WafConfig) -> Option<(RuleAction, String)> {
    if let Err(_e) = rules::ensure_rules_loaded(cfg) {
        return None;
    }

    let guard = rules::rules_mutex().lock().ok()?;
    let cache = guard.as_ref()?;
    let hay = build_haystack(req, path);

    for r in &cache.rules {
        let matched = match r.rule_type {
            RuleType::PathContains => r.values.iter().any(|v| path.contains(v)),
            RuleType::PathPrefix => r.values.iter().any(|v| path.starts_with(v)),
            RuleType::Regex => r.regexes.iter().any(|re| re.is_match(&hay)),
        };

        if matched {
            return Some((r.action.clone(), r.id.clone()));
        }
    }
    None
}

fn should_block(req: &Request, cfg: &WafConfig) -> bool {
    if cfg.mode == "disabled" {
        set_last_reason("");
        return false;
    }

    if !method_allowed(req, cfg) {
        set_last_reason("method-not-allowed");
        return cfg.mode == "block";
    }

    let path = if cfg.normalize_path {
        normalize_path((&req.path).as_ref())
    } else {
        req.path.clone()
    };

    if let Some((action, rule_id)) = apply_rules(req, &path, cfg) {
        match action {
            RuleAction::Block => {
                set_last_reason(&rule_id);
                return cfg.mode == "block";
            }
            RuleAction::Allow => {
                set_last_reason(&rule_id);
                return false;
            }
        }
    }

    set_last_reason("");
    false
}

// ======================
// Exports: init / handle
// ======================

#[unsafe(no_mangle)]
pub extern "C" fn init(ptr: i32, len: i32) -> i32 {
    let bytes = read_bytes(ptr, len);
    let cfg: WafConfig = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return RC_ERROR,
    };

    // load rules if rules file is provided
    if cfg.rules_path.is_some() {
        if let Err(_e) = rules::ensure_rules_loaded(&cfg) {
            return RC_ERROR;
        }
    }

    let _ = CONFIG.set(cfg);
    RC_ALLOW
}

#[unsafe(no_mangle)]
pub extern "C" fn handle(ptr: i32, len: i32) -> i32 {
    let bytes = read_bytes(ptr, len);

    // inline payload
    if let Ok(payload) = serde_json::from_slice::<InlinePayload>(bytes) {
        return if should_block(&payload.request, &payload.config) {
            RC_BLOCK
        } else {
            RC_ALLOW
        };
    }

    // init-mode payload: request only
    let req: Request = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return RC_ERROR,
    };

    let cfg = CONFIG.get().cloned().unwrap_or_else(|| WafConfig {
        mode: default_mode(),
        log: false,
        allowed_methods: default_allowed_methods(),
        normalize_path: true,
        rules_path: None,
        rules_reload_seconds: None,
    });

    if should_block(&req, &cfg) {
        RC_BLOCK
    } else {
        RC_ALLOW
    }
}
