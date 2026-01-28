use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use regex::Regex;
use serde::Deserialize;
use crate::WafConfig;

#[derive(Debug, Deserialize)]
pub struct RulesFile {
    pub version: u32,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub description: Option<String>,
    pub enabled: bool,

    #[serde(rename = "type")]
    pub rule_type: RuleType,

    pub values: Vec<String>,
    pub action: RuleAction,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    PathContains,
    PathPrefix,
    Regex,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Allow,
}

#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub(crate) id: String,
    pub(crate) rule_type: RuleType,
    pub(crate) values: Vec<String>,
    pub(crate) regexes: Vec<Regex>,
    pub(crate) action: RuleAction,
}

#[derive(Debug)]
pub(crate) struct RulesCache {
    pub(crate) rules: Vec<CompiledRule>,
    pub(crate) loaded_at: SystemTime,
    pub(crate) path: String,
}

static RULES: OnceLock<Mutex<Option<RulesCache>>> = OnceLock::new();

pub(crate) fn rules_mutex() -> &'static Mutex<Option<RulesCache>> {
    RULES.get_or_init(|| Mutex::new(None))
}

fn load_rules_from_path(path: &str) -> Result<Vec<CompiledRule>, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("read rules failed: {e}"))?;
    let rf: RulesFile = serde_json::from_str(&data).map_err(|e| format!("parse rules failed: {e}"))?;

    let mut out = Vec::new();
    for r in rf.rules.into_iter().filter(|r| r.enabled) {
        let regexes = if matches!(r.rule_type, RuleType::Regex) {
            let mut compiled = Vec::new();
            for pat in &r.values {
                if let Ok(re) = Regex::new(pat) {
                    compiled.push(re);
                }
            }
            compiled
        } else {
            Vec::new()
        };

        out.push(CompiledRule {
            id: r.id,
            rule_type: r.rule_type,
            values: r.values,
            regexes,
            action: r.action,
        });
    }

    Ok(out)
}

pub(crate) fn ensure_rules_loaded(cfg: &WafConfig) -> Result<(), String> {
    let path = match &cfg.rules_path {
        Some(p) => p.clone(),
        None => return Ok(()),
    };

    let reload_every = cfg.rules_reload_seconds.map(Duration::from_secs);

    let mut guard = rules_mutex().lock().map_err(|_| "rules mutex poisoned".to_string())?;

    let must_load = match &*guard {
        None => true,
        Some(cache) => {
            if cache.path != path {
                true
            } else if let Some(dur) = reload_every {
                match SystemTime::now().duration_since(cache.loaded_at) {
                    Ok(elapsed) => elapsed >= dur,
                    Err(_) => true,
                }
            } else {
                false
            }
        }
    };

    if !must_load {
        return Ok(());
    }

    let rules = load_rules_from_path(&path)?;
    *guard = Some(RulesCache {
        rules,
        loaded_at: SystemTime::now(),
        path,
    });
    Ok(())
}