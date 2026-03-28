use anyhow::Result;
use serde_json::Value;
use std::path::Path;

/// Parse openclaw.json (JSON5 format) from the base directory.
/// Returns an empty object if the file doesn't exist.
pub fn read_config(base_path: &Path) -> Result<Value> {
    let config_path = base_path.join("openclaw.json");

    if !config_path.exists() {
        return Ok(Value::Object(serde_json::Map::new()));
    }

    let raw = std::fs::read_to_string(&config_path)?;

    // Try JSON5 first, fall back to strict JSON
    let value: Value = json5::from_str(&raw)
        .or_else(|_| serde_json::from_str(&raw))?;

    Ok(value)
}

/// Traverse a config value using a dot-separated path (e.g. "gateway.auth.mode").
pub fn get<'a>(config: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = config;
    for key in path.split('.') {
        current = current.get(key)?;
    }
    Some(current)
}

pub fn get_str<'a>(config: &'a Value, path: &str) -> Option<&'a str> {
    get(config, path)?.as_str()
}

pub fn get_bool(config: &Value, path: &str) -> Option<bool> {
    get(config, path)?.as_bool()
}

pub fn get_array<'a>(config: &'a Value, path: &str) -> Option<&'a Vec<Value>> {
    get(config, path)?.as_array()
}
