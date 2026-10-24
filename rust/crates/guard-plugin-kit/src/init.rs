//! `hol-guard plugin init`: a Kit config for an existing plugin, or a minimal
//! Claude Code plugin with one skill in an empty folder. Never overwrites.

use std::path::Path;

use serde_json::{json, Value};

use crate::check::is_kebab;
use crate::detect::Detection;
use crate::emit::{self, Output, Runtime};

pub const CONFIG_FILE: &str = "hol.json";
pub const CONFIG_SCHEMA: &str = "hol.plugin-kit.config.v1";
pub const DEFAULT_OUT_DIR: &str = "dist/hol-plugin";

pub fn plan(root: &Path, detection: &Detection, name: Option<&str>) -> Result<Vec<Output>, String> {
    let mut outputs = Vec::new();
    let runtimes: Vec<&str> = if detection.sources.is_empty() {
        let name = name.ok_or("plugin_kit_init_needs_name")?;
        if !is_kebab(name) || name.len() > 64 {
            return Err("plugin_kit_init_name_invalid".to_owned());
        }
        scaffold(name, &mut outputs);
        vec!["claude-code", "codex", "agent-skills"]
    } else {
        Runtime::ALL
            .into_iter()
            .filter(|runtime| emit::supports(*runtime, &detection.plugin))
            .map(Runtime::id)
            .collect()
    };
    outputs.push(Output {
        path: CONFIG_FILE.to_owned(),
        content: emit::json_bytes(&json!({
            "schema": CONFIG_SCHEMA,
            "out": DEFAULT_OUT_DIR,
            "runtimes": runtimes,
        })),
    });
    for output in &outputs {
        if std::fs::symlink_metadata(root.join(&output.path)).is_ok() {
            return Err("plugin_kit_init_would_overwrite".to_owned());
        }
    }
    Ok(outputs)
}

fn scaffold(name: &str, outputs: &mut Vec<Output>) {
    let description = format!("Describe what {name} does in one sentence.");
    let plugin: Value = json!({
        "name": name,
        "version": "0.1.0",
        "description": description,
        "license": "MIT",
    });
    outputs.push(Output {
        path: ".claude-plugin/plugin.json".to_owned(),
        content: emit::json_bytes(&plugin),
    });
    outputs.push(Output {
        path: ".claude-plugin/marketplace.json".to_owned(),
        content: emit::json_bytes(&json!({
            "name": name,
            "owner": {"name": name},
            "plugins": [{"name": name, "source": "./", "description": description}],
        })),
    });
    outputs.push(Output {
        path: format!("skills/{name}/SKILL.md"),
        content: format!(
            "---\nname: {name}\ndescription: Use when the user asks for {name}. Replace this with when the agent should load the skill.\n---\n\n# {name}\n\nWrite the instructions the agent follows here.\n"
        )
        .into_bytes(),
    });
}

/// Writes `outputs` under `out`. Every directory below `out` is created
/// fresh or must already be a real directory, and no existing symlink is
/// written through.
pub fn write(out: &Path, outputs: &[Output]) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(out).map_err(|_| "plugin_kit_output_unwritable")?;
    let mut written = Vec::new();
    for output in outputs {
        let relative = Path::new(&output.path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err("plugin_kit_output_path_invalid".to_owned());
        }
        let mut directory = out.to_path_buf();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                directory.push(component);
                match std::fs::symlink_metadata(&directory) {
                    Ok(metadata) if metadata.is_dir() => {}
                    Ok(_) => return Err("plugin_kit_output_path_blocked".to_owned()),
                    Err(_) => std::fs::create_dir(&directory)
                        .map_err(|_| "plugin_kit_output_unwritable")?,
                }
            }
        }
        let target = out.join(relative);
        if let Ok(metadata) = std::fs::symlink_metadata(&target) {
            if !metadata.is_file() {
                return Err("plugin_kit_output_path_blocked".to_owned());
            }
        }
        std::fs::write(&target, &output.content).map_err(|_| "plugin_kit_output_unwritable")?;
        written.push(output.path.clone());
    }
    Ok(written)
}
