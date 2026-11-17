use serde::{Deserialize, Serialize};
use serde_yaml;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfigYaml {
  pub version: Option<String>,
  pub endpoint: Option<String>,
  pub onboarding_id: Option<String>,
  pub auth_token: Option<String>,
  pub agent_token: Option<String>,
  pub config_path: Option<String>,
  pub wal_path: Option<String>,
}

pub fn load_config() -> anyhow::Result<ConfigYaml> {
  // Start with defaults
  let mut config = ConfigYaml {
    version: Some("v1".to_string()),
    endpoint: None,
    onboarding_id: None,
    auth_token: None,
    agent_token: None,
    config_path: Some("/etc/misbar/config.yaml".to_string()),
    wal_path: Some("/etc/misbar/wal.log".to_string()),
  };

  // Try to load from config file
  let config_path =
    std::env::var("MISBAR_CONFIG_PATH").unwrap_or_else(|_| "/etc/misbar/config.yaml".to_string());

  if let Ok(config_content) = std::fs::read_to_string(&config_path) {
    if let Ok(file_config) = serde_yaml::from_str::<ConfigYaml>(&config_content) {
      // Override defaults with file values
      if file_config.version.is_some() {
        config.version = file_config.version;
      }
      if file_config.endpoint.is_some() {
        config.endpoint = file_config.endpoint;
      }
      if file_config.onboarding_id.is_some() {
        config.onboarding_id = file_config.onboarding_id;
      }
      if file_config.auth_token.is_some() {
        config.auth_token = file_config.auth_token;
      }
      if file_config.agent_token.is_some() {
        config.agent_token = file_config.agent_token;
      }
      if file_config.config_path.is_some() {
        config.config_path = file_config.config_path;
      }
      if file_config.wal_path.is_some() {
        config.wal_path = file_config.wal_path;
      }
    } else {
      return Err(anyhow::anyhow!("couldn't parse yaml config file"));
    }
  } else {
    return Err(anyhow::anyhow!("couldn't find misbar config file"));
  }

  Ok(config)
}
