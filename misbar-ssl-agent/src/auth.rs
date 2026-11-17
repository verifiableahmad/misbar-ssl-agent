use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentTokenResponse {
  pub agent_uuid: Option<String>,
  pub agent_token: Option<String>,
}

#[derive(Serialize)]
struct AuthData<'a> {
  id: &'a str,
  auth_token: &'a str,
}
