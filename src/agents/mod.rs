mod openclaw;

use crate::types::AgentPlugin;

pub fn all_plugins() -> Vec<Box<dyn AgentPlugin>> {
    vec![Box::new(openclaw::OpenClawPlugin)]
}
