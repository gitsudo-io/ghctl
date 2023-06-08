//! A collection of GitHub functions not provided by or building on top of the Octocrab library

use anyhow::Result;
use log::error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: u64,
    pub login: String,
    pub r#type: String,
}

const NO_PARAMETERS: Option<&()> = None;

pub async fn get_user(access_token: &str, username: &str) -> Result<Account> {
    let octocrab = octocrab::OctocrabBuilder::default()
        .personal_token(access_token.to_owned())
        .build()?;

    let route = format!("/users/{username}");

    let result: Result<Account, octocrab::Error> = octocrab.get(route, NO_PARAMETERS).await;

    match result {
        Ok(account) => Ok(account),
        Err(e) => {
            error!("Error: {}", e);
            Err(anyhow::anyhow!(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    #[ignore = "Don't run this test unless you have a valid GitHub token in the GITHUB_TOKEN environment variable"]
    async fn test_get_user() {
        env_logger::builder()
            .target(env_logger::Target::Stdout)
            .init();

        let github_token = env::var("GITHUB_TOKEN").unwrap();

        let account = get_user(&github_token, "aisrael").await.unwrap();
        assert!(account.id == 89215);
    }
}
