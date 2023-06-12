//! A collection of GitHub functions not provided by or building on top of the Octocrab library

use std::collections::HashMap;

use anyhow::Result;
use http::{HeaderName, StatusCode};
use log::error;
use octocrab::{Octocrab, OctocrabBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: u64,
    pub login: String,
    pub r#type: String,
}

const NO_PARAMETERS: Option<&()> = None;

/// Get a GitHub user (Account) by username
pub async fn get_user(access_token: &str, username: &str) -> Result<Account> {
    let octocrab = OctocrabBuilder::default()
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

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamRepositoryPermission {
    pub name: String,
    pub full_name: String,
    pub owner: Account,
    pub permissions: HashMap<String, bool>,
}

/// Check a team permission for a GitHub repository
pub async fn check_team_permissions(
    access_token: &str,
    org: &str,
    team_slug: &str,
    owner: &str,
    repo: &str,
) -> Result<TeamRepositoryPermission> {
    let octocrab = OctocrabBuilder::default()
        .personal_token(access_token.to_owned())
        .add_header(
            HeaderName::from_static("accept"),
            "application/vnd.github.v3.repository+json".to_string(),
        )
        .add_header(
            HeaderName::from_static("x-github-api-version"),
            "2022-11-28".to_string(),
        )
        .build()?;

    let route = format!("/orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}");
    match octocrab.get(route, NO_PARAMETERS).await {
        Ok(team_repository_permission) => Ok(team_repository_permission),
        Err(e) => {
            error!("Error: {}", e);
            Err(anyhow::anyhow!(e))
        }
    }
}

/// Check if a user is a repository collaborator.
///
/// See: https://docs.github.com/en/rest/collaborators/collaborators?apiVersion=2022-11-28#check-if-a-user-is-a-repository-collaborator
pub async fn check_if_user_is_repository_collaborator(
    octocrab: &Octocrab,
    owner: &str,
    repo: &str,
    username: &str,
) -> Result<bool> {
    let route = format!("/repos/{owner}/{repo}/collaborators/{username}");
    match octocrab._get(route).await {
        Ok(resp) => Ok(resp.status() == StatusCode::NO_CONTENT),
        Err(e) => {
            error!("Error: {}", e);
            Err(anyhow::anyhow!(e))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRepositoryPermission {
    pub permission: String,
    pub user: Account,
}

/// Get repository permissions for user.
///
/// See: https://docs.github.com/en/rest/collaborators/collaborators?apiVersion=2022-11-28#get-repository-permissions-for-a-user
pub async fn get_repository_permissions_for_user(
    octocrab: &Octocrab,
    owner: &str,
    repo: &str,
    username: &str,
) -> Result<UserRepositoryPermission> {
    let route = format!("/repos/{owner}/{repo}/collaborators/{username}/permission");
    match octocrab.get(route, NO_PARAMETERS).await {
        Ok(user_repository_permission) => Ok(user_repository_permission),
        Err(e) => {
            error!("Error: {}", e);
            Err(anyhow::anyhow!(e))
        }
    }
}

pub enum AddRepositoryCollaboratorResult {
    Ok(String),
    AlreadyExists,
}

/// Add a repository collaborator
///
/// See: https://docs.github.com/en/rest/collaborators/collaborators?apiVersion=2022-11-28#add-a-repository-collaborator
pub async fn add_repository_collaborator(
    octocrab: &Octocrab,
    owner: &str,
    repo: &str,
    username: &str,
    permission: &str,
) -> Result<AddRepositoryCollaboratorResult> {
    let route = format!("/repos/{owner}/{repo}/collaborators/{username}");

    let body = serde_json::json!({ "permission": permission });

    let resp = octocrab._put(route, Some(&body)).await?;

    match resp.status() {
        StatusCode::OK | StatusCode::CREATED => {
            let body = hyper::body::to_bytes(resp.into_body()).await?;
            Ok(AddRepositoryCollaboratorResult::Ok(String::from_utf8(
                body.to_vec(),
            )?))
        }
        StatusCode::NO_CONTENT => Ok(AddRepositoryCollaboratorResult::AlreadyExists),
        _ => {
            Err(anyhow::anyhow!(resp.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn init() {
        env_logger::builder()
            .target(env_logger::Target::Stdout)
            .try_init().unwrap_or_default();
    }

    #[tokio::test]
    #[ignore = "Don't run this test unless you have a valid GitHub token in the GITHUB_TOKEN environment variable"]
    async fn test_github_get_user() {
        init();

        let github_token = env::var("GITHUB_TOKEN").unwrap();

        let account = get_user(&github_token, "aisrael").await.unwrap();
        assert!(account.id == 89215);
    }

    #[tokio::test]
    #[ignore = "Don't run this test unless you have a valid GitHub token in the GITHUB_TOKEN environment variable"]
    async fn test_github_check_team_permission() {
        init();

        let github_token = env::var("GITHUB_TOKEN").unwrap();

        let team_repository_permission = check_team_permissions(
            &github_token,
            "gitsudo-io",
            "a-team",
            "gitsudo-io",
            "test-repo-alpha",
        )
        .await
        .unwrap();

        assert!(team_repository_permission.name == "test-repo-alpha");
        assert!(
            team_repository_permission.permissions
                == HashMap::from([
                    ("admin".to_string(), false),
                    ("maintain".to_string(), true),
                    ("push".to_string(), true),
                    ("triage".to_string(), true),
                    ("pull".to_string(), true)
                ])
        );
    }
}
