//! A collection of GitHub functions not provided by or building on top of the Octocrab library

use std::collections::HashMap;

use anyhow::Result;
use http::{HeaderName, StatusCode};
use log::error;
use octocrab::{
    models::{teams::Team, App, UserId},
    Octocrab, OctocrabBuilder,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: UserId,
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
            error!("{}", e);
            Err(anyhow::anyhow!(e))
        }
    }
}

/// A struct that can be used to partially deserialize the response from the check_team_permissions() GitHub
/// API call.
///
/// See: https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#check-team-permissions-for-a-repository
#[derive(Debug, Serialize, Deserialize)]
pub struct TeamRepositoryPermission {
    pub name: String,
    pub full_name: String,
    pub owner: Account,
    pub permissions: HashMap<String, bool>,
}

/// Check a team permission for a GitHub repository
///
/// See: https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#check-team-permissions-for-a-repository
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

/// A struct that can be used to partially deserialize the response from the get_repository_permissions_for_user()
/// GitHub API call.
///
/// See: https://docs.github.com/en/rest/collaborators/collaborators?apiVersion=2022-11-28#get-repository-permissions-for-a-user
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

/// A simple enum to hold the results of the add_repository_collaborator() call. Can either be:
///
/// * Ok(String) - The username was added to the repository, and the String is the JSON response from GitHub
/// * AlreadyExists - The username was already a collaborator on the repository, and we received an empty response body
///
/// See: https://docs.github.com/en/rest/collaborators/collaborators?apiVersion=2022-11-28#add-a-repository-collaborator
#[derive(Debug)]
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
        _ => Err(anyhow::anyhow!(resp.status())),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepositoryBranchProtection {
    pub name: Option<String>,
    pub required_status_checks: Option<RequiredStatusChecks>,
    pub enforce_admins: Option<EnforceAdmins>,
    pub required_pull_request_reviews: Option<RequiredPullRequestReviews>,
    pub restrictions: Option<Restrictions>,
    pub required_linear_history: Option<RequiredLinearHistory>,
    pub required_signatures: Option<RequiredSignatures>,
}

impl RepositoryBranchProtection {
    pub fn new() -> RepositoryBranchProtection {
        RepositoryBranchProtection {
            name: None,
            required_status_checks: None,
            enforce_admins: None,
            required_pull_request_reviews: None,
            restrictions: None,
            required_linear_history: None,
            required_signatures: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredStatusChecks {
    pub strict: bool,
    pub contexts: Vec<String>,
    pub enforcement_level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnforceAdmins {
    pub enabled: bool,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredPullRequestReviews {
    pub dismiss_stale_reviews: bool,
    pub require_code_owner_reviews: bool,
    pub required_approving_review_count: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Restrictions {
    pub users: Vec<Account>,
    pub teams: Vec<Team>,
    pub apps: Vec<App>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredLinearHistory {
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredSignatures {
    pub enabled: bool,
    pub url: String,
}

/// Get branch protection
///
/// See: https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28#get-branch-protection
#[allow(dead_code)]
pub async fn get_branch_protection(
    octocrab: &Octocrab,
    owner: &str,
    repo: &str,
    branch: &str,
) -> Result<RepositoryBranchProtection> {
    let route = format!("/repos/{owner}/{repo}/branches/{branch}/protection");
    match octocrab.get(route, NO_PARAMETERS).await {
        Ok(repository_branch_protection) => Ok(repository_branch_protection),
        Err(e) => {
            error!("Error: {}", e);
            Err(anyhow::anyhow!(e))
        }
    }
}

/// Update branch protection
///
/// See: https://docs.github.com/en/rest/branches/branch-protection?apiVersion=2022-11-28#update-branch-protection
pub async fn update_branch_protection(
    octocrab: &Octocrab,
    owner: &str,
    repo: &str,
    branch: &str,
    repository_branch_protection: &RepositoryBranchProtection,
) -> Result<RepositoryBranchProtection> {
    let route = format!("/repos/{owner}/{repo}/branches/{branch}/protection");
    match octocrab
        .put(route, Some(repository_branch_protection))
        .await
    {
        Ok(repository_branch_protection) => Ok(repository_branch_protection),
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

    fn init() {
        env_logger::builder()
            .target(env_logger::Target::Stdout)
            .try_init()
            .unwrap_or_default();
    }

    #[tokio::test]
    #[ignore = "Don't run this test unless you have a valid GitHub token in the GITHUB_TOKEN environment variable"]
    async fn test_github_get_user() {
        init();

        let github_token = env::var("GITHUB_TOKEN").unwrap();

        let account = get_user(&github_token, "aisrael").await.unwrap();
        assert!(account.id == UserId::from(89215));
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

    #[tokio::test]
    #[ignore = "Don't run this test unless you have a valid GitHub token in the GITHUB_TOKEN environment variable"]
    async fn test_github_get_branch_protection() {
        init();

        let github_token = env::var("GITHUB_TOKEN").unwrap();
        let octocrab = OctocrabBuilder::default()
            .personal_token(github_token)
            .build()
            .unwrap();

        let owner = "gitsudo-io";
        let repo = "gitsudo";
        let branch = "main";

        let before = get_branch_protection(&octocrab, owner, repo, branch).await;

        if before.is_err() {
            let e = before.unwrap_err();
            assert!(e.to_string().starts_with("GitHub: Branch not protected\n"));
        }

        let required_status_checks = RequiredStatusChecks {
            strict: true,
            contexts: vec!["mix-test".to_owned()],
            enforcement_level: None,
        };

        let repository_branch_protection = RepositoryBranchProtection {
            name: Some(branch.to_owned()),
            required_status_checks: Some(required_status_checks),
            enforce_admins: None,
            required_pull_request_reviews: None,
            restrictions: None,
            required_linear_history: None,
            required_signatures: None,
        };

        let result = update_branch_protection(
            &octocrab,
            &owner,
            &repo,
            &branch,
            &repository_branch_protection,
        )
        .await;

        assert!(result.is_ok());
        println!("{:?}", result);
    }
}
