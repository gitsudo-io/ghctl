use anyhow::Result;
use http::HeaderName;
use octocrab::models::Repository;
use octocrab::params::teams::Permission;
use octocrab::OctocrabBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;


/// A struct that represents the ghctl configuration for a GitHub repository
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    pub teams: Option<HashMap<String, String>>,
    pub collaborators: Option<HashMap<String, String>>,
}

pub async fn get_repo(access_token: &String, owner: &str, repo_name: &str) -> Result<Repository> {
    let octocrab = OctocrabBuilder::default()
        .personal_token(access_token.clone())
        .build()?;

    let repository = octocrab.repos(owner, repo_name).get().await?;
    Ok(repository)
}

pub async fn get_repo_config(
    _context: &crate::ghctl::Context,
    repo_full_name: &String,
) -> Result<()> {
    println!("Getting configuration for {}", repo_full_name);

    Ok(())
}

fn permission_from_s(s: &String) -> Option<Permission> {
    match s.as_str() {
        "pull" => Some(Permission::Pull),
        "triage" => Some(Permission::Triage),
        "push" => Some(Permission::Push),
        "maintain" => Some(Permission::Maintain),
        "admin" => Some(Permission::Admin),
        _ => None,
    }
}

fn permission_to_s(permission: &Permission) -> &str {
    match permission {
        Permission::Pull => "pull",
        Permission::Triage => "triage",
        Permission::Push => "push",
        Permission::Maintain => "maintain",
        Permission::Admin => "admin",
        _ => "",
    }
}

impl RepoConfig {
    pub fn new() -> RepoConfig {
        RepoConfig {
            teams: Some(HashMap::new()),
            collaborators: Some(HashMap::new()),
        }
    }

    pub async fn apply(
        &self,
        access_token: String,
        owner: String,
        repo_name: String,
    ) -> anyhow::Result<()> {
        println!("Applying configuration");
        let octocrab = OctocrabBuilder::default()
            .personal_token(access_token.clone())
            .build()?;

        if let Some(team_permissions) = &self.teams {
            apply_teams(&octocrab, &owner, &repo_name, team_permissions).await?;
        }

        let octocrab = OctocrabBuilder::default()
            .personal_token(access_token)
            .add_header(
                HeaderName::from_static("accept"),
                "application/vnd.github+json".to_string(),
            )
            .add_header(
                HeaderName::from_static("x-github-api-version"),
                "2022-11-28".to_string(),
            )
            .build()?;
        if let Some(collaborator_permissions) = &self.collaborators {
            apply_collaborators(&octocrab, &owner, &repo_name, collaborator_permissions).await?;
        }
        Ok(())
    }
}

async fn apply_teams(
    octocrab: &octocrab::Octocrab,
    owner: &String,
    repo_name: &String,
    team_permissions: &HashMap<String, String>,
) -> anyhow::Result<()> {
    println!("Applying teams");
    for (team_slug, permission_s) in team_permissions {
        let permission = permission_from_s(permission_s).unwrap();

        match octocrab
            .teams(owner)
            .repos(team_slug)
            .add_or_update(owner, repo_name, permission)
            .await
        {
            Ok(_) => {
                println!(
                    "Added team {} with permission {:?} to repository {}/{}",
                    team_slug, permission, owner, repo_name
                );
            }
            Err(e) => {
                println!(
                    "Error adding team {} with permission {:?} to repository {}/{}: {}",
                    team_slug, permission, owner, repo_name, e
                );
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryInvitation {
    pub id: u64,
    pub node_id: String,
    pub repository: Option<HashMap<String, serde_json::Value>>,
    pub invitee: Option<HashMap<String, serde_json::Value>>,
    pub inviter: Option<HashMap<String, serde_json::Value>>,
    pub permissions: String,
    pub created_at: String,
    pub url: String,
    pub html_url: String,
}

async fn apply_collaborators(
    octocrab: &octocrab::Octocrab,
    owner: &String,
    repo: &String,
    collaborator_permissions: &HashMap<String, String>,
) -> anyhow::Result<()> {
    println!("Applying collaborators");

    for (username, permission_s) in collaborator_permissions {
        let permission = permission_from_s(permission_s).unwrap();
        let value = permission_to_s(&permission);
        let route = format!("/repos/{owner}/{repo}/collaborators/{username}");
        println!("route: {route}");
        let body = serde_json::json!({ "permission": value });

        let result = octocrab._put(route, Some(&body)).await;

        match result {
            Ok(resp) => {
                println!(
                    "Added collaborator {username} with permission {value} to repository {owner}/{repo}"
                );
                println!("Response: {}", resp.status());
                println!("Response: {:?}", resp.body());
            }
            Err(e) => {
                println!(
                    "Error adding collaborator {username} with permission {value} to repository {owner}/{repo}: {e}"
                );
                return Err(e.into());
            }
        }
    }

    Ok(())
}

impl Default for RepoConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::http::header::HeaderName;
    use octocrab::OctocrabBuilder;
    use std::env;

    #[tokio::test]
    async fn test_repo_config() -> Result<(), Box<dyn std::error::Error>> {
        let repo_config = serde_yaml::from_str::<super::RepoConfig>(
            r#"
            teams:
                a-team: maintain
            collaborators:
                aisrael: admin
            "#,
        )
        .unwrap();
        println!("repo_config: {:?}", repo_config);

        let test_token = env::var("TEST_PERSONAL_ACCESS_TOKEN").unwrap();

        () = repo_config
            .apply(
                test_token.clone(),
                "gitsudo-io".to_string(),
                "test-repo-alpha".to_string(),
            )
            .await?;

        let octocrab = OctocrabBuilder::default()
            .personal_token(test_token)
            .add_header(
                HeaderName::from_static("accept"),
                "application/vnd.github.v3.repository+json".to_string(),
            )
            .build()
            .unwrap();
        let repo = octocrab
            .teams("gitsudo-io")
            .repos("a-team")
            .check_manages("gitsudo-io", "test-repo-alpha")
            .await?
            .unwrap();
        println!("{:?}", repo.permissions);
        assert!(repo.permissions.unwrap().maintain);
        Ok(())
    }
}
