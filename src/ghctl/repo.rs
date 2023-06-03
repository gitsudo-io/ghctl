use anyhow::Result;
use http::{HeaderName, StatusCode};
use log::{debug, error, info};
use octocrab::models::Repository;
use octocrab::params::teams::Permission;
use octocrab::OctocrabBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::utils::split_some_repo_full_name;

/// A struct that represents the ghctl configuration for a GitHub repository
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    pub teams: Option<HashMap<String, String>>,
    pub collaborators: Option<HashMap<String, String>>,
}

pub async fn get_repo(
    access_token: &String,
    owner: impl Into<String>,
    repo_name: impl Into<String>,
) -> Result<Repository> {
    let octocrab = OctocrabBuilder::default()
        .personal_token(access_token.clone())
        .build()?;

    let repository = octocrab.repos(owner, repo_name).get().await?;
    Ok(repository)
}

pub async fn config_environments_list(context: &crate::ghctl::Context, repo_name: &String) {
    do_config_environments_list(context, repo_name)
        .await
        .unwrap();
}

async fn do_config_environments_list(
    context: &crate::ghctl::Context,
    repo_name: &String,
) -> Result<()> {
    let (owner, repo) = split_some_repo_full_name(repo_name)?;

    let octocrab = OctocrabBuilder::default()
        .personal_token(context.access_token.clone())
        .add_header(
            HeaderName::from_static("accept"),
            "application/vnd.github+json".to_string(),
        )
        .add_header(
            HeaderName::from_static("x-github-api-version"),
            "2022-11-28".to_string(),
        )
        .build()?;

    let none: Option<&()> = None;
    let result: Result<serde_json::Value, octocrab::Error> = octocrab
        .get(format!("/repos/{owner}/{repo}/environments"), none)
        .await;

    match result {
        Ok(body) => {
            println!("{}", body);
        }
        Err(e) => error!("Error: {}", e),
    }

    Ok(())
}

pub async fn config_environments_get(
    context: &crate::ghctl::Context,
    repo_name: &String,
    environment_name: &String,
) {
    do_config_environments_get(context, repo_name, environment_name)
        .await
        .unwrap();
}

async fn do_config_environments_get(context: &crate::ghctl::Context, repo_name: &String, environment_name: &String) -> Result<()> {
    let (owner, repo) = split_some_repo_full_name(repo_name)?;

    let octocrab = OctocrabBuilder::default()
        .personal_token(context.access_token.clone())
        .add_header(
            HeaderName::from_static("accept"),
            "application/vnd.github+json".to_string(),
        )
        .add_header(
            HeaderName::from_static("x-github-api-version"),
            "2022-11-28".to_string(),
        )
        .build()?;

    let none: Option<&()> = None;
    let result: Result<serde_json::Value, octocrab::Error> = octocrab
        .get(format!("/repos/{owner}/{repo}/environments/{environment_name}", environment_name=environment_name), none)
        .await;

    match result {
        Ok(body) => {
            println!("{}", body);
        }
        Err(e) => error!("Error: {}", e),
    }

    Ok(())
}

pub async fn get_repo_config(
    _context: &crate::ghctl::Context,
    repo_full_name: &String,
) -> Result<()> {
    info!("Getting configuration for {}", repo_full_name);

    Ok(())
}

pub async fn config_apply(
    access_token: &String,
    owner: impl Into<String>,
    repo: impl Into<String>,
    config_files: &Vec<String>,
) -> Result<()> {
    let owner = owner.into();
    let repo = repo.into();
    debug!("Applying configuration to {owner}/{repo}");

    if config_files.len() == 0 {
        error!("No configuration files specified! Please specify one or more configuration files with -F/--config-file");
        return Ok(());
    }

    let merged_config =
        config_files
            .iter()
            .try_fold(RepoConfig::new(), |config, config_file| {
                debug!("Reading configuration file {config_file}");
                match std::fs::File::open(config_file) {
                    Ok(f) => match serde_yaml::from_reader(f) {
                        Ok(repo_config) => Ok(merge_config(config, repo_config)),
                        Err(e) => {
                            error!("Error deserializing configuration file {config_file}: {e}");
                            Err(anyhow::anyhow!(e))
                        }
                    },
                    Err(e) => {
                        error!("Error reading configuration file {config_file}: {e}");
                        Err(anyhow::anyhow!(e))
                    }
                }
            })?;

    debug!("Applying merged configuration: {:?}", merged_config);

    match merged_config
        .apply(access_token.clone(), &owner, &repo)
        .await
    {
        Ok(_) => {
            debug!("Applied configuration to {owner}/{repo}");
        }
        Err(e) => {
            error!("Error applying configuration to {owner}/{repo}: {e}");
            return Err(anyhow::anyhow!(e));
        }
    };

    Ok(())
}

fn merge_config(first: RepoConfig, second: RepoConfig) -> RepoConfig {
    RepoConfig {
        teams: Some(merge_option_hashmap(first.teams, second.teams)),
        collaborators: Some(merge_option_hashmap(
            first.collaborators,
            second.collaborators,
        )),
    }
}

fn merge_option_hashmap<K, V>(
    map1: Option<HashMap<K, V>>,
    map2: Option<HashMap<K, V>>,
) -> HashMap<K, V>
where
    K: std::cmp::Eq + std::hash::Hash,
{
    if let Some(map1) = map1 {
        if let Some(map2) = map2 {
            map1.into_iter().chain(map2.into_iter()).collect()
        } else {
            map1
        }
    } else {
        if let Some(map2) = map2 {
            map2
        } else {
            HashMap::new()
        }
    }
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
        owner: &String,
        repo_name: &String,
    ) -> anyhow::Result<()> {
        debug!("Applying configuration");
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
    repo: &String,
    team_permissions: &HashMap<String, String>,
) -> anyhow::Result<()> {
    debug!("Applying teams");
    for (team_slug, permission_s) in team_permissions {
        let permission = permission_from_s(permission_s).unwrap();

        match octocrab
            .teams(owner)
            .repos(team_slug)
            .add_or_update(owner, repo, permission)
            .await
        {
            Ok(_) => {
                info!(
                    "Added team {team_slug} with permission {:?} to repository {owner}/{repo}",
                    permission
                );
            }
            Err(e) => {
                error!(
                    "Error adding team {team_slug} with permission {:?} to repository {owner}/{repo}: {:?}",
                    permission, e
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
    debug!("Applying collaborators");

    for (username, permission_s) in collaborator_permissions {
        let permission = permission_from_s(permission_s).unwrap();
        let value = permission_to_s(&permission);
        let route = format!("/repos/{owner}/{repo}/collaborators/{username}");

        let body = serde_json::json!({ "permission": value });

        let result = octocrab._put(route, Some(&body)).await;

        match result {
            Ok(resp) => match resp.status() {
                StatusCode::OK | StatusCode::CREATED => {
                    info!(
                            "Added collaborator {username} with permission {value} to repository {owner}/{repo}"
                        );
                    let body = hyper::body::to_bytes(resp.into_body()).await?;
                    println!("{}", String::from_utf8(body.to_vec())?);
                }
                StatusCode::NO_CONTENT => {
                    info!(
                            "Updated collaborator {username} with permission {value} to repository {owner}/{repo}"
                        );
                }
                _ => {
                    error!(
                            "Error updating collaborator {username} with permission {value} to repository {owner}/{repo}: {}", resp.status()
                        );
                    return Err(anyhow::anyhow!(resp.status()));
                }
            },
            Err(e) => {
                error!(
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

    /// We ignore this test for now as it requires a TEST_PERSONAL_ACCESS_TOKEN and
    /// performs actual GitHub API calls, until we can add some VCR-like HTTP recording
    /// in the future.
    ///
    /// To run ignored tests locally, use `cargo test -- --ignored`
    #[tokio::test]
    #[ignore]
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
                &"gitsudo-io".to_string(),
                &"test-repo-alpha".to_string(),
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
