use anyhow::Result;
use http::{HeaderName, StatusCode};
use log::{debug, error, info};
use octocrab::models::Repository;
use octocrab::params::teams::Permission;
use octocrab::OctocrabBuilder;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, hash::Hash};

use crate::utils::split_some_repo_full_name;

/// A struct that represents the ghctl configuration for a GitHub repository
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    pub teams: Option<HashMap<String, String>>,
    pub collaborators: Option<HashMap<String, String>>,
    pub environments: Option<HashMap<String, RepoEnvironment>>,    
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoEnvironment {
    reviewers: Option<Vec<String>>,
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

async fn do_config_environments_get(
    context: &crate::ghctl::Context,
    repo_name: &String,
    environment_name: &String,
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
        .get(
            format!(
                "/repos/{owner}/{repo}/environments/{environment_name}",
                environment_name = environment_name
            ),
            none,
        )
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
        teams: merge_option_hashmap(first.teams, second.teams),
        collaborators: merge_option_hashmap(first.collaborators, second.collaborators),
        environments: merge_environments(first.environments, second.environments),
    }
}

fn merge_option_hashmap<K, V>(
    map1: Option<HashMap<K, V>>,
    map2: Option<HashMap<K, V>>,
) -> Option<HashMap<K, V>>
where
    K: std::cmp::Eq + std::hash::Hash,
{
    if let Some(map1) = map1 {
        if let Some(map2) = map2 {
            Some(map1.into_iter().chain(map2.into_iter()).collect())
        } else {
            Some(map1)
        }
    } else {
        if let Some(map2) = map2 {
            Some(map2)
        } else {
            None
        }
    }
}

fn merge_environments(
    first: Option<HashMap<String, RepoEnvironment>>,
    second: Option<HashMap<String, RepoEnvironment>>,
) -> Option<HashMap<String, RepoEnvironment>> {
    if let Some(map1) = first {
        if let Some(mut map2) = second {
            for (environment_name, repo_environment) in map1 {
                if let Some(repo_environment2) = map2.get(&environment_name) {
                    if let Some(reviewers) = &repo_environment.reviewers {
                        if let Some(reviewers2) = &repo_environment2.reviewers {
                            let reviewers =
                                reviewers.iter().chain(reviewers2.iter()).cloned().collect();
                            map2.insert(
                                environment_name,
                                RepoEnvironment {
                                    reviewers: Some(reviewers),
                                },
                            );
                        }
                    }
                }
            }

            Some(map2)
        } else {
            Some(map1)
        }
    } else {
        if let Some(map2) = second {
            Some(map2)
        } else {
            None
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
            teams: None,
            collaborators: None,
            environments: None,
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

        if let Some(environments) = &self.environments {
            apply_environments(&octocrab, &owner, &repo_name, environments).await?;
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

#[derive(Debug, Serialize, Deserialize)]
struct CreateOrUpdateEnvironmentRequest {
    reviewers: Option<Vec<EnvironmentReviewer>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EnvironmentReviewer {
    r#type: String,
    id: u64,
}

impl CreateOrUpdateEnvironmentRequest {
    pub fn new() -> CreateOrUpdateEnvironmentRequest {
        CreateOrUpdateEnvironmentRequest {
            reviewers: None,
        }
    }
}

async fn apply_environments(
    octocrab: &octocrab::Octocrab,
    owner: &String,
    repo: &String,
    environments: &HashMap<String, RepoEnvironment>,
) -> anyhow::Result<()> {
    debug!("Applying environments");

    for (environment_name, repo_environment) in environments {
        let route = format!("/repos/{owner}/{repo}/environments/{environment_name}");

        let request_data = CreateOrUpdateEnvironmentRequest::new();
        
        if let Some(reviewers) = &repo_environment.reviewers {
            for reviewer in reviewers {
                
            }
        }

        let body = serde_json::json!({"reviewers": [{"type":"User","id":89215}]});

        debug!("PUT {}\n{}", route, body);
        let result = octocrab._put(route, Some(&body)).await;

        match result {
            Ok(resp) => match resp.status() {
                StatusCode::OK | StatusCode::CREATED => {
                    info!(
                            "Created deployment environment {environment_name} in repository {owner}/{repo}"
                        );
                    let body = hyper::body::to_bytes(resp.into_body()).await?;
                    println!("{}", String::from_utf8(body.to_vec())?);
                }
                StatusCode::NO_CONTENT => {
                    info!(
                            "Updated deployment environment {environment_name} in repository {owner}/{repo}"
                        );
                }
                _ => {
                    error!(
                            "Error updating deployment environment {environment_name} in repository {owner}/{repo}: {}", resp.status()
                        );
                    return Err(anyhow::anyhow!(resp.status()));
                }
            },
            Err(e) => {
                error!(
                    "Error creating deployment environment {environment_name} in repository {owner}/{repo}: {e}"
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
        env_logger::builder()
        .target(env_logger::Target::Stdout)
        .init();


        let repo_config = serde_yaml::from_str::<super::RepoConfig>(
            r#"
            teams:
                a-team: maintain
            collaborators:
                aisrael: admin
            environments:
                gigalixir:
                    reviewers:
                        - aisrael
                        - gitsudo-io/a-team
            "#,
        )
        .unwrap();
        println!("repo_config: {:?}", repo_config);

        let test_token = env::var("GITHUB_TOKEN").unwrap();

        () = repo_config
            .apply(
                test_token.clone(),
                &"gitsudo-io".to_string(),
                &"gitsudo".to_string(),
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
            .check_manages("gitsudo-io", "gitsudo")
            .await?
            .unwrap();
        println!("{:?}", repo.permissions);
        assert!(repo.permissions.unwrap().maintain);
        Ok(())
    }

    #[test]
    fn test_merge_environments() {
        let prod1 = RepoEnvironment {
            reviewers: Some(vec!["alice".to_string()]),
        };
        let first: HashMap<String, RepoEnvironment> =
            HashMap::from([("production".to_string(), prod1)]);

        let prod2 = RepoEnvironment {
            reviewers: Some(vec!["bob".to_string()]),
        };
        let second: HashMap<String, RepoEnvironment> =
            HashMap::from([("production".to_string(), prod2)]);

        let merged = merge_environments(Some(first), Some(second)).unwrap();
        assert!(merged.get("production").is_some());
        let production = merged.get("production").unwrap();
        assert!(production.reviewers.is_some());
        let reviewers = production.reviewers.as_ref().unwrap();
        assert_eq!(reviewers.len(), 2);
        assert!(reviewers.contains(&"alice".to_string()));
        assert!(reviewers.contains(&"bob".to_string()));
    }
}
