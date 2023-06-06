use anyhow::Result;
use http::{HeaderName, StatusCode};
use log::{debug, error, info, warn};
use octocrab::params::teams::Permission;
use octocrab::OctocrabBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A struct that represents the ghctl configuration for a GitHub repository
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    pub teams: Option<HashMap<String, String>>,
    pub collaborators: Option<HashMap<String, String>>,
    pub environments: Option<HashMap<String, RepoEnvironment>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoEnvironment {
    pub reviewers: Option<Vec<String>>,
}

/// The `repo config get` command
pub async fn get(_context: &crate::ghctl::Context, repo_full_name: &String) -> Result<()> {
    error!("Not yet implemented: repo config get {}", repo_full_name);

    Ok(())
}

/// The `repo config apply` command
pub async fn apply(
    access_token: &str,
    owner: impl Into<String>,
    repo: impl Into<String>,
    config_files: &Vec<String>,
) -> Result<()> {
    let owner = owner.into();
    let repo = repo.into();
    debug!("Applying configuration to {owner}/{repo}");

    if config_files.is_empty() {
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

    match merged_config.apply(access_token, &owner, &repo).await {
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
        map2
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
        second
    }
}

fn permission_from_s(s: &str) -> Option<Permission> {
    match s {
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

    pub async fn validate_and_prefetch(
        &self,
        access_token: &str,
        owner: &str
    ) -> Result<(HashMap<String, u64>, HashMap<String, HashMap<String, u64>>)> {
        let mut users = HashMap::new();

        if let Some(collaborators) = self.collaborators.as_ref() {
            for collaborator in collaborators.keys() {
                debug!("Validating user {collaborator}");
                let user = crate::github::get_user(access_token, collaborator).await?;
                debug!("Found user {:?}", user);
                users.insert(collaborator.clone(), user.id);
            }
        }

        let mut orgs_teams: HashMap<String, HashMap<String, u64>> = HashMap::new();

        let octocrab = OctocrabBuilder::default()
            .personal_token(access_token.to_owned())
            .build()?;

        if let Some(teams) = self.teams.as_ref() {
            let org = orgs_teams
                .entry(owner.to_string())
                .or_insert_with(HashMap::new);

            for team_slug in teams.keys() {
                debug!("Validating team {team_slug}");
                let team = octocrab.teams(owner).get(team_slug).await?;
                debug!("Found team \"{}\" ({})", team.name, team.id);
                org.insert(team_slug.clone(), *team.id);
            }
        }

        if let Some(environments) = self.environments.as_ref() {
            for repo_environment in environments.values() {
                if let Some(reviewers) = &repo_environment.reviewers {
                    for reviewer in reviewers {
                        match reviewer.split_once('/') {
                            Some((org, team_slug)) => {
                                if org.is_empty() || team_slug.is_empty() {
                                    warn!("Invalid {{org}}/{{team}} name: \"{}\"!", reviewer);
                                } else {
                                    let teams = orgs_teams
                                        .entry(org.to_string())
                                        .or_insert_with(HashMap::new);
                                    if !teams.contains_key(team_slug) {
                                        debug!("Validating team {team_slug}");
                                        let team = octocrab.teams(org).get(team_slug).await?;
                                        debug!("Found team \"{}\" ({})", team.name, team.id);
                                        teams.insert(team_slug.to_string(), *team.id);
                                    }
                                }
                            }

                            None => {
                                let user = crate::github::get_user(access_token, reviewer).await?;
                                debug!("Found user {:?}", user);
                                users.insert(reviewer.clone(), user.id);
                            }
                        }
                    }
                }
            }
        }

        Ok((users, orgs_teams))
    }

    pub async fn apply(
        &self,
        access_token: &str,
        owner: &String,
        repo_name: &String,
    ) -> anyhow::Result<()> {
        let (users, orgs_teams) = self
            .validate_and_prefetch(access_token, owner)
            .await?;
        debug!("Applying configuration");
        let octocrab = OctocrabBuilder::default()
            .personal_token(access_token.to_owned())
            .build()?;

        if let Some(team_permissions) = &self.teams {
            apply_teams(&octocrab, owner, repo_name, team_permissions).await?;
        }

        let octocrab = OctocrabBuilder::default()
            .personal_token(access_token.to_owned())
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
            apply_collaborators(&octocrab, owner, repo_name, collaborator_permissions).await?;
        }

        if let Some(environments) = &self.environments {
            apply_environments(&octocrab, owner, repo_name, environments, users, orgs_teams)
                .await?;
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
        CreateOrUpdateEnvironmentRequest { reviewers: None }
    }

    pub fn add_reviewer(&mut self, r#type: &str, id: u64) {
        if self.reviewers.is_none() {
            self.reviewers = Some(vec![EnvironmentReviewer {
                r#type: r#type.to_string(),
                id,
            }]);
        } else {
            self.reviewers.as_mut().unwrap().push(EnvironmentReviewer {
                r#type: r#type.to_string(),
                id,
            });
        }
    }
}

async fn apply_environments(
    octocrab: &octocrab::Octocrab,
    owner: &String,
    repo: &String,
    environments: &HashMap<String, RepoEnvironment>,
    users: HashMap<String, u64>,
    orgs_teams: HashMap<String, HashMap<String, u64>>,
) -> anyhow::Result<()> {
    debug!("Applying environments");

    for (environment_name, repo_environment) in environments {
        let route = format!("/repos/{owner}/{repo}/environments/{environment_name}");

        let mut request_data = CreateOrUpdateEnvironmentRequest::new();

        if let Some(reviewers) = &repo_environment.reviewers {
            for reviewer in reviewers {
                match reviewer.split_once('/') {
                    Some((org, team_slug)) => {
                        if org.is_empty() || team_slug.is_empty() {
                            warn!("Invalid {{org}}/{{team}} name: \"{}\"!", reviewer);
                        } else {
                            let teams = orgs_teams.get(org).unwrap();
                            match teams.get(team_slug) {
                                Some(id) => request_data.add_reviewer("Team", *id),
                                None => {
                                    warn!(
                                        "Unknown team \"{}\" in organization \"{}\"",
                                        team_slug, org
                                    );
                                }
                            }
                        }
                    }

                    None => match users.get(reviewer) {
                        Some(id) => request_data.add_reviewer("User", *id),
                        None => warn!("Unknown user \"{}\"", reviewer),
                    },
                }
            }
        }

        let body = serde_json::json!(request_data);

        debug!("PUT {}\n{}", route, body);
        let result = octocrab._put(route, Some(&body)).await;

        match result {
            Ok(resp) => match resp.status() {
                StatusCode::OK | StatusCode::CREATED => {
                    info!(
                            "Created deployment environment {environment_name} in repository {owner}/{repo}"
                        );
                    let body = hyper::body::to_bytes(resp.into_body()).await?;
                    debug!("{}", String::from_utf8(body.to_vec())?);
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

    /// We ignore this test for now as it requires an access token for testing and
    /// performs actual GitHub API calls, until we can add some VCR-like HTTP recording
    /// in the future.
    ///
    /// To run ignored tests locally, use `cargo test -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn test_validate_and_prefetch() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::builder()
            .target(env_logger::Target::Stdout)
            .init();
        let github_token = env::var("GITHUB_TOKEN").unwrap();

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
                        - gitsudo-io/infrastructure
            "#,
        )
        .unwrap();
        println!("repo_config: {:?}", repo_config);

        let (users, teams) = repo_config
            .validate_and_prefetch(&github_token, "gitsudo-io")
            .await?;
        assert!(!users.is_empty());
        assert!(*users.get("aisrael").unwrap() == 89215);

        assert!(!teams.is_empty());
        let gitsudo_io = teams.get("gitsudo-io").unwrap();
        assert!(!gitsudo_io.is_empty());
        assert!(*gitsudo_io.get("a-team").unwrap() == 7604587);
        assert!(*gitsudo_io.get("infrastructure").unwrap() == 7924849);

        Ok(())
    }

    /// We ignore this test for now as it requires an access token for testing and
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

        let github_token = env::var("GITHUB_TOKEN").unwrap();

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

        () = repo_config
            .apply(
                github_token.as_str(),
                &"gitsudo-io".to_string(),
                &"gitsudo".to_string(),
            )
            .await?;

        let octocrab = OctocrabBuilder::default()
            .personal_token(github_token)
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
