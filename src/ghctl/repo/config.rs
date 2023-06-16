use anyhow::Result;
use http::{HeaderName, StatusCode};
use log::Level::Trace;
use log::{debug, error, info, log_enabled, trace, warn};
use octocrab::models::repos::{ProtectionRule, Reviewer};
use octocrab::models::{Permissions, Repository, TeamId};
use octocrab::repos::RepoHandler;
use octocrab::{models::UserId, params::teams::Permission};
use octocrab::{Octocrab, OctocrabBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ghctl;
use crate::github;
use crate::utils::split_some_repo_full_name;
use github::AddRepositoryCollaboratorResult;

/// A struct that represents the ghctl configuration for a GitHub repository
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collaborators: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environments: Option<HashMap<String, RepoEnvironment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_protection_rules: Option<HashMap<String, BranchProtectionRule>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoEnvironment {
    pub reviewers: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BranchProtectionRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pull_request: Option<RequirePullRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_status_checks: Option<RequiredStatusChecks>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequirePullRequest {
    Enabled(bool),
    EnabledWithSettings(RequirePullRequestSettings),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequirePullRequestSettings {
    pub required_approving_review_count: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequiredStatusChecks {
    pub strict: Option<bool>,
    pub contexts: Option<Vec<String>>,
}

/// The `repo config get` command
pub async fn get(context: &ghctl::Context, repo_full_name: &String) -> Result<()> {
    let (owner, repo) = split_some_repo_full_name(repo_full_name)?;

    let octocrab = OctocrabBuilder::default()
        .personal_token(context.access_token.to_owned())
        .add_header(
            HeaderName::from_static("accept"),
            "application/vnd.github.v3.repository+json".to_string(),
        )
        .add_header(
            HeaderName::from_static("x-github-api-version"),
            "2022-11-28".to_string(),
        )
        .build()?;

    let repo_handler = octocrab.repos(owner, repo);

    match repo_handler.get().await {
        Ok(repository) => do_repo_config_get(&octocrab, &repository, repo_handler).await?,
        Err(e) => {
            error!("Error: {}", e);
        }
    }

    Ok(())
}

async fn do_repo_config_get(
    octocrab: &Octocrab,
    repository: &Repository,
    repo_handler: RepoHandler<'_>,
) -> Result<()> {
    let teams = list_repo_teams(octocrab, &repo_handler).await?;
    let collaborators = list_repo_collaborators(octocrab, &repo_handler).await?;
    let environments = list_repo_environments(repository, &repo_handler).await?;
    let branch_protection_rules =
        list_branch_protection_rules(octocrab, repository, &repo_handler).await?;
    let repo_config = RepoConfig {
        teams,
        collaborators,
        environments,
        branch_protection_rules,
    };

    println!("{}", serde_yaml::to_string(&repo_config)?);

    Ok(())
}

async fn list_repo_teams(
    octocrab: &Octocrab,
    repo_handler: &RepoHandler<'_>,
) -> Result<Option<HashMap<String, String>>> {
    let teams = octocrab
        .all_pages(repo_handler.list_teams().send().await?)
        .await?;
    if log_enabled!(Trace) {
        for team in &teams {
            trace!(
                "Found team \"{}\" ({}) with \"{}\" permission",
                team.name,
                team.id,
                team.permission
            );
        }
    } else {
        debug!("Found {} teams", teams.len());
    }

    Ok(if teams.is_empty() {
        None
    } else {
        let map = teams
            .iter()
            .map(|team| (team.slug.clone(), team.permission.clone()))
            .collect();
        Some(map)
    })
}

async fn list_repo_collaborators(
    octocrab: &Octocrab,
    repo_handler: &RepoHandler<'_>,
) -> Result<Option<HashMap<String, String>>> {
    let collaborators = octocrab
        .all_pages(repo_handler.list_collaborators().send().await?)
        .await?;
    if log_enabled!(Trace) {
        for collaborator in &collaborators {
            trace!(
                "Found collaborator \"{}\" ({}) with permissions \"{:?}\"",
                collaborator.author.login,
                collaborator.author.id,
                collaborator.permissions
            );
        }
    } else {
        debug!("Found {} collaborators", collaborators.len());
    }

    Ok(if collaborators.is_empty() {
        None
    } else {
        let map = collaborators
            .iter()
            .map(|collaborator| {
                let username = collaborator.author.login.clone();
                let permission = permissions_to_single_value(&collaborator.permissions);
                (username, permission)
            })
            .collect();

        Some(map)
    })
}

fn permissions_to_single_value(permissions: &Permissions) -> String {
    String::from(if permissions.admin {
        "admin"
    } else if permissions.maintain {
        "maintain"
    } else if permissions.push {
        "push"
    } else if permissions.triage {
        "triage"
    } else if permissions.pull {
        "pull"
    } else {
        "unknown"
    })
}

async fn list_repo_environments(
    repository: &Repository,
    repo_handler: &RepoHandler<'_>,
) -> Result<Option<HashMap<String, RepoEnvironment>>> {
    debug!("Listing environments");
    let list_environments = repo_handler.list_environments().send().await?;
    let environments = list_environments.environments;
    if log_enabled!(Trace) {
        for environment in &environments {
            trace!("Found environment:\n{:?}", environment);
        }
    } else {
        debug!("Found {} environments", environments.len());
    }

    Ok(if environments.is_empty() {
        None
    } else {
        let map: HashMap<String, RepoEnvironment> = environments
            .iter()
            .map(|environment| {
                let name = environment.name.clone();

                let protection_rules: &Vec<ProtectionRule> = &environment.protection_rules;
                trace!("Found protection rules: {:?}", protection_rules);

                let reviewers: Vec<String> = protection_rules
                    .iter()
                    .filter(|rule| matches!(rule, ProtectionRule::RequiredReviewers(_)))
                    .flat_map(|rule| match rule {
                        ProtectionRule::RequiredReviewers(reviewers) => reviewers
                            .reviewers
                            .iter()
                            .map(|reviewer: &Reviewer| match reviewer {
                                Reviewer::User(reviewer) => reviewer.reviewer.login.clone(),
                                Reviewer::Team(reviewer) => format!(
                                    "{}/{}",
                                    match reviewer.reviewer.organization.as_ref() {
                                        Some(org) => org.login.clone(),
                                        None => repository.owner.as_ref().unwrap().login.clone(),
                                    },
                                    reviewer.reviewer.slug
                                ),
                                &_ => todo!(),
                            })
                            .collect(),
                        _ => vec![],
                    })
                    .collect();

                let reviewer_names = if reviewers.is_empty() {
                    None
                } else {
                    Some(reviewers)
                };

                let repo_environment = RepoEnvironment {
                    reviewers: reviewer_names,
                };
                (name, repo_environment)
            })
            .collect();

        println!("Found {} environments", map.values().len());

        Some(map)
    })
}

async fn list_branch_protection_rules(
    octocrab: &Octocrab,
    repository: &Repository,
    repo_handler: &RepoHandler<'_>,
) -> Result<Option<HashMap<String, BranchProtectionRule>>> {
    debug!("Listing environments");
    let protected_branches = octocrab
        .all_pages(repo_handler.list_branches().protected(true).send().await?)
        .await?;
    debug!("Found {} protected branches", protected_branches.len());

    if protected_branches.is_empty() {
        return Ok(None);
    }

    let futures = protected_branches.iter().map(|branch| async move {
        trace!("Found protected branch:\n{:?}", branch);

        let owner = &repository.owner.as_ref().unwrap().login;

        let branch_protection =
            github::get_branch_protection(octocrab, owner, &repository.name, &branch.name)
                .await
                .unwrap();

        let require_pull_request =
            branch_protection
                .required_pull_request_reviews
                .map(|required_pull_request_reviews| {
                    let required_approving_review_count = required_pull_request_reviews
                        .required_approving_review_count
                        .unwrap_or(0);
                    if required_approving_review_count > 0 {
                        RequirePullRequest::EnabledWithSettings(RequirePullRequestSettings {
                            required_approving_review_count: required_pull_request_reviews
                                .required_approving_review_count,
                        })
                    } else {
                        RequirePullRequest::Enabled(true)
                    }
                });

        let required_status_checks =
            branch_protection
                .required_status_checks
                .map(|checks| RequiredStatusChecks {
                    strict: Some(checks.strict),
                    contexts: Some(checks.contexts),
                });

        (
            branch.name.clone(),
            BranchProtectionRule {
                require_pull_request,
                required_status_checks,
            },
        )
    });

    let branch_protection_rules: HashMap<String, BranchProtectionRule> =
        futures::future::join_all(futures)
            .await
            .into_iter()
            .collect();

    Ok(Some(branch_protection_rules))
}

/// The `repo config apply` command
pub async fn apply(
    access_token: &str,
    owner: &str,
    repo: &str,
    config_files: &Vec<String>,
) -> Result<()> {
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

    match merged_config.apply(access_token, owner, repo).await {
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
        branch_protection_rules: merge_option_hashmap(
            first.branch_protection_rules,
            second.branch_protection_rules,
        ),
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
    maybe_first: Option<HashMap<String, RepoEnvironment>>,
    maybe_second: Option<HashMap<String, RepoEnvironment>>,
) -> Option<HashMap<String, RepoEnvironment>> {
    if let Some(first) = maybe_first {
        if let Some(mut second) = maybe_second {
            for (environment_name, repo_environment) in first {
                if let Some(repo_environment2) = second.get(&environment_name) {
                    if let Some(reviewers) = &repo_environment.reviewers {
                        if let Some(reviewers2) = &repo_environment2.reviewers {
                            let reviewers =
                                reviewers.iter().chain(reviewers2.iter()).cloned().collect();
                            second.insert(
                                environment_name,
                                RepoEnvironment {
                                    reviewers: Some(reviewers),
                                },
                            );
                        }
                    }
                }
            }

            Some(second)
        } else {
            Some(first)
        }
    } else {
        maybe_second
    }
}

fn permission_from_s(s: &str) -> Option<Permission> {
    match s {
        "pull" | "read" => Some(Permission::Pull),
        "triage" => Some(Permission::Triage),
        "push" | "write" => Some(Permission::Push),
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
            branch_protection_rules: None,
        }
    }

    pub async fn validate_and_prefetch(
        &self,
        access_token: &str,
        owner: &str,
    ) -> Result<(
        HashMap<String, UserId>,
        HashMap<String, HashMap<String, TeamId>>,
    )> {
        let mut users = HashMap::new();

        if let Some(collaborators) = self.collaborators.as_ref() {
            for (collaborator, permission) in collaborators {
                match permission_from_s(permission) {
                    Some(_) => {}
                    None => {
                        let msg = format!("Invalid/unrecognized permission \"{permission}\" for collaborator \"{collaborator}\"!");
                        return Err(anyhow::anyhow!(msg));
                    }
                }

                debug!("Validating user {collaborator}");
                let user = crate::github::get_user(access_token, collaborator).await?;
                debug!("Found user {:?}", user);
                users.insert(collaborator.clone(), user.id);
            }
        }

        let mut orgs_teams: HashMap<String, HashMap<String, TeamId>> = HashMap::new();

        let octocrab = OctocrabBuilder::default()
            .personal_token(access_token.to_owned())
            .build()?;

        if let Some(teams) = self.teams.as_ref() {
            let org = orgs_teams
                .entry(owner.to_string())
                .or_insert_with(HashMap::new);

            for (team_slug, permission) in teams {
                debug!("Validating permission {permission}");
                match permission_from_s(permission) {
                    Some(_) => {}
                    None => {
                        let msg = format!("Invalid/unrecognized permission \"{permission}\" for team \"{team_slug}\"!");
                        return Err(anyhow::anyhow!(msg));
                    }
                }

                debug!("Validating team {team_slug}");
                let team = octocrab.teams(owner).get(team_slug).await?;
                debug!("Found team \"{}\" ({})", team.name, team.id);
                org.insert(team_slug.clone(), team.id);
            }
        }

        if let Some(environments) = self.environments.as_ref() {
            for repo_environment in environments.values() {
                self.validate_repo_environment(
                    &octocrab,
                    &mut users,
                    &mut orgs_teams,
                    access_token,
                    repo_environment,
                )
                .await?;
            }
        }

        Ok((users, orgs_teams))
    }

    async fn validate_repo_environment(
        &self,
        octocrab: &octocrab::Octocrab,
        users: &mut HashMap<String, UserId>,
        orgs_teams: &mut HashMap<String, HashMap<String, TeamId>>,
        access_token: &str,
        repo_environment: &RepoEnvironment,
    ) -> Result<()> {
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
                                teams.insert(team_slug.to_string(), team.id);
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

        Ok(())
    }

    pub async fn apply(
        &self,
        access_token: &str,
        owner: &str,
        repo_name: &str,
    ) -> anyhow::Result<()> {
        let (users, orgs_teams) = self.validate_and_prefetch(access_token, owner).await?;
        debug!("Applying configuration");
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

        if let Some(team_permissions) = &self.teams {
            apply_teams(access_token, &octocrab, owner, repo_name, team_permissions).await?;
        }

        if let Some(collaborator_permissions) = &self.collaborators {
            apply_collaborators(&octocrab, owner, repo_name, collaborator_permissions).await?;
        }

        if let Some(environments) = &self.environments {
            apply_environments(&octocrab, owner, repo_name, environments, users, orgs_teams)
                .await?;
        }

        if let Some(branch_protection_rules) = &self.branch_protection_rules {
            apply_branch_protection_rules(&octocrab, owner, repo_name, branch_protection_rules)
                .await?;
        }
        Ok(())
    }
}

async fn apply_teams(
    access_token: &str,
    octocrab: &octocrab::Octocrab,
    owner: &str,
    repo: &str,
    team_permissions: &HashMap<String, String>,
) -> anyhow::Result<()> {
    debug!("Applying teams");
    for (team_slug, permission_s) in team_permissions {
        let result =
            github::check_team_permissions(access_token, owner, team_slug, owner, repo).await?;
        let already_has_permission = match result.permissions.get(permission_s) {
            Some(v) => *v,
            None => false,
        };
        if already_has_permission {
            info!("Team {team_slug} already has permission {permission_s} on {owner}/{repo}");
            continue;
        }

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
    owner: &str,
    repo: &str,
    collaborator_permissions: &HashMap<String, String>,
) -> anyhow::Result<()> {
    debug!("Applying collaborators");

    for (username, permission_s) in collaborator_permissions {
        if octocrab
            .repos(owner, repo)
            .is_collaborator(username)
            .await?
        {
            let result =
                github::get_repository_permissions_for_user(octocrab, owner, repo, username)
                    .await?;

            if result.permission == *permission_s {
                info!("User {username} already has permission {permission_s} on repository {owner}/{repo}");
                continue;
            }
        }

        match permission_from_s(permission_s) {
            Some(permission) => match github::add_repository_collaborator(
                octocrab,
                owner,
                repo,
                username,
                permission_to_s(&permission),
            )
            .await?
            {
                AddRepositoryCollaboratorResult::Ok(body) => {
                    info!(
                            "Added collaborator {username} with permission {permission_s} to repository {owner}/{repo}"
                        );
                    println!("{}", body);
                }
                AddRepositoryCollaboratorResult::AlreadyExists => {
                    info!(
                            "Updated collaborator {username} with permission {permission_s} to repository {owner}/{repo}"
                        );
                }
            },
            None => {
                let msg = format!("Invalid/unrecognized permission \"{permission_s}\" for collaborator \"{username}\"!");
                return Err(anyhow::anyhow!(msg));
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
    owner: &str,
    repo: &str,
    environments: &HashMap<String, RepoEnvironment>,
    users: HashMap<String, UserId>,
    orgs_teams: HashMap<String, HashMap<String, TeamId>>,
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
                                Some(id) => request_data.add_reviewer("Team", id.into_inner()),
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
                        Some(id) => request_data.add_reviewer("User", id.into_inner()),
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

async fn apply_branch_protection_rules(
    octocrab: &Octocrab,
    owner: &str,
    repo: &str,
    branch_protection_rules: &HashMap<String, BranchProtectionRule>,
) -> Result<()> {
    for (branch, branch_protection_rule) in branch_protection_rules {
        apply_branch_protection_rule(octocrab, owner, repo, branch, branch_protection_rule).await?
    }

    Ok(())
}

async fn apply_branch_protection_rule(
    octocrab: &Octocrab,
    owner: &str,
    repo: &str,
    branch: &str,
    branch_protection_rule: &BranchProtectionRule,
) -> Result<()> {
    let mut repository_branch_protection = github::RepositoryBranchProtectionRequest::new();

    if let Some(require_pull_request) = &branch_protection_rule.require_pull_request {
        repository_branch_protection.required_pull_request_reviews = match require_pull_request {
            RequirePullRequest::Enabled(enabled) => {
                if *enabled {
                    Some(github::RequiredPullRequestReviews {
                        dismiss_stale_reviews: false,
                        require_code_owner_reviews: false,
                        required_approving_review_count: Some(0),
                    })
                } else {
                    None
                }
            }
            RequirePullRequest::EnabledWithSettings(settings) => {
                Some(github::RequiredPullRequestReviews {
                    dismiss_stale_reviews: false,
                    require_code_owner_reviews: false,
                    required_approving_review_count: settings.required_approving_review_count,
                })
            }
        };
    }

    if let Some(required_status_checks) = &branch_protection_rule.required_status_checks {
        repository_branch_protection.required_status_checks = Some(github::RequiredStatusChecks {
            strict: required_status_checks.strict.unwrap_or(false),
            contexts: match required_status_checks.contexts.as_ref() {
                Some(contexts) => contexts.clone(),
                None => Vec::new(),
            },
            enforcement_level: None,
        });
    }

    let result = github::update_branch_protection(
        octocrab,
        owner,
        repo,
        branch,
        &repository_branch_protection,
    )
    .await;

    match result {
        Ok(repository_branch_protection) => {
            info!(
                "Applied branch protection rules to branch {branch} in repository {owner}/{repo}"
            );
            debug!("{:?}", repository_branch_protection);
        }
        Err(e) => {
            debug!(
                "{}",
                serde_json::to_string_pretty(&repository_branch_protection)?
            );
            error!("{:?}", e);
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

    fn init() {
        env_logger::builder()
            .target(env_logger::Target::Stdout)
            .try_init()
            .unwrap_or_default();
    }

    /// We ignore this test for now as it requires an access token for testing and
    /// performs actual GitHub API calls, until we can add some VCR-like HTTP recording
    /// in the future.
    ///
    /// To run ignored tests locally, use `cargo test -- --ignored`
    #[tokio::test]
    async fn test_validate_and_prefetch_invalid_permission(
    ) -> Result<(), Box<dyn std::error::Error>> {
        init();

        let repo_config = serde_yaml::from_str::<super::RepoConfig>(
            r#"
            teams:
                a-team: foo
            "#,
        )
        .unwrap();
        println!("repo_config: {:?}", repo_config);

        if let Err(e) = repo_config.validate_and_prefetch("", "gitsudo-io").await {
            assert!(e.to_string().contains("Invalid/unrecognized permission"));
            Ok(())
        } else {
            panic!("Expected error");
        }
    }

    /// We ignore this test for now as it requires an access token for testing and
    /// performs actual GitHub API calls, until we can add some VCR-like HTTP recording
    /// in the future.
    ///
    /// To run ignored tests locally, use `cargo test -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn test_validate_and_prefetch() -> Result<(), Box<dyn std::error::Error>> {
        init();
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
        assert!(*users.get("aisrael").unwrap() == UserId::from(89215));

        assert!(!teams.is_empty());
        let gitsudo_io = teams.get("gitsudo-io").unwrap();
        assert!(!gitsudo_io.is_empty());
        assert!(gitsudo_io.get("a-team").unwrap().into_inner() == 7604587);
        assert!(gitsudo_io.get("infrastructure").unwrap().into_inner() == 7924849);

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
        init();

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
            branch_protection_rules:
                main:
                    required_status_checks:
                        contexts:
                            - "mix/test"
                    require_pull_request:
                        required_approving_review_count: 1
            "#,
        )
        .unwrap();
        println!("repo_config: {:?}", repo_config);
        println!("repo_config: {:?}", repo_config.branch_protection_rules);

        repo_config
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

#[cfg(test)]
mod test {
    use super::*;
    use octocrab::OctocrabBuilder;
    use std::env;

    fn init() {
        env_logger::builder()
            .target(env_logger::Target::Stdout)
            .try_init()
            .unwrap_or_default();
    }

    #[tokio::test]
    #[ignore]
    async fn test_repo_list_environments() {
        init();
        let github_token = env::var("GITHUB_TOKEN").unwrap();

        let octocrab = OctocrabBuilder::default()
            .personal_token(github_token)
            .add_header(
                HeaderName::from_static("accept"),
                "application/vnd.github.v3.repository+json".to_string(),
            )
            .add_header(
                HeaderName::from_static("x-github-api-version"),
                "2022-11-28".to_string(),
            )
            .build()
            .unwrap();

        let list_environments = octocrab
            .repos("gitsudo-io", "gitsudo")
            .list_environments()
            .send()
            .await
            .unwrap();
        let environments = list_environments.environments;

        println!("Got {} environments", environments.len());

        for environment in environments {
            println!("{:?}", environment);
        }
    }
}
