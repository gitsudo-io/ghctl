use anyhow::Result;
use octocrab::models::Repository;
use octocrab::params::teams::Permission;
use octocrab::OctocrabBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub async fn get_repo(access_token: &String, owner: &str, repo_name: &str) -> Result<Repository> {
    let octocrab = OctocrabBuilder::default()
        .personal_token(access_token.clone())
        .build()?;

    let repository = octocrab.repos(owner, repo_name).get().await?;
    Ok(repository)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    pub teams: HashMap<String, String>,
}

fn permission_from_s(s: &String) -> Option<Permission> {
    match s.as_str() {
        "pull" => Some(Permission::Pull),
        "push" => Some(Permission::Push),
        "admin" => Some(Permission::Admin),
        "maintain" => Some(Permission::Maintain),
        "triage" => Some(Permission::Triage),
        _ => None,
    }
}

impl RepoConfig {
    pub fn new() -> RepoConfig {
        RepoConfig {
            teams: HashMap::new(),
        }
    }

    pub async fn apply(
        &self,
        access_token: String,
        owner: String,
        repo_name: String,
    ) -> anyhow::Result<()> {
        println!("Applying configuration");
        self.apply_teams(access_token, owner, repo_name).await
    }

    async fn apply_teams(
        &self,
        access_token: String,
        owner: String,
        repo_name: String,
    ) -> anyhow::Result<()> {
        println!("Applying teams");
        let octocrab = OctocrabBuilder::default()
            .personal_token(access_token)
            .build()?;

        for (team_slug, permission_s) in &self.teams {
            let permission = permission_from_s(permission_s).unwrap();

            match octocrab
                .teams(&owner)
                .repos(team_slug)
                .add_or_update(&owner, &repo_name, permission)
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
}

impl Default for RepoConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use ::http::header::HeaderName;
    use octocrab::OctocrabBuilder;
    use std::env;

    #[tokio::test]
    async fn test_repo_config() -> Result<(), Box<dyn std::error::Error>> {
        let repo_config = serde_yaml::from_str::<super::RepoConfig>(
            r#"teams:
                a-team: maintain
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
