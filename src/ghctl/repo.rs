pub mod config;

use anyhow::Result;
use http::HeaderName;
use log::error;
use octocrab::models::Repository;
use octocrab::OctocrabBuilder;

pub use config::RepoConfig;

use crate::utils::split_some_repo_full_name;

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

pub async fn environments_list(context: &crate::ghctl::Context, repo_name: &String) {
    do_environments_list(context, repo_name)
        .await
        .unwrap();
}

async fn do_environments_list(
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

pub async fn environments_get(
    context: &crate::ghctl::Context,
    repo_name: &String,
    environment_name: &String,
) {
    do_environments_get(context, repo_name, environment_name)
        .await
        .unwrap();
}

async fn do_environments_get(
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
}
