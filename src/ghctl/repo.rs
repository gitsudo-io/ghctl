pub mod config;

use anyhow::Result;
use http::HeaderName;
use log::error;
use octocrab::models::Repository;
use octocrab::OctocrabBuilder;



use crate::utils::split_some_repo_full_name;

pub async fn get_repo(
    access_token: &str,
    owner: impl Into<String>,
    repo_name: impl Into<String>,
) -> Result<Repository> {
    let octocrab = OctocrabBuilder::default()
        .personal_token(access_token.to_owned())
        .build()?;

    let repository = octocrab.repos(owner, repo_name).get().await?;
    Ok(repository)
}

pub async fn environments_list(context: &crate::ghctl::Context, repo_name: &String) {
    do_environments_list(context, repo_name).await.unwrap();
}

async fn do_environments_list(context: &crate::ghctl::Context, repo_name: &String) -> Result<()> {
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
