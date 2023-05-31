///! This module defines actual code that executes the ghctl commands.
pub mod repo;

use crate::commands;
use crate::commands::{Commands, Opts};
use crate::commands::repo::RepoCommands;
use anyhow::Result;

/// A context object that holds state for the ghctl commands
#[derive(Debug)]
pub struct Context {
    pub access_token: String,
    pub opts: Opts,
}

/// Build a context object from the command-line arguments
fn build_context(opts: Opts) -> Result<Context> {
    let access_token = get_access_token(&opts)?;
    Ok(Context { access_token, opts })
}

fn get_access_token(opts: &Opts) -> Result<String> {
    match &opts.access_token {
        Some(access_token) => Ok(access_token.clone()),
        None => maybe_get_github_token_env_var(),
    }
}

fn maybe_get_github_token_env_var() -> Result<String> {
    match std::env::var("GITHUB_TOKEN") {
        Ok(access_token) => Ok(access_token),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

/// Run the ghctl CLI
pub async fn cli(opts: Opts) {
    match build_context(opts) {
        Ok(context) => match &context.opts.command {
            Commands::Repo(repo) => match &repo.command {
                RepoCommands::Get { repo_name } => {
                    let v: Vec<&str> = repo_name.as_ref().unwrap().split("/").collect();
                    match repo::get_repo(&context.access_token, v[0], v[1]).await {
                        Ok(repo) => println!("{}", serde_json::to_string_pretty(&repo).unwrap()),
                        Err(e) => println!("Error: {}", e),
                    }
                }

                RepoCommands::Config(repo_config) =>  {
                    commands::repo::handle_repo_config_commands(&context, repo_config).await.unwrap();                    
                }
            },
        },
        Err(e) => println!("Error: {}", e),
    }
}
