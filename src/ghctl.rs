///! This module defines actual code that executes the ghctl commands.
pub mod repo;

use crate::commands;
use crate::commands::{Commands, Opts};
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
            Commands::Repo(repo) => commands::repo::repo(&context, repo).await,
        },
        Err(e) => println!("Error: {}", e),
    }
}
 