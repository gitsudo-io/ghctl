///! This module defines actual code that executes the ghctl commands.
pub mod repo;

use log::error;
use std::env::VarError;
use std::process::exit;

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
        Err(e) => match e {
            VarError::NotPresent => {
                error!("No access token provided and GITHUB_TOKEN environment variable not set, aborting.");
                exit(1)
            }
            _ => Err(anyhow::anyhow!(e)),
        },
    }
}

/// Run the ghctl CLI
pub async fn cli(opts: Opts) {
    match &opts.command {
        Commands::Version => println!("ghctl version {}", clap::crate_version!()),
        _ => {
            env_logger::builder()
                .filter_level(opts.verbose.log_level_filter())
                .target(env_logger::Target::Stdout)
                .init();
            match build_context(opts) {
                Ok(context) => match &context.opts.command {
                    Commands::Repo(repo) => commands::repo::repo(&context, repo).await,
                    _ => {
                        error!("Not yet implemented: {:?}", &context.opts.command)
                    }
                },
                Err(e) => error!("Error: {}", e),
            }
        }
    }
}
