///! This module defines actual code that executes the ghctl commands.
use crate::commands::{Opts, Commands, RepoCommands, RepoConfigCommands};

/// A context object that holds state for the ghctl commands
#[derive(Debug)]
pub struct Context {
    pub opts: Opts,
}

/// Build a context object from the command-line arguments
fn build_context(opts: Opts) -> Context {
    Context { opts }
}

/// Run the ghctl CLI
pub fn cli(opts: Opts) {
    let context = build_context(opts);

    match &context.opts.command {
        Commands::Repo(repo) => {
            match &repo.command {
                RepoCommands::Config(config) => {
                    match &config.command {
                        RepoConfigCommands::Apply { repository, config_file } => {
                            println!("Applying configuration {} to repository {}", config_file.as_ref().unwrap(), repository.as_ref().unwrap());
                            match &context.opts.access_token {
                                Some(token) => {
                                    println!("Using access token {}", token);
                                }
                                None => {
                                    println!("No access token provided");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

}