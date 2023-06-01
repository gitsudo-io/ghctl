use anyhow::Result;
use clap::{Args, Subcommand};
use log::{error, info};

use crate::ghctl;
use crate::utils::split_repo_full_name;

/// The `repo` subcommand
#[derive(Args, Debug)]
pub struct RepoCommand {
    #[command(subcommand)]
    pub command: RepoSubcommand,
}

/// The `repo` subcommands
#[derive(Subcommand, Debug)]
pub enum RepoSubcommand {
    #[command(about = "Apply repository configuration")]
    Get {
        #[arg(help = "The repository full name, e.g. 'aisrael/ghctl'")]
        repo_name: Option<String>,
    },
    Config(RepoConfigCommand),
}

#[derive(Args, Debug)]
pub struct RepoConfigCommand {
    #[command(subcommand)]
    pub command: RepoConfigSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum RepoConfigSubcommand {
    #[command(about = "Retrieve repository configuration")]
    Get {
        #[arg(help = "The repository full name, e.g. 'aisrael/ghctl'")]
        repo_full_name: Option<String>,
    },
    #[command(about = "Apply repository configuration")]
    Apply {
        #[arg(help = "The repository full name, e.g. 'aisrael/ghctl'")]
        repo_full_name: Option<String>,

        #[arg(
            short = 'F',
            long = "config-file",
            help = "The configuration file to apply"
        )]
        config_files: Vec<String>
    },
}

pub async fn repo(context: &ghctl::Context, repo: &RepoCommand) {
    match &repo.command {
        RepoSubcommand::Get { repo_name } => {
            let (owner, repo_name) = split_repo_full_name(repo_name).unwrap();
            match crate::ghctl::repo::get_repo(&context.access_token, owner, repo_name).await {
                Ok(repo) => println!("{}", serde_json::to_string_pretty(&repo).unwrap()),
                Err(e) => error!("Error: {}", e),
            }
        }

        RepoSubcommand::Config(command) => {
            config(&context, command).await.unwrap();
        }
    }
}

pub async fn config(context: &ghctl::Context, repo_config: &RepoConfigCommand) -> Result<()> {
    match &repo_config.command {
        RepoConfigSubcommand::Get { repo_full_name } => 
            ghctl::repo::get_repo_config(&context, repo_full_name.as_ref().unwrap()).await,
        
        RepoConfigSubcommand::Apply { repo_full_name, config_files } => {
            let (owner, repo_name) = split_repo_full_name(repo_full_name).unwrap();
            match ghctl::repo::config_apply(&context.access_token, owner, repo_name, config_files).await {
                Ok(_) => info!("Applied configuration to {}", repo_full_name.as_ref().unwrap()),
                Err(e) => error!("Error: {}", e),
            }
           Ok(())
        }
    }
}
