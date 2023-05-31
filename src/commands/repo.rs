use anyhow::Result;
use clap::{Args, Subcommand};

use crate::ghctl;
use crate::ghctl::repo::RepoConfig;

/// The `repo` subcommand
#[derive(Args, Debug)]
pub struct Repo {
    #[command(subcommand)]
    pub command: RepoCommands,
}

/// The `repo` subcommands
#[derive(Subcommand, Debug)]
pub enum RepoCommands {
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
    },
}

pub async fn handle_repo_command(context: &ghctl::Context, repo: &Repo) {
    match &repo.command {
        RepoCommands::Get { repo_name } => {
            let v: Vec<&str> = repo_name.as_ref().unwrap().split("/").collect();
            match crate::ghctl::repo::get_repo(&context.access_token, v[0], v[1]).await {
                Ok(repo) => println!("{}", serde_json::to_string_pretty(&repo).unwrap()),
                Err(e) => println!("Error: {}", e),
            }
        }

        RepoCommands::Config(repo_config) => {
            handle_repo_config_commands(&context, repo_config)
                .await
                .unwrap();
        }
    }
}

pub async fn handle_repo_config_commands(
    context: &ghctl::Context,
    repo_config: &RepoConfigCommand,
) -> Result<()> {
    match &repo_config.command {
        RepoConfigSubcommand::Get { repo_full_name } => {
            ghctl::repo::get_repo_config(&context, repo_full_name.as_ref().unwrap()).await?;
        }
        RepoConfigSubcommand::Apply { repo_full_name } => {
            let v: Vec<&str> = repo_full_name.as_ref().unwrap().split("/").collect();
            match ghctl::repo::get_repo(&context.access_token, v[0], v[1]).await {
                Ok(repo) => {
                    let config = RepoConfig::new();
                    match config
                        .apply(
                            context.access_token.clone(),
                            repo.owner.unwrap().login,
                            repo.name,
                        )
                        .await
                    {
                        Ok(_) => println!("Applied configuration"),
                        Err(e) => println!("Error: {}", e),
                    }
                }
                Err(e) => println!("Error: {}", e),
            }
        }
    }

    Ok(())
}
