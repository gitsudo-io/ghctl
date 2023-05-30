use anyhow::Result;

use crate::ghctl;
use crate::ghctl::repo::RepoConfig;
use crate::commands::{RepoConfigCommand, RepoConfigSubcommand};

pub async fn handle_repo_config_commands(context: &ghctl::Context, repo_config: &RepoConfigCommand) -> Result<()> {

    match &repo_config.command {
        RepoConfigSubcommand::Get { repo_full_name } => {
            println!("Getting configuration for {}", repo_full_name.as_ref().unwrap());
        },
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