///! This module defines the commands, subcommands, and arguments for ghctl.
pub mod repo;

use clap::{Parser, Subcommand};
use repo::Repo;

/// The top level clap parser and CLI arguments
#[derive(Parser, Debug)]
#[command(name = "ghctl")]
#[command(author = "Alistair Israel <aisrael@gmail.com>")]
#[command(version = clap::crate_version!())]
#[command(about = "A tool for managing GitHub repository configuration")]
pub struct Opts {
    #[arg(long = "access-token", global = true, help = "GitHub access token")]
    pub access_token: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

/// The top-level commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Manage repository configuration")]
    Repo(Repo),
}
