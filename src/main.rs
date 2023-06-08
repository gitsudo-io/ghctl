mod commands;
mod ghctl;
mod github;
mod utils;

use clap::Parser;
use commands::Opts;

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    ghctl::cli(opts).await;
}
