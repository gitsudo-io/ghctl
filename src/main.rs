mod commands;
mod ghctl;

use clap::Parser;
use commands::Opts;

fn main() {
    let opts = Opts::parse();
    ghctl::cli(opts);
}
