use core::panic;
use cucumber::{gherkin::Step, given, then, when, World};
use log::{debug, info};
use std::process::Command;

#[derive(Debug, Default, World)]
pub struct CliWorld {
    command_output: Option<String>,
    command_stderr: Option<String>,
}

#[given(regex = "a valid GITHUB_TOKEN is set")]
async fn a_valid_github_token_is_set(_world: &mut CliWorld) {
    assert!(std::env::vars().any(|(key, _)| key == "GITHUB_TOKEN"),
"No GITHUB_TOKEN environment variable found. Please set a valid GITHUB_TOKEN environment variable to run the tests.");
}

#[when(regex = "the following command is run:")]
async fn run_command(world: &mut CliWorld, step: &Step) {
    let raw_command = step.docstring().unwrap();
    let parts = raw_command.split_whitespace().collect::<Vec<&str>>();
    assert!(!parts.is_empty(), "No command provided");
    let mut args: Vec<&str> = parts[1..].to_vec();
    let executable = if parts[0] == "ghctl" {
        args.insert(0, "--");
        args.insert(0, "run");
        "cargo"
    } else {
        parts[0]
    };

    match Command::new(executable).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8(output.stdout).unwrap();
            world.command_output = Some(stdout);
            let stderr = String::from_utf8(output.stderr).unwrap();
            world.command_stderr = Some(stderr);
        }
        Err(e) => {
            panic!("Failed to run command: {}", e);
        }
    }
}

#[given(expr = r#"a file named `{word}` containing:"#)]
async fn a_file_containing(_world: &mut CliWorld, filename: String, step: &Step) {
    debug!("filename: {:?}", filename);
    let file_content = step.docstring().unwrap();
    debug!("file_content: {:?}", file_content);
}

#[then(expr = "it should exit with status code {int}")]
async fn it_should_exit_with_status(_world: &mut CliWorld, status: i32) {
    debug!("status: {:?}", status);
}

#[then(expr = "it should output:")]
async fn it_should_output(world: &mut CliWorld, step: &Step) {
    assert!(world.command_output.is_some());
    // For some reason, the output docstring has a leading newline
    let expected_output = step.docstring().unwrap().strip_prefix('\n').unwrap();
    let actual_output = world.command_output.as_ref().unwrap();
    assert_eq!(expected_output, actual_output);
}

#[then(expr = "the output should contain:")]
async fn the_output_should_contain(world: &mut CliWorld, step: &Step) {
    assert!(world.command_output.is_some());
    // For some reason, the output docstring has a leading newline
    let docstring = step.docstring().unwrap();
    let expected_output = docstring.strip_prefix('\n').unwrap();
    let actual_output = world.command_output.as_ref().unwrap();
    assert!(actual_output.contains(expected_output));
}

#[then(expr = "the output YAML should be:")]
async fn the_output_should_contain_yaml(world: &mut CliWorld, step: &Step) {
    assert!(world.command_output.is_some());
    // For some reason, the output docstring has a leading newline
    let docstring = step.docstring().unwrap();
    let trimmed_docstring = docstring.strip_prefix('\n').unwrap();
    let expected_output_as_yaml: serde_yaml::Value = serde_yaml::from_str(trimmed_docstring).unwrap();
    let expected_output = serde_yaml::to_string(&expected_output_as_yaml).unwrap();
    let command_output = world.command_output.as_ref().unwrap();
    let actual_output_as_yaml: serde_yaml::Value = serde_yaml::from_str(command_output).unwrap();
    let actual_output = serde_yaml::to_string(&actual_output_as_yaml).unwrap();
    assert_eq!(expected_output, actual_output);
}

#[then(expr = "stderr should contain:")]
async fn stderr_should_contain(world: &mut CliWorld, step: &Step) {
    assert!(world.command_stderr.is_some());
    // For some reason, the output docstring has a leading newline
    let expected_stderr = step.docstring().unwrap().strip_prefix('\n').unwrap();
    let actual_stderr = world.command_stderr.as_ref().unwrap();
    assert!(actual_stderr.contains(expected_stderr));
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .format_target(false)
        .format_timestamp_secs()
        .target(env_logger::Target::Stdout)
        .init();
    info!("cargo build --release");
    Command::new("cargo")
        .args(&["build", "--release"])
        .status()
        .expect("Failed to build");
    let path = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("target/release;{}", path));
    info!("Running CLI tests");

    CliWorld::run("features/cli.feature").await;
    CliWorld::run("features/repos.feature").await;
    CliWorld::run("features/config.feature").await;
}
