ghctl - A GitHub utility
=====

[![Tests](https://github.com/gitsudo-io/ghctl/actions/workflows/tests.yml/badge.svg)](https://github.com/gitsudo-io/ghctl/actions/workflows/tests.yml)


ghctl is both a command-line utility for GitHub, _and_ a GitHub Action that allows you to use the utility in your GitHub Actions workflows.

> NOTE: ghctl is in early development and is not quite ready for production use. However, please feel free to try it out and provide feedback!


## ghctl CLI

ghctl currently requires a GitHub Personal Access Token (PAT) with at least the following scopes:

  - `read:org`
  - `repo` (full control)
  - `read:user`

You can provide the access token to ghctl in one of the following ways:

  - set the `$GITHUB_TOKEN` environment variable
  - explicitly pass it using the `--access-token` option


### Download the latest release binary

You can download the latest release binary (built for Debian Bookworm / Ubuntu 22.04 ) from the [Releases](https://github.com/gitsudo-io/ghctl/releases) page, using the GitHub CLI (`gh`) or just `curl`:

```
gh release download -R gitsudo-io/ghctl --pattern ghctl
```

```
curl -L https://github.com/gitsudo-io/ghctl/releases/download/v0.3.1/ghctl > ghctl
```

Then make the file executable (`chmod u+x ghctl`) and place it in your `$PATH`.


### Install using Cargo

To install the `ghctl` binary using Cargo, you will need to have Rust 1.66.0 or later installed ([rustup](https://rustup.rs/)).

```bash
cargo install ghctl
```


### Local Development / Installation from source

To build and install the `ghctl` binary locally, you will need to have Rust 1.66.0 or later installed ([rustup](https://rustup.rs/)).

Clone this repository

```bash
git clone https://github.com/gitsudo-io/ghctl.git
```

Build and install the `ghctl` binary

```bash
cargo install --path ghctl
```


## Usage

### Retrieve GitHub repository information

`ghctl repo get "{owner}/{repo}"` will retrieve information about the specified GitHub repository and output it as JSON.

```bash
$ ghctl repo get gitsudo-io/ghctl --access-token $GITHUB_TOKEN
ghctl repo get gitsudo-io/ghctl
{
  "id": 647928865,
  "node_id": "R_kgDOJp6cIQ",
  "name": "ghctl",
  "full_name": "gitsudo-io/ghctl",
  "owner": {
    "login": "gitsudo-io",
    "id": 121780924,
...
```

### Retrieve a GitHub repository's configuration

`ghctl repo config get "{owner}/{repo}"` will retrieve the configuration for the specified GitHub repository and output it as YAML.

For example:

```
ghctl repo config get gitsudo-io/ghctl
```

Will output something like:

```yaml
teams:
  a-team: maintain
branch_protection_rules:
  main:
    require_pull_request:
      required_approving_review_count: 1
      dismiss_stale_reviews: false
      require_code_owner_reviews: false
    required_status_checks:
      strict: true
      contexts:
      - test
    enforce_admins: false
```

The output of `ghctl repo config get` is suitable for use with `ghctl repo config apply` (see below).

### Apply a GitHub repository configuration to a repository

`ghctl repo apply "{owner}/{repo}" --config-file {config_file}` will read the specified YAML configuration file and apply it to the specified GitHub repository.

The configuration file should be a YAML file and currently supports the following sections:


#### Repository team permissions

```yaml
teams:
  {team-slug}: {permission}
```

Where `{team-slug}` is the team slug on GitHub, and `{permission}` is one of `pull`, `triage`, `push`, `maintain`, or `admin`.

**Example:**

```yaml
teams:
  a-team: maintain
```

When applied to a repository, will grant the `a-team` team `maintain` permissions on the repository.


#### Repository collaborators

```yaml
collaborators:
  {username}: {permission}
```

Where `{username}` is the GitHub username, and `{permission}` is one of `pull`, `triage`, `push`, `maintain`, or `admin`.

**Example:**

```yaml
collaborators:
  aisrael: admin
```

#### Deployment Environments

```yaml
environments:
  {environment}:
    reviewers:
      - {username}, or
      - {org}/{team-slug}
```

Where `{environment}` is the name of the deployment environment, `{username}` is the GitHub username, or, if `{org}/{team-slug}` is given, then it references a GitHub organization and team.

**Example:**

```yaml
environments:
  gigalixir:
    reviewers:
      - aisrael
      - gitsudo-io/a-team
```

When applied to a repository, will create the deployment environment and configure its reviewers accordingly.

#### Branch Protection Rules

```yaml
branch_protection_rules:
  {branch name}:
    required_status_checks:
      contexts:
        - {status check name}
        - ...
    require_pull_request: true
```

Where `{branch name}` is the name of the branch to protect.

The `required_status_checks` is optional, and if given, will require the specified status checks to pass before allowing a branch to be merged. Specify any required status checks by name in the `contexts` list.

The `require_pull_request` is optional, and if given, will require all commits to be made via a pull request.

**Example:**

```yaml
branch_protection_rules:
  main:
    required_status_checks:
      contexts:
        - "mix/test"
        - "mix/credo"
    require_pull_request: true
```

When applied to a repositody, will protect the `main` branch and require a pull request before merging, and require the `mix/test` and `mix/credo` status checks to pass before allowing a branch to be merged.


#### Full example

Given a `gitsudo.yaml` file containing:

```yaml
teams:
  a-team: maintain
collaborators:
  aisrael: admin
environments:
  gigalixir:
    reviewers:
      - aisrael
      - gitsudo-io/a-team
branch_protection_rules:
  main:
    required_status_checks:
      contexts:
        - "mix/test"
    require_pull_request: true
```

When we execute:

```bash
ghctl repo config apply gitsudo-io/gitsudo --access-token ${GHCTL_ACCESS_TOKEN} -F gitsudo.yaml
```

Then we should see output similar to the following:

```
[2023-06-16T18:33:34Z INFO ] Added team a-team with permission Maintain to repository gitsudo-io/gitsudo
[2023-06-16T18:33:34Z INFO ] Updated collaborator aisrael with permission admin to repository gitsudo-io/gitsudo
[2023-06-16T18:33:34Z INFO ] Created deployment environment gigalixir in repository gitsudo-io/gitsudo
[2023-06-16T18:33:35Z INFO ] Applied branch protection rules to branch main in repository gitsudo-io/gitsudo
[2023-06-16T18:33:35Z INFO ] Applied configuration to gitsudo-io/gitsudo
```


## ghctl GitHub Action

GitHub Action for ghctl

## Inputs

| Name | Description       | Required | Default |
|------|-------------------|----------|---------|
| args | Program arguments | Required |         |

`gitsudo-io/ghctl` is also a GitHub Action that allows you to use the `ghctl` utility in your GitHub Actions workflows.

For example, given the following workflow:

```yaml
name: Configure ghctl repository
on:
  push:
  workflow_dispatch:

jobs:
  ghctl-repo-config-apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: gitsudo-io/ghctl@main
        with:
            args: repo config apply gitsudo-io/gitsudo --access-token ${{ secrets.GHCTL_ACCESS_TOKEN }} -F gitsudo.yaml
```

Then executing the workflow above will perform the equivalent of the earlier command.
