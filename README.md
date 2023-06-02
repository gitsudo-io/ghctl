ghctl - A GitHub utility
=====

[![Tests](https://github.com/gitsudo-io/ghctl/actions/workflows/tests.yml/badge.svg)](https://github.com/gitsudo-io/ghctl/workflows/tests.yml)


ghctl is both a command-line utility for GitHub, _and_ a GitHub Action that allows you to use the utility in your GitHub Actions workflows.

> NOTE: ghctl is in early development and is not yet ready for production use. However, please feel free to try it out and provide feedback!


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
curl -L https://github.com/gitsudo-io/ghctl/releases/download/v0.1.3/ghctl > ghctl
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


### Usage

#### Retrieve GitHub repository information

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


#### Apply a GitHub repository configuration to a repository

`ghctl repo apply "{owner}/{repo}" --config-file {config_file}` will read the specified YAML configuration file and apply it to the specified GitHub repository.

The configuration file should be a YAML file and currently supports the following sections:


##### Repository team permissions

```YAML
teams:
  {team-slug}: {permission}
```

Where `{team-slug}` is the team slug on GitHub, and `{permission}` is one of `pull`, `triage`, `push`, `maintain`, or `admin`.

**Example:**

```YAML
teams:
  a-team: maintain
```

When applied to a repository, will grant the `a-team` team `maintain` permissions on the repository.


##### Repository collaborators

```YAML
collaborators:
  {username}: {permission}
```

Where `{username}` is the GitHub username, and `{permission}` is one of `pull`, `triage`, `push`, `maintain`, or `admin`.

**Example:**

```YAML
collaborators:
  aisrael: admin
```

When applied to a repository, will grant the user `aisrael` `admin` permissions to the repository.


##### Full example

Given a `ghctl.yaml` file containing:

```YAML
teams:
  a-team: maintain
collaborators:
  aisrael: admin
```

When we execute:

```bash
$ ghctl repo config apply gitsudo-io/ghctl --access-token ${PERSONAL_ACCESS_TOKEN} -F ghctl.yaml
[2023-06-01T21:46:06Z INFO ] Added team a-team with permission Maintain to repository gitsudo-io/ghctl
[2023-06-01T21:46:06Z INFO ] Updated collaborator aisrael with permission admin to repository gitsudo-io/ghctl
[2023-06-01T21:46:06Z INFO ] Applied configuration to gitsudo-io/ghctl
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
            args: repo config apply gitsudo-io/ghctl --access-token ${{ secrets.GHCTL_ACCESS_TOKEN }} -F ghctl.yaml
```

Then executing the workflow above will perform the equivalent of the earlier command.
