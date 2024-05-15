Feature: Basic features

  Scenario: Display the version

    To display the version, just run `ghctl version`

    When I run `ghctl version`
    Then the output should contain:
    """
    ghctl version 0.3.3
    """

  Scenario: Display help

    To display help, just run `ghctl` without any arguments.

    When I run `ghctl`
    Then the output should contain:
    """
    A tool for managing GitHub repository configuration

    Usage: ghctl [OPTIONS] <COMMAND>

    Commands:
      repo     Manage repository configuration
      version  Display the ghctl version
      help     Print this message or the help of the given subcommand(s)

    Options:
          --access-token <ACCESS_TOKEN>  GitHub access token
      -v, --verbose...                   More output per occurrence
      -q, --quiet...                     Less output per occurrence
      -h, --help                         Print help
      -V, --version                      Print version
    """
