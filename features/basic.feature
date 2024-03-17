Feature: Basic features

  Scenario: Display the version

    To display the version, just run `ghctl version`

    When I run `ghctl version`
    Then the output should contain:
    """
    ghctl version 0.3.3
    """
