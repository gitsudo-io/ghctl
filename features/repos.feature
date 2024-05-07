Feature: Repository management features

  Scenario: Fetch repository details as JSON

    Given a valid GITHUB_TOKEN is set
    When I run `ghctl repo get gitsudo-io/ghctl`
    Then the output should contain:
    """
      "id": 647928865
    """
    And the output should contain:
    """
      "name": "ghctl",
      "full_name": "gitsudo-io/ghctl",
    """
