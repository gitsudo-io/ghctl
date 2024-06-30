Feature: Repository management features

  Scenario: Fetch repository details as JSON

    Given a valid GITHUB_TOKEN is set
    When the following command is run:
      ```
      ghctl repo get gitsudo-io/ghctl
      ```
    Then the output should contain:
      ```
        "id": 647928865,
      ```
    And the output should contain:
      ```
        "name": "ghctl",
      ```
    And the output should contain:
      ```
        "full_name": "gitsudo-io/ghctl",
      ```
