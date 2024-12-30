Feature: Repository management features

  Scenario: Fetch repository configuration as YAML

    Given a valid GITHUB_TOKEN is set
    When the following command is run:
      ```
      ghctl repo config get gitsudo-io/ghctl
      ```
    Then the output YAML should be:
      ```
      teams:
        a-team: maintain
      branch_protection_rules:
        main:
          require_pull_request:
            required_approving_review_count: 1
            dismiss_stale_reviews: false
            require_code_owner_reviews: false
          enforce_admins: false
      ```
