# frozen_string_literal: true

# This file is used to set up the environment for the tests.

# Set the GITHUB_TOKEN from the environment variable CUCUMBER_GITHUB_TOKEN
# This is necessary to run the tests in GitHub Actions which does _not_ allow
# environments variables starting with `GITHUB_`.
Given(/a valid GITHUB_TOKEN is set/) do
  raise 'No GITHUB_TOKEN or CUCUMBER_GITHUB_TOKEN environment variable set!' unless ENV['GITHUB_TOKEN']
end
