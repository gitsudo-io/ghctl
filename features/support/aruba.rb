# frozen_string_literal: true

require 'aruba/cucumber'

BASEDIR = File.expand_path('../../', __dir__)

Aruba.configure do |config|
  config.command_runtime_environment = {
    'PATH' => "#{File.join(BASEDIR, 'target', 'release')}:#{ENV['PATH']}"
  }
end

Before do
  Dir.chdir(BASEDIR) do
    `cargo build --release`
  end
end
