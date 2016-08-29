require_relative 'auth_provider/show_command'
require_relative 'auth_provider/config_command'

module Kontena
  module Cli
    module Master
      class AuthProviderCommand < Kontena::Command

        subcommand "show", "Display master authentication provider configuration", Kontena::Cli::Master::AuthProvider::ShowCommand
        subcommand "config", "Set master authentication provider configuration", Kontena::Cli::Master::AuthProvider::ConfigCommand

      end
    end
  end
end
