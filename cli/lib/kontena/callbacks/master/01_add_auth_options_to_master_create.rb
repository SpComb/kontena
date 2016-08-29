require_relative '../../cli/master/auth_provider/config_command'

class AddAuthOptionsToMasterCreate < Kontena::Callback
  command_types master: :create

  def after_load
    command.class_eval do
      banner <<-EOB
      Note: You can use the options from master authentication provider configuration
      command to automatically configure the authentication provider settings
      after deployment. To get a list of the options use:
        kontena master auth-provider config --help
      EOB

      option ["--skip-auth-provider-config"], :flag, "Don't configure master auth provider"
    end

    Kontena::Cli::Master::AuthProvider::ConfigCommand.recognised_options.each do |opt|
      next if opt.switches.include?('--dump')
      next if opt.switches.include?('--help')
      command.class_eval do
        option opt.switches, opt.type, opt.description, hidden: true
      end
    end
  end
end
