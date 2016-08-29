require_relative '../../cli/master/auth_provider/config_command'

# Runs kontena master auth-provider config after deployment if
# auth provider configuration options have been supplied.
#
# Runs the config command with --preset kontena if the user has
# authenticated to Kontena unless --no-auth-config is used.
class ConfigureAuthProviderAfterDeploy < Kontena::Callback

  include Kontena::Cli::Common

  command_types master: :create

  def after
    return if command.skip_auth_provider_config?
    return unless command.exit_code == 0
    return unless command.result.kind_of?(Hash)
    return unless command.result.has_key?(:name)
    return unless config.current_master
    return unless config.current_master.name == command.result[:name]

    auth_params = []

    Kontena::Cli::Master::AuthProvider::ConfigCommand.recognised_options.each do |opt|
      next if opt.switches.include?('--dump')
      next if opt.switches.include?('--help')
      unless command.send(opt.attribute_name).nil?
        auth_params << "#{opt.switches.first} #{command.send(opt.attribute_name)}"
      end
    end

    kontena_account = config.find_account('kontena')

    if auth_params.empty? && kontena_account && kontena_account.token
      auth_params << "--auth-preset kontena"
    end

    unless auth_params.empty?
      ShellSpinner "* Configuring master authentication provider" do
        Kontena.run("master auth-provider config #{auth_params.join(' ')}")
      end
    end
  end
end
