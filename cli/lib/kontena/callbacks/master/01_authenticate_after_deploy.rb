require_relative '../../cli/common'

class AuthenticateAfterDeploy < Kontena::Callback

  include Kontena::Cli::Common

  command_types master: :create

  def after
    return unless command.exit_code == 0
    return unless command.result.kind_of?(Hash)
    return unless command.result.has_key?(:public_ip)
    return unless command.result.has_key?(:code)
    return unless command.result.has_key?(:name)

    # In case there already is a server with the same name add random characters to name
    if config.find_server(command.result[:name])
      command.result[:name] = "#{command.result[:name]}-#{SecureRandom.hex(2)}"
    end

    new_master = Kontena::Cli::Config::Server.new(
      url: "https://#{command.result[:public_ip]}",
      name: command.result[:name]
    )

    retried = false

    # Figure out if HTTPS works, if not, try HTTP
    begin
      client = Kontena::Client.new(new_master.url, nil, ignore_ssl_errors: true)
      client.get('/')
    rescue
      unless retried
        new_master.url = "http://#{command.result[:public_ip]}"
        retried = true
        retry
      end
      return
    end

    Kontena.run("master auth --name #{command.result[:name].shellescape} --code #{command.result[:code].shellescape} #{new_master.url.shellescape}")
  end
end
