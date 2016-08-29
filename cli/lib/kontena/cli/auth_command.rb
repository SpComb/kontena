class Kontena::Cli::AuthCommand < Kontena::Command
  include Kontena::Cli::Common

  option ['-t', '--token'], '[TOKEN]', 'Use a pre-generated access token'

  def execute
    if self.token.nil?
      token = kontena_account.token ||= Kontena::Cli::Config::Token.new(parent_type: :account, parent_name: ENV['KONTENA_ACCOUNT'] || 'kontena')
    else
      kontena_account.token = Kontena::Cli::Config::Token.new(access_token: self.token, parent_type: :account, parent_name: ENV['KONTENA_ACCOUNT'] || 'kontena')
    end

    client = Kontena::Client.new(kontena_account.url, kontena_account.token)

    if kontena_account.token.access_token
      if client.authentication_ok?(kontena_account.token.userinfo_endpoint)
        display_login_info
        display_logo
        exit 0
      end
    end

    uri = URI.parse(kontena_account.authorization_endpoint)
    uri.host ||= kontena_account.url

    web_server = LocalhostWebServer.new

    params = {
      client_id: kontena_account.client_id || Kontena::Client::CLIENT_ID,
      response_type: 'code',
      redirect_uri: "http://localhost:#{web_server.port}/cb"
    }

    uri.query = URI.encode_www_form(params)

    puts "Opening browser to #{uri.scheme}://#{uri.host}"
    puts
    puts "If you are running this command over an ssh connection or it's"
    puts "otherwise not possible to open a browser from this terminal"
    puts "then you must use a pregenerated access token using the --token"
    puts "option."
    puts
    puts "Once the authentication is complete you can close the browser"
    puts "window or tab and return to this window to continue."
    puts
    any_key_to_continue

    puts "If the browser does not open, try visiting this URL manually:"
    puts "<#{uri.to_s}>"
    puts

    server_thread  = Thread.new { Thread.main['response'] = web_server.serve_one }
    browser_thread = Thread.new { Launchy.open(uri.to_s) }
    
    server_thread.join
    browser_thread.join

    puts "The authentication flow was completed successfuly, welcome back!".colorize(:green)
    any_key_to_continue

    response = Thread.main['response']

    # If the master responds with a code, then exchange it to a token
    if response && response.kind_of?(Hash) && response['code']
      ENV["DEBUG"] && puts('Account responded with code, exchanging to token')
      response = client.exchange_code(response['code'])
    end

    if response && response.kind_of?(Hash) && response['access_token']
      kontena_account.token = Kontena::Cli::Config::Token.new
      kontena_account.token.access_token = response['access_token']
      kontena_account.token.refresh_token = response['refresh_token']
      kontena_account.token.expires_at = response['expires_in'].to_i > 0 ? Time.now.utc.to_i + response['expires_in'].to_i : nil
    else
      puts "Authentication failed".colorize(:red)
      exit 1
    end

    uri = URI.parse(kontena_account.userinfo_endpoint)
    path = uri.path
    uri.path = '/'

    client = Kontena::Client.new(uri.to_s, kontena_account.token)

    response = client.get(path) rescue nil
    if response && response.kind_of?(Hash)
      kontena_account.username = response['username']
      config.write
      display_logo
      display_login_info
      exit 0
    else
      puts "Authentication failed".colorize(:red)
      exit 1
    end
  end
end

