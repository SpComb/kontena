require 'uri'
require_relative '../localhost_web_server'
require 'launchy'

module Kontena::Cli::Master
  class AuthCommand < Kontena::Command
    include Kontena::Cli::Common

    require 'highline/import'

    parameter "[URL]", "Kontena Master URL or name."
    option ['-j', '--join'], '[INVITE_CODE]', "Join master using an invitation code"
    option ['-t', '--token'], '[TOKEN]', 'Use a pre-generated access token'
    option ['-n', '--name'], '[NAME]', 'Set server name'
    option ['-c', '--code'], '[CODE]', 'Use authorization code generated during master install'
    option ['-r', '--remote'], :flag, 'Do not try to open a browser'
    option ['-e', '--expires-in'], '[SECONDS]', 'Request token with expiration of X seconds. Use 0 to never expire', default: 7200

    def master_account
      @master_account ||= config.find_account('master')
    end

    def execute
      # Use current master from config if available
      unless self.url
        if config.current_master
          self.url = config.current_master.url
        else
          puts "Current master is not set and URL was not provided."
          exit 1
        end
      end

      unless self.url =~ /^(?:http|https):\/\//
        server = config.find_server(self.url)
        if server && server.url
          self.url = server.url
        else
          puts "Server '#{self.url}' not found in configuration."
          exit 1
        end
      end

      existing_server = config.find_server_by(url: self.url)
      
      if existing_server
        server = existing_server
      else
        server = Kontena::Cli::Config::Server.new(url: self.url, name: self.name)
        config.servers << server
      end

      if self.token
        # Use supplied token
        server.token = Kontena::Cli::Config::Token.new(access_token: self.token, parent_type: :master, parent_name: server.name)
      elsif server.token.nil?
        # Create new empty token if the server does not have one yet
        server.token = Kontena::Cli::Config::Token.new(parent_type: :master, parent_name: server.name)
      end


      # Exchange supplied code for an access token
      if self.code
        client = Kontena::Client.new(server.url)

        response = client.request(
          http_method: master_account.token_method.downcase.to_sym,
          path: master_account.token_endpoint,
          body: {
            grant_type: 'authorization_code',
            code: self.code,
            client_id: Kontena::Client::CLIENT_ID,
            client_secret: Kontena::Client::CLIENT_SECRET
          },
          auth: false
        )

        if response && response.kind_of?(Hash) && !response.has_key?('error')
          server.token.access_token = response['access_token']
          server.token.refresh_token = response['refresh_token']
          server.token.expires_at = response['expires_in'].to_i > 0 ? Time.now.utc.to_i + response['expires_in'].to_i : nil
          server.token.username = response['user']['name'] || response['user']['email']
          server.username = server.token.username
          server.name ||= response['server']['name'] if response['server']
        end
      end

      client = Kontena::Client.new(server.url, server.token)

      if server && server.token && server.token.access_token && !self.join
        # See if the existing or supplied authentication works without reauthenticating
        if client.authentication_ok?(master_account.userinfo_endpoint)
          config.current_master = server.name
          config.write
          display_logo
          display_login_info
          exit 0
        end
      end


      params = {}
      
      if self.remote?
        params[:redirect_uri] = "/code"
      else
        web_server = LocalhostWebServer.new
        params[:redirect_uri] = "http://localhost:#{web_server.port}/cb"
      end

      params[:invite_code]  = self.join if self.join
      params[:expires_in]   = self.expires_in

      client.request(
        http_method: :get,
        path: "/authenticate?" + URI.encode_www_form(params),
        expects: [501, 400, 302, 403],
        auth: false
      )

      response = client.last_response
      case response.status
      when 501
        puts "Authentication provider not configured"
        exit 1
      when 403
        puts "Invalid invitation code"
        exit 1
      when 302
        if self.remote?
          puts "Visit this URL in a browser:"
          puts "<#{response.headers['Location']}>"
          puts 
          puts "Then, to complete the authentication use:"
          puts "kontena master auth --code <CODE FROM BROWSER>"
          exit 1
        end

        uri = URI.parse(response.headers['Location'])
        puts "Opening browser to #{uri.scheme}://#{uri.host}"
        puts
        puts "If you are running this command over an ssh connection or it's"
        puts "otherwise not possible to open a browser from this terminal"
        puts "then you must use the --remote flag or use a pregenerated"
        puts "access token using the --token option."
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
          ENV["DEBUG"] && puts('Master responded with code, exchanging to token')
          response = client.request(
            http_method: :post,
            path: '/oauth2/token',
            body: {
              'grant_type' => 'authorization_code',
              'code' => response['code'],
              'client_id' => Kontena::Client::CLIENT_ID,
              'client_secret' => Kontena::Client::CLIENT_SECRET
            },
            expects: [201],
            auth: false
          )
          ENV["DEBUG"] && puts('Code exchanged')
        end

        if response && response.kind_of?(Hash) && response['access_token']
          server.token = Kontena::Cli::Config::Token.new
          server.token.access_token = response['access_token']
          server.token.refresh_token = response['refresh_token']
          server.token.expires_at = response['expires_in'].to_i > 0 ? Time.now.utc.to_i + response['expires_in'].to_i : nil
          server.token.username = response.fetch('user', {}).fetch('name', nil) || response.fetch('user', {}).fetch('email', nil)
          server.username = server.token.username
          if !server.name && response['server'] && response['server']['name']
            server.name = response['server']['name']
          else
            server.name ||= self.name || (config.find_server('default') ? "default-#{SecureRandom.hex(2)}" : "default")
          end
          config.current_master = server.name
          config.write
          display_logo
          display_login_info
          exit 0
        end
      else
        puts "Server error: #{response.body}".colorize(:red)
        exit 1
      end
    end
  end
end


