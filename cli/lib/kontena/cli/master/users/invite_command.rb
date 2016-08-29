require_relative '../../common'
require_relative 'roles/add_command'

module Kontena::Cli::Master::Users
  class InviteCommand < Kontena::Command
    include Kontena::Cli::Common

    parameter "EMAIL ...", "List of emails"

    option ['-r', '--roles'], '[ROLES]', 'Comma separated list of roles to assign to the invited users'

    def execute
      require_api_url
      token = require_token

      if self.roles
        roles = self.roles.split(',')
      else
        roles = []
      end

      email_list.each do |email|
        begin
          data = { email: email, response_type: 'invite' }
          response = client(token).post('/oauth2/authorize', data)
          puts "Invitation created for #{response['email']}".colorize(:green)
          puts "  * code:  #{response['invite_code']}"
          puts "  * link:  #{response['link']}"
          roles.each do |role|
            cmd = Kontena::Cli::Master::Users::Roles::AddCommand.new(
              self.invocation_path
            )
            cmd.run([role, email])
          end
        rescue
          puts "Failed to invite #{email}".colorize(:red)
          ENV["DEBUG"] && puts("#{$!} - #{$!.message} -- #{$!.backtrace}")
        end
      end
    end
  end
end
