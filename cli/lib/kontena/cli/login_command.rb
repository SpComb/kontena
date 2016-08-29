class Kontena::Cli::LoginCommand < Kontena::Command
  include Kontena::Cli::Common

  parameter "URL", "url"

  banner "Command removed, use 'kontena auth' to authenticate to a Kontena Cloud account\nor 'kontena master auth' to authenticate to a Kontena Master"

  def execute
    abort("Command removed. Use #{"kontena master auth #{self.url}".colorize(:yellow)} to login to a Kontena Master")
  end
end
