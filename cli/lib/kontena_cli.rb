module Kontena
  # Run a kontena command like it was launched from the command line.
  # 
  # @example
  #   Kontena.run("grid list --help")
  #
  # @param [String] command_line 
  # @return [Fixnum] exit_code
  def self.run(cmdline = "")
    Kontena::MainCommand.new(File.basename(__FILE__)).run(cmdline.shellsplit)
    0
  rescue SystemExit
    $!.status
  end

  def self.version
    "kontena-cli/#{Kontena::Cli::VERSION}"
  end
end

require 'ruby_dig'
require_relative 'kontena/cli/version'
require_relative 'kontena/cli/common'
require_relative 'kontena/command'
require_relative 'kontena/client'
require_relative 'kontena/plugin_manager'
require_relative 'kontena/main_command'

