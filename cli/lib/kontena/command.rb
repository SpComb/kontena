require 'clamp'

class Kontena::Command < Clamp::Command

  attr_accessor :arguments
  attr_reader :result
  attr_reader :exit_code


  def self.inherited(where)
    return if where.has_subcommands?

    name_parts = where.name.split('::')[-2, 2]

    unless name_parts.nil?
      # 1: Remove trailing 'Command' from for example AuthCommand
      # 2: Convert the string from CamelCase to under_score
      # 3: Convert the string into a symbol
      #
      # In comes: ['ExternalRegistry', 'UseCommand']
      # Out goes: [:external_registry, :use]
      name_parts = name_parts.map { |np|
        np.gsub(/Command$/, '').
        gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').
        gsub(/([a-z\d])([A-Z])/,'\1_\2').
        tr("-", "_").
        downcase.
        to_sym
      }
      where.command_type(*name_parts)
    end

    # Run all #after_load callbacks for this command.
    [name_parts.last, :all].compact.uniq.each do |cmd_type|
      [name_parts.first, :all].compact.uniq.each do |cmd_class|
        if Kontena::Callback.callbacks.fetch(cmd_class, {}).fetch(cmd_type, nil)
          Kontena::Callback.callbacks[cmd_class][cmd_type].each do |cb|
            if cb.instance_methods.include?(:after_load)
              cb.new(where).after_load
            end
          end
        end
      end
    end
  end

  def self.command_type(cmd_class = nil, cmd_type = nil)
    unless cmd_class
      return nil unless @command_class
      return [@command_class, @command_type]
    end
    @command_class = cmd_class
    @command_type = cmd_type
    [@command_class, @command_type]
  end

  def run_callbacks(state)
    if self.class.respond_to?(:command_type) && !self.class.command_type.nil?
      Kontena::Callback.run_callbacks(self.class.command_type, state, self)
    end
  end

  # Overwrite Clamp's banner command. Calling banner multiple times 
  # will now add lines to the banner message instead of overwriting
  # the whole message. This is useful if callbacks add banner messages.
  #
  # @param [String] message
  def self.banner(msg)
    self.description = [self.description, msg].compact.join("\n")
  end

  def run(arguments)
    ENV["DEBUG"] && puts("Running #{self} -- callback command type = #{Hash[self.class.command_type.first, self.class.command_type.last]}")
    @arguments = arguments
    run_callbacks :before_parse
    parse @arguments
    run_callbacks :before
    begin
      @result = execute
      @exit_code = @result.kind_of?(FalseClass) ? 1 : 0
    rescue SystemExit => exc
      @result = exc.status == 0
      @exit_code = exc.status
    end
    run_callbacks :after
    exit(@exit_code) if @exit_code.to_i > 0
  end
end

require_relative 'callback'
