class ListAndSelectGrid < Kontena::Callback

  include Kontena::Cli::Common

  command_types master: :auth

  # Runs kontena grids list --use which will auto join the first available
  # grid
  def after
    return unless current_master
    return unless command.exit_code == 0
    return unless current_master.grid.nil?

    Kontena.run('grid list --use --verbose')
  end
end
