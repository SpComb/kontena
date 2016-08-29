class SuggestInvitingYourself < Kontena::Callback

  include Kontena::Cli::Common

  command_types master: :create

  def after
    return unless current_master
    return unless command.exit_code == 0
    return unless current_master.username.to_s == 'admin'

    puts
    puts "Protip:"
    puts "  You are currently using Kontena Master administrator account."
    puts "  Consider inviting yourself as a regular user and using the"
    puts "  returned invite code to authenticate. Use:"
    puts "    kontena master users invite your@email.address.example.com"
    puts "    kontena auth master --join <invite_code>"
    puts
  end
end
