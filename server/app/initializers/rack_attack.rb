require 'rack/attack'

class Rack::Attack
  MIN_VERSION     = Gem::Version.new('0.15.0').freeze
  CLI_APPLICATION = 'kontena-cli'.freeze
  LOCALHOSTS      = ['127.0.0.1'.freeze, '::1'.freeze].freeze

  safelist('allow from localhost') do |req|
    LOCALHOSTS.include?(req.ip)
  end

  blocklist('block old kontena CLIs') do |req|
    application, version = req.user_agent.to_s.split('/'.freeze)
    application.eql?(CLI_APPLICATION) && Gem::Version.new(version) < MIN_VERSION
  end

  blocklisted_response = lambda do |env|
		msg = "{ \"error\": \"Client upgrade required. Minimum version for this server is #{MIN_VERSION.to_s}. Use: gem install kontena-cli - if your server was recently upgraded, you may also need to reconfigure the authentication provider settings. After upgrading your client see kontena master auth-provider config --help\" }"
		response = [
			400,
			{
				'Content-Type'   => 'application/json',
				'Content-Length' => msg.bytesize.to_s
			},
			[msg]
		]
  end

  # Allow 1 req / second to oauth token endpoint and authenticate endpoint
  # which can be easier to brute force since there are shorter tokens in use.
  # (authorization and invite codes are short, other tokens are long enough to
  # be safe from brute forcing)
  #
  # Requests to other endpoints are unlimited
  throttle('auth/ip', limit: 60, period: 1.minute) do |req|
    if req.path.start_with?('/oauth2/token') || req.path.start_with?('/authenticate')
      req.ip
    else
      false
    end
  end

  throttled_response = lambda do |env|
    now = Time.now
    match_data = env['rack.attack.match_data']

    headers = {
      'X-RateLimit-Limit' => match_data[:limit].to_s,
      'X-RateLimit-Remaining' => '0',
      'X-RateLimit-Reset' => (now + (match_data[:period] - now.to_i % match_data[:period])).to_s,
      'Content-Type' => 'application/json'
    }

    [ 429, headers, ["{ \"error\": \"too_many_requests\" }"] ]
  end
end
