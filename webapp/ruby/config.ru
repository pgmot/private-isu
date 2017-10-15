require 'rack/session/dalli'

require_relative './app.rb'

require 'dotenv'
Dotenv.load

if ENV['STACKPROF'] == '1'
  require 'stackprof'
  Dir.mkdir('/tmp/stackprof') unless File.exist?('/tmp/stackprof')
  use StackProf::Middleware, enabled: true,
    mode: :wall,
    interval: 1000,
    save_every: 5,
    path: '/tmp/stackprof'
end

run Isuconp::App
