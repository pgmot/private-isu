require_relative './app.rb'

require 'dotenv'
Dotenv.load

if ENV['STACKPROF'] == '1'
  require 'stackprof'
  Dir.mkdir('/tmp/stackprof') unless File.exist?('/tmp/stackprof')
  use StackProf::Middleware, enabled: true,
    mode: :wall,
    interval: 100,
    save_every: 1,
    path: '/tmp/stackprof'
end

if ENV['SQLLOG'] == '1'
  require "mysql2/client/general_log"
end


run Isuconp::App
