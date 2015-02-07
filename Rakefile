require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

task :default => :spec

desc 'Start irb session with this library and a context preloaded'
task :console do
  exec 'irb -r./console_setup'
end
