require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

task :default => :spec

task "to""do" do
  sh "grep -ni to""do -r . || echo none"
end
