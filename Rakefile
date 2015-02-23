require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

task default: :spec

desc 'Print TO''DO items'
task 'to''do' do
  sh 'grep -ni to''do -r lib spec console Gemfile Rakefile *.gemspec || echo none'
end

desc 'Generate documentation with YARD'
task 'doc' do
  sh 'yard'
end

desc 'Check style rules with rubocop'
task 'cop' do
  sh 'rubocop'
end
