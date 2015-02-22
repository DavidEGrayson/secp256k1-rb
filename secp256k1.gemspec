require './lib/secp256k1/version'

Gem::Specification.new do |spec|
  spec.name          = 'secp256k1'
  spec.version       = Secp256k1::VERSION
  spec.authors       = ['Andy Alness', 'Micah Winkelspecht']
  spec.email         = ['hello@gem.co']
  spec.summary       = 'Wrapper for libsecp256k1.'
  spec.homepage      = ''
  spec.license       = 'MIT'

  spec.files         = Dir['lib/**/*.rb', 'README.md', 'LICENSE.txt']

  spec.add_dependency 'ffi'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'coveralls'
  spec.add_development_dependency 'ripl'
  spec.add_development_dependency 'rubocop', '0.29.1'
  spec.add_development_dependency 'yard'
end
