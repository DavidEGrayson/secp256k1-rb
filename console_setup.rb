$LOAD_PATH << 'lib'
require 'secp256k1'
C = Secp256k1::Context.new(sign: true, verify: true)

require_relative 'spec/hex_inspect'
