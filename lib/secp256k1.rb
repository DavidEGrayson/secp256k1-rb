require 'secp256k1/version'
require 'secp256k1/foreign_library'
require 'secp256k1/context'
require 'secp256k1/argument'

module Secp256k1
  def self.nonce_function_default(msg32, seckey, attempt = 0)
    nonce = Argument::NonceOut.new
    msg32 = Argument::MessageHash.new(msg32)
    seckey = Argument::SecretKeyIn.new(seckey)
    attempt = attempt.to_i

    result = ForeignLibrary.secp256k1_nonce_function_default.call(
      nonce.pointer, msg32.string, seckey.string, attempt, nil)

    # TODO: check result

    nonce.value
  end
end
