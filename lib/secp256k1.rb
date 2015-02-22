require 'secp256k1/version'
require 'secp256k1/foreign_library'
require 'secp256k1/context'
require 'secp256k1/argument'

# This the main module of the gem.  Everything lives inside this module.
module Secp256k1
  def self.nonce_function_default(msg32, seckey, attempt = 0)
    call_nonce_function ForeignLibrary.secp256k1_nonce_function_default,
      msg32, seckey, attempt
  end

  def self.nonce_function_rfc6979(msg32, seckey, attempt = 0)
    call_nonce_function ForeignLibrary.secp256k1_nonce_function_rfc6979,
      msg32, seckey, attempt
  end

  private

  def self.call_nonce_function(function, msg32, seckey, attempt)
    nonce = Argument::NonceOut.new
    msg32 = Argument::MessageHash.new(msg32)
    seckey = Argument::SecretKeyIn.new(seckey)
    attempt = attempt.to_i

    result = function.call(nonce.pointer, msg32.string, seckey.string, attempt, nil)

    case result
    when 1 then nonce.value
    when 0 then nil
    else fail 'unexpected result'
    end
  end
end
