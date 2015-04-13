require 'secp256k1/version'
require 'secp256k1/foreign_library'
require 'secp256k1/context'
require 'secp256k1/argument'

# Main module for the gem.
#
# @api public
module Secp256k1
  # Calls the function pointed to by the `secp256k1_nonce_function_default`
  # pointer in libsecp256k1.  Most users should not need to call this method
  # directly.
  #
  # @param msg32 A 32-byte string holding the message hash.
  # @param seckey A 32-byte string holding the secret key.
  # @param attempt How many iterations we have tried to find a nonce.
  # @return A 32-byte nonce string or nil if nonce generation failed.
  def self.nonce_function_default(msg32, seckey, attempt = 0, data = nil)
    call_nonce_function ForeignLibrary.secp256k1_nonce_function_default,
      msg32, seckey, attempt, data
  end

  # Calls the function pointed to by the `secp256k1_nonce_function_rfc6979`
  # pointer in libsecp256k1.  Most users should not need to call this method
  # directly.
  #
  # @param msg32 A 32-byte string holding the message hash.
  # @param seckey A 32-byte string holding the secret key.
  # @param attempt How many iterations we have tried to find a nonce.
  # @return A 32-byte nonce string or nil if nonce generation failed.
  def self.nonce_function_rfc6979(msg32, seckey, attempt = 0, data = nil)
    call_nonce_function ForeignLibrary.secp256k1_nonce_function_rfc6979,
      msg32, seckey, attempt, data
  end

  private

  def self.call_nonce_function(function, msg32, seckey, attempt, data)
    nonce = Argument::NonceOut.new
    msg32 = Argument::MessageHash.new(msg32)
    seckey = Argument::SecretKeyIn.new(seckey)
    extra_entropy = Argument::ExtraEntropy.new(data)
    attempt = attempt.to_i

    result = function.call(
      nonce.pointer, msg32.string, seckey.string,
      attempt, extra_entropy.pointer)

    case result
    when 1 then nonce.value
    when 0 then nil
    else fail 'unexpected result'
    end
  end
end
