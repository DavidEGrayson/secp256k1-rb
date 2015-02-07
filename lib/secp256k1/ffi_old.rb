# TODO: remove this file

# encoding: ascii-8bit

require 'ffi'
require 'securerandom'  # TODO: remove
require 'digest'  # TODO: remove

# Wraps libsecp256k1 (https://github.com/bitcoin/secp256k1)
module Secp256k1
  def self.recover_compact(data, signature)
    return nil if signature.bytesize != 65

    version = signature.unpack('C')[0]
    return nil if version < 27 || version > 34

    compressed = version >= 31 ? true : false
    version -= 4 if compressed
    rec_id = version - 27

    hash = Digest::SHA256.digest Digest::SHA256.digest data

    signature[0] = ''
    sig_buf = FFI::MemoryPointer.new(:uchar, signature.bytesize)
    sig_buf.put_bytes(0, signature)

    pub_key_len = compressed ? 33 : 65
    pub_key_buf = FFI::MemoryPointer.new(:uchar, pub_key_len)
    pub_key_size = FFI::MemoryPointer.new(:int)
    pub_key_size.write_int(pub_key_len)

    result = secp256k1_ecdsa_recover_compact(hash,
                                             sig_buf,
                                             pub_key_buf, pub_key_size,
                                             compressed ? 1 : 0,
                                             rec_id)
    return nil unless result

    pub_key_buf.read_bytes(pub_key_size.read_int)
  end

  private

  def self.check_signing_result(result)
    case result
    when 0 then raise "Nonce generation function failed."
    when 1 then
    else raise "Unexpected signing result code: #{result}"
    end
  end
end
