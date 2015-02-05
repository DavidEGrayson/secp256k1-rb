# TODO: remove this file

# encoding: ascii-8bit

require 'ffi'
require 'securerandom'  # TODO: remove
require 'digest'  # TODO: remove

# Wraps libsecp256k1 (https://github.com/bitcoin/secp256k1)
module Secp256k1

  def self.ecdsa_sign(msg32, seckey, nonce_spec)
    # TODO: more options for controlling the nonce generation
    # It should accept things like :default, :rfc6979, SecureRandom, Integer, and Proc
    # TODO: better argument checking

    case nonce_spec
    when String
      # TODO: if nonce_spec.bytesize != 32
      #  raise ArgumentError, "String nonces must be 32 bytes long."
      # end
      nonce_proc = Proc.new do |nonce32, msg32, key32, attempt, data|
        nonce32.put_bytes(0, nonce_spec)
        1
      end
    else
      raise ArgumentError, "Invalid nonce specification."
    end

    sig_buf = FFI::MemoryPointer.new(:uchar, MAX_SIGNATURE_SIZE)
    sig_size = FFI::MemoryPointer.new(:int)
    sig_size.write_int(MAX_SIGNATURE_SIZE)

    result = secp256k1_ecdsa_sign(msg32, sig_buf, sig_size, seckey, nonce_proc, nil)

    # TODO: check_signing_result(result)

    sig_buf.read_string(sig_size.read_int)
  end

  def self.ecdsa_verify(msg32, sig, pubkey)
    # TODO: better argument checking
    secp256k1_ecdsa_verify(msg32, sig, sig.bytesize, pubkey, pubkey.bytesize)
  end

  def self.generate_key_pair(compressed=true)
    while true do
      priv_key = SecureRandom.random_bytes(32)
      break if secp256k1_ec_seckey_verify(priv_key)
    end

    pub_key_buf = FFI::MemoryPointer.new(:uchar, 65)
    pub_key_size = FFI::MemoryPointer.new(:int)
    result = secp256k1_ec_pubkey_create(pub_key_buf, pub_key_size, priv_key, compressed ? 1 : 0)
    raise "error creating pubkey" unless result

    [ priv_key, pub_key_buf.read_string(pub_key_size.read_int) ]
  end

  def self.sign_compact(data, priv_key, compressed=true)
    hash = Digest::SHA256.digest Digest::SHA256.digest data

    sig_buf = FFI::MemoryPointer.new(:uchar, 64)

    priv_key_buf = FFI::MemoryPointer.new(:uchar, priv_key.bytesize)
    priv_key_buf.put_bytes(0, priv_key)

    rec_id = FFI::MemoryPointer.new(:int)

    nonce_proc = Proc.new do |nonce32, msg32, key32, attempt, data|
      nonce32.put_bytes(0, SecureRandom.random_bytes(32))
      1
    end

    result = secp256k1_ecdsa_sign_compact(hash, sig_buf, priv_key, nonce_proc, nil, rec_id)
    check_signing_result(result)

    header = [27 + rec_id.read_int + (compressed ? 4 : 0)].pack("C")
    [ header, sig_buf.read_string(64) ].join
  end

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
