# encoding: ascii-8bit

require 'ffi'
require 'securerandom'  # TODO: remove
require 'digest'  # TODO: remove

# Wraps libsecp256k1 (https://github.com/bitcoin/secp256k1)
module Secp256k1
  extend ::FFI::Library

  # This corresponds to secp256k1_nonce_function_t in secp256k1.h.
  callback :nonce_function, [:pointer, :pointer, :pointer, :uint, :pointer], :int

  ffi_lib 'secp256k1'
  attach_function :secp256k1_start, [:int], :void
  attach_function :secp256k1_stop, [], :void
  attach_function :secp256k1_ec_seckey_verify, [:pointer], :int
  attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer, :int], :int
  attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :nonce_function, :pointer], :int
  attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :int, :pointer, :int], :int
  attach_function :secp256k1_ecdsa_sign_compact, [:pointer, :pointer, :pointer, :nonce_function, :pointer, :pointer], :int
  attach_function :secp256k1_ecdsa_recover_compact, [:pointer, :pointer, :pointer, :pointer, :int, :int], :int

  SECP256K1_START_VERIFY = (1 << 0)
  SECP256K1_START_SIGN   = (1 << 1)

  def self.init
    return if @secp256k1_started
    secp256k1_start(SECP256K1_START_VERIFY | SECP256K1_START_SIGN)
    @secp256k1_started = true
  end

  def self.generate_key_pair(compressed=true)
    init

    while true do
      priv_key = SecureRandom.random_bytes(32)
      priv_key_buf = FFI::MemoryPointer.new(:uchar, 32)
      priv_key_buf.put_bytes(0, priv_key)
      break if secp256k1_ec_seckey_verify(priv_key_buf)
    end

    pub_key_buf = FFI::MemoryPointer.new(:uchar, 65)
    pub_key_size = FFI::MemoryPointer.new(:int)
    result = secp256k1_ec_pubkey_create(pub_key_buf, pub_key_size, priv_key_buf, compressed ? 1 : 0)
    raise "error creating pubkey" unless result

    [ priv_key, pub_key_buf.read_string(pub_key_size.read_int) ]
  end

  # TODO: rename to ecdsa_sign to be consistent with the library
  # TODO: add an argument for controlling the nonce generation
  # It should accept things like :default, :rfc6979, SecureRandom, Integer, and Proc
  def self.sign(data, priv_key)
    init

    hash = Digest::SHA256.digest Digest::SHA256.digest data
    hash_buf = FFI::MemoryPointer.new(:uchar, 32)
    hash_buf.put_bytes(0, hash)

    sig_buf = FFI::MemoryPointer.new(:uchar, 72)
    sig_size = FFI::MemoryPointer.new(:int)
    sig_size.write_int(72)

    priv_key_buf = FFI::MemoryPointer.new(:uchar, priv_key.bytesize)
    priv_key_buf.put_bytes(0, priv_key)

    nonce_proc = Proc.new do |nonce32, msg32, key32, attempt, data|
      nonce32.put_bytes(0, SecureRandom.random_bytes(32))
      1
    end

    result = secp256k1_ecdsa_sign(hash_buf, sig_buf, sig_size, priv_key, nonce_proc, nil)
    check_signing_result(result)

    sig_buf.read_string(sig_size.read_int)
  end

  def self.verify(data, signature, pub_key)
    init

    hash = Digest::SHA256.digest Digest::SHA256.digest data
    hash_buf = FFI::MemoryPointer.new(:uchar, 32)
    hash_buf.put_bytes(0, hash)

    sig_buf = FFI::MemoryPointer.new(:uchar, signature.bytesize)
    sig_buf.put_bytes(0, signature)

    pub_key_buf = FFI::MemoryPointer.new(:uchar, pub_key.bytesize)
    pub_key_buf.put_bytes(0, pub_key)

    result = secp256k1_ecdsa_verify(hash_buf,
                                    sig_buf, signature.bytesize,
                                    pub_key_buf, pub_key.bytesize)
    if result == -1
      raise "error invalid pubkey"
    elsif result == -2
      raise "error invalid signature"
    end

    result == 1
  end

  def self.sign_compact(data, priv_key, compressed=true)
    init

    hash = Digest::SHA256.digest Digest::SHA256.digest data
    hash_buf = FFI::MemoryPointer.new(:uchar, 32)
    hash_buf.put_bytes(0, hash)

    sig_buf = FFI::MemoryPointer.new(:uchar, 64)

    priv_key_buf = FFI::MemoryPointer.new(:uchar, priv_key.bytesize)
    priv_key_buf.put_bytes(0, priv_key)

    rec_id = FFI::MemoryPointer.new(:int)

    nonce_proc = Proc.new do |nonce32, msg32, key32, attempt, data|
      nonce32.put_bytes(0, SecureRandom.random_bytes(32))
      1
    end

    result = secp256k1_ecdsa_sign_compact(hash_buf, sig_buf, priv_key, nonce_proc, nil, rec_id)
    check_signing_result(result)

    header = [27 + rec_id.read_int + (compressed ? 4 : 0)].pack("C")
    [ header, sig_buf.read_string(64) ].join
  end

  def self.recover_compact(data, signature)
    init

    return nil if signature.bytesize != 65

    version = signature.unpack('C')[0]
    return nil if version < 27 || version > 34

    compressed = version >= 31 ? true : false
    version -= 4 if compressed
    rec_id = version - 27

    hash = Digest::SHA256.digest Digest::SHA256.digest data
    hash_buf = FFI::MemoryPointer.new(:uchar, 32)
    hash_buf.put_bytes(0, hash)

    signature[0] = ''
    sig_buf = FFI::MemoryPointer.new(:uchar, signature.bytesize)
    sig_buf.put_bytes(0, signature)

    pub_key_len = compressed ? 33 : 65
    pub_key_buf = FFI::MemoryPointer.new(:uchar, pub_key_len)
    pub_key_size = FFI::MemoryPointer.new(:int)
    pub_key_size.write_int(pub_key_len)

    result = secp256k1_ecdsa_recover_compact(hash_buf,
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
