require 'ffi'

module Secp256k1
  module ForeignLibrary
    extend FFI::Library

    SECP256K1_START_VERIFY = (1 << 0)
    SECP256K1_START_SIGN   = (1 << 1)

    MAX_SIGNATURE_LENGTH = 72
    COMPACT_SIGNATURE_LENGTH = 64

    VALID_PUBKEY_LENGTHS = [33, 65]
    MAX_PUBKEY_LENGTH = VALID_PUBKEY_LENGTHS.max

    MAX_PRIVKEY_DER_LENGTH = 300  # just a guess; not documented in secp256k1.h

    ffi_lib 'secp256k1'

    lib = ffi_libraries.first

    # This corresponds to secp256k1_nonce_function_t in secp256k1.h.
    nonce_function_args = [:pointer, :pointer, :pointer, :uint, :pointer]
    callback :nonce_function, nonce_function_args, :int

    pointer = lib.find_variable('secp256k1_nonce_function_default').read_pointer
    @nonce_function_default = FFI::Function.new(:int, nonce_function_args, pointer)

    pointer = lib.find_variable('secp256k1_nonce_function_rfc6979').read_pointer
    @nonce_function_rfc6979 = FFI::Function.new(:int, nonce_function_args, pointer)

    def self.secp256k1_nonce_function_default
      @nonce_function_default
    end

    def self.secp256k1_nonce_function_rfc6979
      @nonce_function_rfc6979
    end

    msg32_type = :buffer_in
    ctx_const_type = :pointer
    ctx_type = :pointer
    flags_type = :int
    seckey_const_type = :buffer_in
    seckey_type = :pointer

    attach_function :secp256k1_context_create, [
                      flags_type,
                    ], ctx_type

    attach_function :secp256k1_context_initialize_sign, [
                      ctx_type,
                    ], :void

    attach_function :secp256k1_context_initialize_verify, [
                      ctx_type,
                    ], :void

    attach_function :secp256k1_context_destroy, [
                      ctx_type,
                    ], :void

    attach_function :secp256k1_ecdsa_verify, [
                      ctx_const_type,
                      msg32_type,
                      :buffer_in,
                      :int,
                      seckey_const_type,
                      :int,
                    ], :int

    attach_function :secp256k1_ecdsa_sign, [
                      ctx_const_type,
                      msg32_type,
                      :buffer_out,
                      :pointer,
                      seckey_const_type,
                      :nonce_function,
                      :pointer,
                    ], :int

    attach_function :secp256k1_ecdsa_sign_compact, [
                      ctx_const_type,
                      msg32_type,
                      :pointer,
                      seckey_const_type,
                      :nonce_function,
                      :pointer,
                      :pointer
                    ], :int

    attach_function :secp256k1_ecdsa_recover_compact, [
                      ctx_const_type,
                      msg32_type,
                      :buffer_in,
                      :buffer_out,
                      :pointer,
                      :int,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_seckey_verify, [
                      ctx_const_type,
                      seckey_const_type,
                    ], :int

    attach_function :secp256k1_ec_pubkey_verify, [
                      ctx_const_type,
                      :buffer_in,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_pubkey_create, [
                      ctx_const_type,
                      :buffer_out,
                      :pointer,
                      seckey_const_type,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_pubkey_decompress, [
                      ctx_const_type,
                      :buffer_inout,
                      :pointer,
                    ], :int

    attach_function :secp256k1_ec_privkey_export, [
                      ctx_const_type,
                      seckey_const_type,
                      :buffer_out,
                      :pointer,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_privkey_import, [
                      ctx_const_type,
                      seckey_type,
                      :buffer_in,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_privkey_tweak_add, [
                      ctx_const_type,
                      seckey_type,
                      :buffer_in,
                    ], :int

    attach_function :secp256k1_ec_pubkey_tweak_add, [
                      ctx_const_type,
                      seckey_type,
                      :int,
                      :buffer_in,
                    ], :int

    attach_function :secp256k1_ec_privkey_tweak_mul, [
                      ctx_const_type,
                      :pointer,
                      :buffer_in,
                    ], :int

    attach_function :secp256k1_ec_pubkey_tweak_mul, [
                      ctx_const_type,
                      :pointer,
                      :int,
                      :buffer_in
                    ], :int
  end
end
