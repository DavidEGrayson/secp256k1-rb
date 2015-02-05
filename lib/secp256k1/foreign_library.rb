require 'ffi'

module Secp256k1
  module ForeignLibrary
    class SecretKeyConverter
      extend FFI::DataConverter
      native_type FFI::Type::BUFFER_IN

      def self.to_native(value, context)
        if !value.is_a?(String)
          raise ArgumentError, 'secret key argument must be a string'
        end

        # TODO: also make sure it is 32 bytes

        value
      end
    end

    extend FFI::Library

    SECP256K1_START_VERIFY = (1 << 0)
    SECP256K1_START_SIGN   = (1 << 1)

    MAX_SIGNATURE_SIZE = 72

    # This corresponds to secp256k1_nonce_function_t in secp256k1.h.
    callback :nonce_function, [:pointer, :pointer, :pointer, :uint, :pointer], :int

    ffi_lib 'secp256k1'

    msg32_type = :buffer_in
    ctx_const_type = :pointer
    ctx_type = :pointer
    flags_type = :int

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
                      :buffer_in,
                      :int,
                    ], :int

    attach_function :secp256k1_ecdsa_sign, [
                      ctx_const_type,
                      msg32_type,
                      :buffer_out,
                      :pointer,
                      SecretKeyConverter,
                      :nonce_function,
                      :pointer,
                    ], :int

    attach_function :secp256k1_ecdsa_sign_compact, [
                      ctx_const_type,
                      msg32_type,
                      :pointer,
                      SecretKeyConverter,
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
                      :buffer_in,
                    ], :int

    attach_function :secp256k1_ec_pubkey_verify, [
                      ctx_const_type,
                      :buffer_in,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_pubkey_create, [
                      ctx_const_type,
                      :buffer_out,
                      SecretKeyConverter,
                      :buffer_in,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_pubkey_decompress, [
                      ctx_const_type,
                      :buffer_inout,
                      :pointer,
                    ], :int

    attach_function :secp256k1_ec_privkey_export, [
                      ctx_const_type,
                      SecretKeyConverter,
                      :buffer_out,
                      :pointer,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_privkey_import, [
                      ctx_const_type,
                      :buffer_out,
                      :buffer_in,
                      :int,
                    ], :int

    attach_function :secp256k1_ec_privkey_tweak_add, [
                      ctx_const_type,
                      :buffer_inout,
                      :buffer_in,
                    ], :int

    attach_function :secp256k1_ec_pubkey_tweak_add, [
                      ctx_const_type,
                      :buffer_in,
                      :int,
                      :buffer_in,
                    ], :int

    attach_function :secp256k1_ec_privkey_tweak_mul, [
                      ctx_const_type,
                      :buffer_inout,
                      :buffer_in,
                    ], :int

    attach_function :secp256k1_ec_pubkey_tweak_mul, [
                      ctx_const_type,
                      :buffer_inout,
                      :int,
                      :buffer_in
                    ], :int
  end
end
