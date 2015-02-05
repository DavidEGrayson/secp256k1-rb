# This is the only file in the project that should know anything about
# FFI.

require 'ffi'

module Secp256k1
  module ForeignLibrary
    class Buffer32Converter
      extend FFI::DataConverter
      native_type FFI::Type::BUFFER_IN

      def self.to_native(value, context)
        if !value.is_a?(String)
          raise ArgumentError, 'argument must be a 32-byte string'
        end

        if value.bytesize != 32
          raise ArgumentError, 'argument must be 32 bytes long'
        end

        value
      end
    end

    class ContextPointerConverter
      extend FFI::DataConverter
      native_type FFI::Type::POINTER

      def self.from_native(value, context)
        destroyer = ForeignLibrary.method(:secp256k1_context_destroy)
        FFI::AutoPointer.new(value, destroyer)
      end
    end

    extend FFI::Library

    SECP256K1_START_VERIFY = (1 << 0)
    SECP256K1_START_SIGN   = (1 << 1)

    MAX_SIGNATURE_SIZE = 72

    # This corresponds to secp256k1_nonce_function_t in secp256k1.h.
    callback :nonce_function, [:pointer, :pointer, :pointer, :uint, :pointer], :int

    ffi_lib 'secp256k1'
    attach_function :secp256k1_context_create, [:int], ContextPointerConverter
    attach_function :secp256k1_context_destroy, [], :void
    attach_function :secp256k1_ecdsa_verify, [Buffer32Converter, :buffer_in, :int, :buffer_in, :int], :int
    attach_function :secp256k1_ecdsa_sign, [Buffer32Converter, :buffer_out, :pointer, :pointer, :nonce_function, :pointer], :int
    attach_function :secp256k1_ecdsa_sign_compact, [Buffer32Converter, :pointer, :pointer, :nonce_function, :pointer, :pointer], :int
    attach_function :secp256k1_ecdsa_recover_compact, [Buffer32Converter, :buffer_in, :buffer_out, :pointer, :int, :int], :int
    attach_function :secp256k1_ec_seckey_verify, [Buffer32Converter], :int
    attach_function :secp256k1_ec_pubkey_verify, [Buffer32Converter, :int], :int
    attach_function :secp256k1_ec_pubkey_create, [:buffer_out, :pointer, Buffer32Converter, :int], :int
    attach_function :secp256k1_ec_pubkey_decompress, [:buffer_inout, :pointer], :int
    attach_function :secp256k1_ec_privkey_export, [Buffer32Converter, :buffer_out, :pointer, :int], :int
    attach_function :secp256k1_ec_privkey_import, [:buffer_out, :buffer_in, :int], :int
    attach_function :secp256k1_ec_privkey_tweak_add, [:buffer_inout, :buffer_in], :int
    attach_function :secp256k1_ec_pubkey_tweak_add, [:buffer_in, :int, :buffer_in], :int
    attach_function :secp256k1_ec_privkey_tweak_mul, [:buffer_inout, :buffer_in], :int
    attach_function :secp256k1_ec_pubkey_tweak_mul, [:buffer_inout, :int, :buffer_in], :int
  end
end
