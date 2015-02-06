require 'ffi'

module Secp256k1
  module Argument
    class MessageHash
      attr_reader :string

      def initialize(msg32)
        if !msg32.is_a?(String)
          raise ArgumentError, 'msg32 must be a string'
        end

        if msg32.bytesize != 32
          raise ArgumentError, 'msg32 must be 32 bytes long'
        end

        @string = msg32
      end
    end

    class NonceFunction
      attr_reader :func

      def initialize(noncefp)
        @func = case noncefp
                when Proc
                  wrapper_proc(noncefp)
                when :default, nil
                  ForeignLibrary.secp256k1_nonce_function_default
                when :rfc6979
                  ForeignLibrary.secp256k1_nonce_function_rfc6979
                else
                  raise ArgumentError, "invalid noncefp"
                end
      end

      private

      def wrapper_proc(noncefp)
        Proc.new do |nonce32, msg32, key32, attempt, data|
          nonce = noncefp.call(attempt)
          case nonce
          when nil
            0
          when String
            if nonce.bytesize != 32
              raise 'nonce must be 32 bytes long'
            end
            nonce32.put_bytes(0, nonce)
            1
          else
            raise 'nonce must be a string'
          end
        end
      end
    end

    class SecretKeyIn
      attr_reader :string

      def initialize(seckey)
        if !seckey.is_a?(String)
          raise ArgumentError, 'seckey must be a string'
        end

        if seckey.bytesize != 32
          raise ArgumentError, 'seckey must be 32 bytes long'
        end

        @string = seckey
      end
    end

    class SignatureOut
      attr_reader :pointer
      attr_reader :size_pointer

      def initialize
        @pointer = FFI::MemoryPointer.new(:uchar, ForeignLibrary::MAX_SIGNATURE_SIZE)
        @size_pointer = FFI::MemoryPointer.new(:int)
        @size_pointer.write_int(ForeignLibrary::MAX_SIGNATURE_SIZE)
      end

      def value
        @pointer.read_string(@size_pointer.read_int)
      end
    end
  end
end
