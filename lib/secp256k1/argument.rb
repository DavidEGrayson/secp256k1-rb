require 'ffi'

module Secp256k1
  module Argument
    class StringIn
      attr_reader :string

      def initialize(string, name, opts={})
        if !string.is_a?(String)
          raise ArgumentError, "#{name} must be a string"
        end

        if opts[:length] && string.bytesize != opts[:length]
          raise ArgumentError, "#{name} must be 32 bytes long"
        end

        @string = string
        @name = name
      end

      def length
        @string.length
      end
    end

    class MessageHash < StringIn
      def initialize(msg32)
        super msg32, :msg32, length: 32
      end
    end

    class SecretKeyIn < StringIn
      def initialize(seckey)
        super seckey, :seckey, length: ForeignLibrary::SECRET_KEY_LENGTH
      end
    end

    class SignatureIn < StringIn
      def initialize(sig)
        super sig, :sig
      end
    end

    class PublicKeyIn < StringIn
      def initialize(pubkey)
        super pubkey, :pubkey
      end
    end

    class SignatureCompactIn < StringIn
      def initialize(sig64)
        super sig64, :sig64, length: 64
      end
    end

    class PrivateKeyDerIn < StringIn
      def initialize(privkey)
        super privkey, :privkey
      end
    end

    class VarStringOut
      attr_reader :pointer
      attr_reader :size_pointer

      def initialize(max_length)
        @pointer = FFI::MemoryPointer.new(:uchar, max_length)
        @size_pointer = FFI::MemoryPointer.new(:int)
        @size_pointer.write_int(max_length)
      end

      def value
        @pointer.read_string(@size_pointer.read_int)
      end
    end

    class SignatureOut < VarStringOut
      def initialize
        super ForeignLibrary::MAX_SIGNATURE_LENGTH
      end
    end

    class PublicKeyOut < VarStringOut
      def initialize
        super ForeignLibrary::MAX_PUBKEY_LENGTH
      end
    end

    class PrivateKeyDerOut < VarStringOut
      def initialize
        super ForeignLibrary::MAX_PRIVKEY_DER_LENGTH
      end
    end

    class VarStringInOut
      attr_reader :pointer
      attr_reader :size_pointer

      def initialize(in_value, name, max_length)
        if !in_value.is_a?(String)
          raise ArgumentError, "#{name} input value must be a string"
        end

        if in_value.bytesize > max_length
          raise ArgumentError, "#{name} input value is too long"
        end

        @pointer = FFI::MemoryPointer.new(:uchar, max_length)
        @pointer.put_bytes(0, in_value)

        @size_pointer = FFI::MemoryPointer.new(:int)
        @size_pointer.write_int(in_value.length)
      end

      def value
        @pointer.read_string(@size_pointer.read_int)
      end
    end

    class PublicKeyInOutVar < VarStringInOut
      def initialize(pubkey)
        super pubkey, :pubkey, ForeignLibrary::MAX_PUBKEY_LENGTH

        if !ForeignLibrary::VALID_PUBKEY_LENGTHS.include?(pubkey.length)
          raise ArgumentError, 'pubkey has invalid length'
        end
      end
    end

    class FixedStringOut
      attr_reader :pointer
      attr_reader :length

      def initialize(length)
        @length = length
        @pointer = FFI::MemoryPointer.new(:uchar, length)
      end

      def value
        @pointer.read_string(length)
      end
    end

    class SignatureCompactOut < FixedStringOut
      def initialize
        super ForeignLibrary::COMPACT_SIGNATURE_LENGTH
      end
    end

    class SecretKeyOut < FixedStringOut
      def initialize
        super ForeignLibrary::SECRET_KEY_LENGTH
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
          # TODO: consider passing 3 arguments to the inner proc
          # so that its interface is the same as Secp256k1.nonce_function_default
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

    class NonceOut
      attr_reader :pointer

      def initialize
        @pointer = FFI::MemoryPointer.new(:uchar, 32)
      end

      def value
        @pointer.read_string(32)
      end
    end

    class RecidOut
      attr_reader :pointer

      def initialize
        @pointer = FFI::MemoryPointer.new(:int)
      end

      def value
        @pointer.read_int
      end
    end

    class Boolean
      AllowedInputs = [true, false, nil]

      def initialize(value, name)
        if !AllowedInputs.include?(value)
          raise ArgumentError, "#{name} must be true, false, or nil"
        end
        @integer = value ? 1 : 0
      end

      def to_i
        @integer
      end
    end

    class Compressed < Boolean
      def initialize(compressed)
        super compressed, :compressed
      end
    end
  end
end
