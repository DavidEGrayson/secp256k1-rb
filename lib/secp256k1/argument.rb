module Secp256k1
  module Argument
    class MessageHash
      def initialize(msg32)
        if !msg32.is_a?(String)
          raise ArgumentError, 'msg32 must be a string'
        end

        if msg32.bytesize != 32
          raise ArgumentError, 'msg32 must be 32 bytes long'
        end

        @msg32 = msg32
      end

      def for_ffi
        @msg32
      end
    end

    class SecretKeyIn
      def initialize(seckey)
        @seckey = seckey

        if !seckey.is_a?(String)
          raise ArgumentError, 'seckey must be a string'
        end

        if seckey.bytesize != 32
          raise ArgumentError, 'seckey must be 32 bytes long'
        end
      end

      def for_ffi
        @seckey
      end
    end

    class NonceFunction
      def initialize(noncefp)
        case noncefp
        when Proc
          @fp = wrapper_proc(noncefp)
        else
          raise ArgumentError, "invalid noncefp"
        end
      end

      def for_ffi
        @fp
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
  end
end
