module Secp256k1
  module Argument
    class MessageHash
      def initialize(msg32)
        if !msg32.is_a?(String)
          if msg32.respond_to?(:to_str)
            msg32 = msg32.to_str
          end
          if !msg32.is_a?(String)
            raise ArgumentError, 'msg32 must be a string'
          end
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
          if seckey.respond_to?(:to_str)
            seckey = seckey.to_str
          end
          if !seckey.is_a?(String)
            raise ArgumentError, 'seckey must be a string'
          end
        end

        if seckey.bytesize != 32
          raise ArgumentError, 'seckey must be 32 bytes long'
        end
      end

      def for_ffi
        @seckey
      end
    end
  end
end
