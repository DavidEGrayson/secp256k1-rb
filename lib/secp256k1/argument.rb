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
  end
end
