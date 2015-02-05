require 'secp256k1/foreign_library'

module Secp256k1
  class Context
    def initialize(opts = {})
      @lib = opts.fetch(:lib) { ForeignLibrary }

      flags = 0
      flags |= ForeignLibrary::SECP256K1_START_VERIFY if opts[:verify]
      flags |= ForeignLibrary::SECP256K1_START_SIGN if opts[:sign]

      @ptr = @lib.secp256k1_context_create(flags)
    end

    def ecdsa_sign(msg32, seckey, nonce_spec)
      sig_buf = FFI::MemoryPointer.new(:uchar, ForeignLibrary::MAX_SIGNATURE_SIZE)
      sig_size = FFI::MemoryPointer.new(:int)
      sig_size.write_int(ForeignLibrary::MAX_SIGNATURE_SIZE)

      nonce_func = self.class.nonce_func(nonce_spec)
      result = @lib.secp256k1_ecdsa_sign(@ptr, msg32, sig_buf, sig_size,
                                         seckey, nonce_func, nil)

      # TODO: check_signing_result(result)

      sig_buf.read_string(sig_size.read_int)
    end

    private

    def self.nonce_func(nonce_spec)
      case nonce_spec
      when Proc
        Proc.new do |nonce32, msg32, key32, attempt, data|
          nonce_str = nonce_spec.call(attempt)
          # TODO: allow nonce_spec to return nil
          nonce32.put_bytes(0, nonce_str)
          1
        end
      else
        raise ArgumentError, "Invalid nonce_spec."
      end
    end
  end
end
