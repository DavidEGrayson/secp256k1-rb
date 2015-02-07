require 'secp256k1/foreign_library'

module Secp256k1
  class Context
    def initialize(opts = {})
      @lib = opts.fetch(:lib) { ForeignLibrary }

      flags = 0
      flags |= ForeignLibrary::SECP256K1_START_VERIFY if opts[:verify]
      flags |= ForeignLibrary::SECP256K1_START_SIGN if opts[:sign]

      pointer = @lib.secp256k1_context_create(flags)

      destroyer = @lib.method(:secp256k1_context_destroy)
      @ptr = FFI::AutoPointer.new(pointer, destroyer)
    end

    def initialize_sign
      @lib.secp256k1_context_initialize_sign(self)
    end

    def initialize_verify
      @lib.secp256k1_context_initialize_verify(self)
    end

    def ecdsa_sign(msg32, seckey, noncefp = :default)
      msg32 = Argument::MessageHash.new(msg32)
      seckey = Argument::SecretKeyIn.new(seckey)
      noncefp = Argument::NonceFunction.new(noncefp)
      sig = Argument::SignatureOut.new

      result = @lib.secp256k1_ecdsa_sign(self, msg32.string, sig.pointer,
        sig.size_pointer, seckey.string, noncefp.func, nil)

      case result
      when 0
        # the nonce generation function failed
        nil
      when 1
        # signature created
        sig.value
      else
        raise 'unexpected result from secp256k1_ecdsa_sign'
      end
    end

    def ecdsa_verify(msg32, sig, pubkey)
      msg32 = Argument::MessageHash.new(msg32)
      @lib.secp256k1_ecdsa_verify(self, msg32.string, sig, sig.bytesize, pubkey, pubkey.bytesize)
    end

    # This is not part of the public API of the gem.  It may change in
    # the future without notice.  This method makes it so we can pass
    # a Context object to FFI and it automatically converts it to a
    # pointer.
    def to_ptr
      @ptr
    end
  end
end
