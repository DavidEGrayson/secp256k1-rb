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

    def ecdsa_sign(msg32, seckey, noncefp)
      msg32 = Argument::MessageHash.new(msg32)
      seckey = Argument::SecretKeyIn.new(seckey)
      noncefp = Argument::NonceFunction.new(noncefp)
      sig = Argument::SignatureOut.new

      result = @lib.secp256k1_ecdsa_sign(@ptr, msg32.for_ffi, sig.pointer,
        sig.size_pointer, seckey.for_ffi, noncefp.for_ffi, nil)

      # TODO: check_signing_result(result)

      sig.value
    end

    def ecdsa_verify(msg32, sig, pubkey)
      msg32 = Argument::MessageHash.new(msg32)
      @lib.secp256k1_ecdsa_verify(@ptr, msg32.for_ffi, sig, sig.bytesize, pubkey, pubkey.bytesize)
    end
  end
end
