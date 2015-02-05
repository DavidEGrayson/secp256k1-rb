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

      sig_buf = FFI::MemoryPointer.new(:uchar, ForeignLibrary::MAX_SIGNATURE_SIZE)
      sig_size = FFI::MemoryPointer.new(:int)
      sig_size.write_int(ForeignLibrary::MAX_SIGNATURE_SIZE)

      result = @lib.secp256k1_ecdsa_sign(@ptr, msg32.for_ffi, sig_buf, sig_size,
                                         seckey.for_ffi, noncefp.for_ffi, nil)

      # TODO: check_signing_result(result)

      sig_buf.read_string(sig_size.read_int)
    end

    def ecdsa_verify(msg32, sig, pubkey)
      msg32 = Argument::MessageHash.new(msg32)
      @lib.secp256k1_ecdsa_verify(@ptr, msg32.for_ffi, sig, sig.bytesize, pubkey, pubkey.bytesize)
    end
  end
end
