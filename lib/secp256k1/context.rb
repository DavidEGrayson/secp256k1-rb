require 'secp256k1/foreign_library'
require 'secp256k1/argument'

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

    def ecdsa_verify(msg32, sig, pubkey)
      msg32 = Argument::MessageHash.new(msg32)
      sig = Argument::SignatureIn.new(sig)
      pubkey = Argument::PublicKeyIn.new(pubkey)
      @lib.secp256k1_ecdsa_verify(self, msg32.string, sig.string, sig.length,
        pubkey.string, pubkey.length)
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
        raise 'unexpected result'
      end
    end

    def ecdsa_sign_compact(msg32, seckey, noncefp = :default)
      msg32 = Argument::MessageHash.new(msg32)
      seckey = Argument::SecretKeyIn.new(seckey)
      noncefp = Argument::NonceFunction.new(noncefp)

      sig = Argument::SignatureCompactOut.new
      recid = Argument::RecidOut.new

      result = @lib.secp256k1_ecdsa_sign_compact(self, msg32.string,
        sig.pointer, seckey.string, noncefp.func, nil, recid.pointer)

      case result
      when 0
        # the nonce generation function failed
        nil
      when 1
        # signature created
        [sig.value, recid.value]
      else
        raise 'unexpected result'
      end
    end

    def ecdsa_recover_compact(msg32, sig64, compressed, recid)
      msg32 = Argument::MessageHash.new(msg32)
      sig64 = Argument::SignatureCompactIn.new(sig64)
      compressed = Argument::Compressed.new(compressed)

      raise 'recid must be an integer' if !recid.is_a?(Integer)

      pubkey = Argument::PublicKeyOut.new

      result = @lib.secp256k1_ecdsa_recover_compact(self,
        msg32.string, sig64.string, pubkey.pointer, pubkey.size_pointer,
        compressed.to_i, recid)

      case result
      when 0
        # something went wrong
        nil
      when 1
        # public key successfully recovered (which guarantees a correct signature)
        pubkey.value
      else
        raise 'unexpected result'
      end
    end

    def ec_seckey_verify(seckey)
      seckey = Argument::SecretKeyIn.new(seckey)
      @lib.secp256k1_ec_seckey_verify(self, seckey.string)
    end

    def ec_pubkey_verify(pubkey)
      pubkey = Argument::PublicKeyIn.new(pubkey)
      @lib.secp256k1_ec_pubkey_verify(self, pubkey.string, pubkey.length)
    end

    def ec_pubkey_create(seckey, compressed)
      seckey = Argument::SecretKeyIn.new(seckey)
      compressed = Argument::Compressed.new(compressed)

      pubkey = Argument::PublicKeyOut.new

      result = @lib.secp256k1_ec_pubkey_create(self, pubkey.pointer,
        pubkey.size_pointer, seckey.string, compressed.to_i)

      case result
      when 0
        # secret was invalid, try again
        nil
      when 1
        # secret was valid
        pubkey.value
      else
        raise 'unexpected error'
      end
    end

    def ec_pubkey_decompress(pubkey)
      pubkey = Argument::PublicKeyInOutVar.new(pubkey)

      result = @lib.secp256k1_ec_pubkey_decompress(self, pubkey.pointer, pubkey.size_pointer)

      case result
      when 0
        # public key was invalid
        nil
      when 1
        # success
        pubkey.value
      else
        raise 'unexpected result'
      end
    end

    def ec_privkey_export(seckey, compressed)
      seckey = Argument::SecretKeyIn.new(seckey)
      privkey = Argument::PrivateKeyDerOut.new
      compressed = Argument::Compressed.new(compressed)

      result = @lib.secp256k1_ec_privkey_export(self, seckey.string,
        privkey.pointer, privkey.size_pointer, compressed.to_i)

      # TODO: get libsecp256k1 to document this return value
      case result
      when 0
        nil
      when 1
        privkey.value
      else
        raise 'unexpected result'
      end
    end

    def ec_privkey_import(privkey)
      privkey = Argument::PrivateKeyDerIn.new(privkey)
      seckey = Argument::SecretKeyOut.new

      result = @lib.secp256k1_ec_privkey_import(self, seckey.pointer,
        privkey.string, privkey.length)

      # TODO: get libsecp256k1 to document this return vale
      case result
      when 0
        nil
      when 1
        seckey.value
      else
        raise 'unexpected result'
      end
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
