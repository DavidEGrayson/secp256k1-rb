require 'secp256k1/foreign_library'
require 'secp256k1/argument'

module Secp256k1
  # A Context object must be created in order to use most parts of libsecp256k1.
  # The context object holds tables of precomputed data that make the
  # operation of the library more efficient.
  #
  # The way that the context object was initialized determines which features it
  # supports.  To create a fully-functional context, just do:
  #
  #     cont = Secp256k1::Context.new(sign: true, verify: true)
  class Context
    # Calls `secp256k1_context_create` to create a new context.
    #
    # Two options are accepted in an optional hash argument:
    #
    # - `:verify` - Set this option to true to initialize this context for signature verification.
    # - `:sign` - Set this option to true to initialize this context for signing.
    #
    # To create a fully-functional context, just do:
    #
    #     cont = Secp256k1::Context.new(sign: true, verify: true)
    #
    # @param opts Hash of options
    def initialize(opts = {})
      @lib = opts.fetch(:lib) { ForeignLibrary }

      @ptr = opts.fetch(:ptr) do
        flags = 0
        flags |= ForeignLibrary::SECP256K1_START_VERIFY if opts[:verify]
        flags |= ForeignLibrary::SECP256K1_START_SIGN if opts[:sign]

        pointer = @lib.secp256k1_context_create(flags)
        destroyer = @lib.method(:secp256k1_context_destroy)
        FFI::AutoPointer.new(pointer, destroyer)
      end
    end

    # Calls `secp256k1_context_clonse` to clone this context.
    #
    # @return (Context) A new context with the same capabilities.
    def context_clone
      clone_ptr = @lib.secp256k1_context_clone(@ptr)
      self.class.new(lib: @lib, ptr: clone_ptr)
    end

    # Verifies an ECDSA signature by calling `secp256k1_ecdsa_verify`.
    #
    # Returns the status code from the native function:
    #
    # - 1: correct signature
    # - 0: incorrect signature
    # - -1: invalid public key
    # - -2: invalid signature
    #
    # @param msg32 A 32-byte string holding the message hash.
    # @param sig A string holding the DER-encoded signature.
    # @param pubkey A string holding the public key.
    # @return (Integer)
    # @initreq verify
    def ecdsa_verify(msg32, sig, pubkey)
      msg32 = Argument::MessageHash.new(msg32)
      sig = Argument::SignatureIn.new(sig)
      pubkey = Argument::PublicKeyIn.new(pubkey)
      @lib.secp256k1_ecdsa_verify(self, msg32.string, sig.string, sig.length,
        pubkey.string, pubkey.length)
    end

    # Creates an ECDSA signature by calling `secp256k1_ecdsa_sign`.
    #
    # Acceptable values for `noncefp` are:
    #
    # - nil, which results in passing a null pointer to `secp256k1_ecdsa_sign`.
    # - `:default`, which results in using `secp256k1_nonce_function_default`.
    # - `:rfc6979`, which results in using `secp256k1_nonce_function_rfc699`.
    # - A Proc that takes the same arguments as
    #   {Secp256k1.nonce_function_default} and returns either a 32-byte nonce
    #   string or nil.  This option is only recommended for advanced users who
    #   know what they are doing; badly generated nonces can compromise your
    #   secret key!
    #
    # Note: Choosing `nil` should be equivalent to choosing `:default`, but the
    # two options do result in different arguments being passed to `libsecp256k1`.
    #
    # @param msg32 A 32-byte string holding the message hash.
    # @param seckey A 32-byte string holding the secret hey.
    # @param noncefp A specification for how to generate the nonce.
    # @return Usually returns a string holding the DER-encoded signature, but
    #   can return nil if the secret key was invalid or nonce generation failed.
    # @initreq sign
    def ecdsa_sign(msg32, seckey, noncefp = nil)
      msg32 = Argument::MessageHash.new(msg32)
      seckey = Argument::SecretKeyIn.new(seckey)
      noncefp = Argument::NonceFunction.new(noncefp)
      sig = Argument::SignatureOut.new

      result = @lib.secp256k1_ecdsa_sign(self, msg32.string, sig.pointer,
        sig.size_pointer, seckey.string, noncefp.func, nil)

      case result
      when 0
        nil
      when 1
        sig.value
      else
        fail 'unexpected result'
      end
    end

    # Creates a compact ECDSA signature (64-byte string and recovery ID) by
    # calling `secp256k1_ecdsa_sign`.
    #
    # The parameters are the same as {Context#ecdsa_sign}'s parameters.
    #
    # @return Usually returns an array whose first element is the 64-byte
    #   signature string and the second element is the recovery ID
    #   (integer between 0 and 3).
    #   Returns nil if the secret key was invalid or nonce generation failed.
    # @initreq sign
    def ecdsa_sign_compact(msg32, seckey, noncefp = nil)
      msg32 = Argument::MessageHash.new(msg32)
      seckey = Argument::SecretKeyIn.new(seckey)
      noncefp = Argument::NonceFunction.new(noncefp)

      sig = Argument::SignatureCompactOut.new
      recid = Argument::RecidOut.new

      result = @lib.secp256k1_ecdsa_sign_compact(self, msg32.string,
        sig.pointer, seckey.string, noncefp.func, nil, recid.pointer)

      case result
      when 0
        nil
      when 1
        # signature created
        [sig.value, recid.value]
      else
        fail 'unexpected result'
      end
    end

    # Recover an ECDSA public key from a compact signature by calling
    # `secp256k1_ecdsa_recover_compact`.
    #
    # @param msg32 A 32-byte string holding the message hash.
    # @param sig64 A 64-byte string holding the compact signature.
    # @param compressed A boolean indicating whether to output the
    #   recovered public key in compressed format.
    # @param recid The recovery ID (integer between 0 and 3, as returned by
    #   `ecdsa_sign_compact`).
    # @initreq verify
    def ecdsa_recover_compact(msg32, sig64, compressed, recid)
      msg32 = Argument::MessageHash.new(msg32)
      sig64 = Argument::SignatureCompactIn.new(sig64)
      compressed = Argument::Compressed.new(compressed)

      fail 'recid must be an integer' unless recid.is_a?(Integer)

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
        fail 'unexpected result'
      end
    end

    # Verifies an ECDSA secret key by calling `secp256k1_ec_seckey_verify`.
    #
    # NOTE: For consistency with {Context#ecdsa_verify}, this function returns
    # an integer instead of boolean.
    #
    # @param seckey A 32-byte string holding the secret key.
    # @return 1 if the key is valid, 0 if it is invalid.
    def ec_seckey_verify(seckey)
      seckey = Argument::SecretKeyIn.new(seckey)
      @lib.secp256k1_ec_seckey_verify(self, seckey.string)
    end

    # Verifies an ECDSA public key by calling `secp256k1_ec_pubkey_verify`.
    #
    # NOTE: For consistency with {Context#ecdsa_verify}, this function returns
    # an integer instead of boolean.
    #
    # @param pubkey A 33-byte or 65-byte string holding the public key.
    # @return 1 if the key is valid, 0 if it is invalid
    def ec_pubkey_verify(pubkey)
      pubkey = Argument::PublicKeyIn.new(pubkey)
      @lib.secp256k1_ec_pubkey_verify(self, pubkey.string, pubkey.length)
    end

    # Computes the public key for a secret key by calling
    # `secp256k1_ec_pubkey_create`.
    #
    # @param seckey A 32-byte string holding the secret key.
    # @param compressed A boolean indicating whether to output the public key in
    #   compressed format.
    # @return Normally returns a string holding the public key.
    #   Returns nil if the secret key was invalid.
    # @initreq sign
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
        fail 'unexpected error'
      end
    end

    # Decompresses a public key by calling `secp256k1_ec_pubkey_decompress`.
    #
    # @param pubkey A string holding a compressed or decompressed public key.
    # @return Normally returns a string holding the uncompressed public key.
    # Returns nil if the passed public key was invalid.
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
        fail 'unexpected result'
      end
    end

    # Exports a private key in DER format by calling `secp256k1_ec_privkey_export`.
    #
    # @initreq sign
    # @param seckey A 32-byte string holding the private key.
    # @param compressed A boolean indicating whether to use a compressed format.
    # @return A string holding the DER-encoded private key, or nil if
    #   something went wrong.
    def ec_privkey_export(seckey, compressed)
      seckey = Argument::SecretKeyIn.new(seckey)
      privkey = Argument::PrivateKeyDerOut.new
      compressed = Argument::Compressed.new(compressed)

      result = @lib.secp256k1_ec_privkey_export(self, seckey.string,
        privkey.pointer, privkey.size_pointer, compressed.to_i)

      case result
      when 0
        nil
      when 1
        privkey.value
      else
        fail 'unexpected result'
      end
    end

    # Imports a private key in DER format by calling `secp256k1_ec_privkey_import`.
    #
    # @param privkey A string holding the DER-encoded private key.
    # @return A 32-byte string holding the secret key, or nil if
    #   something went wrong.
    def ec_privkey_import(privkey)
      privkey = Argument::PrivateKeyDerIn.new(privkey)
      seckey = Argument::SecretKeyOut.new

      result = @lib.secp256k1_ec_privkey_import(self, seckey.pointer,
        privkey.string, privkey.length)

      case result
      when 0
        nil
      when 1
        seckey.value
      else
        fail 'unexpected result'
      end
    end

    # Adds two private keys together by calling `secp256k1_ec_privkey_tweak_add`.
    #
    # @param seckey A 32-byte string holding a secret key.
    # @param tweak A 32-byte string holding a secret key.
    # @return A 32-byte string holding the secret key that is the sum
    #   of `seckey` and `tweak`, or nil if something went wrong.
    def ec_privkey_tweak_add(seckey, tweak)
      seckey = Argument::SecretKeyInOut.new(seckey)
      tweak = Argument::SecretKeyIn.new(tweak)

      result = @lib.secp256k1_ec_privkey_tweak_add(self, seckey.pointer, tweak.string)

      case result
      when 0
        nil
      when 1
        seckey.value
      else
        fail 'unexpected result'
      end
    end

    # Tweaks a public key by adding tweak times the generator to it, by calling
    # `secp256k1_ec_pubkey_tweak`.
    #
    # @param pubkey A string holding a public key.
    # @param tweak A 32-byte string holding a private key.
    # @return A string holding the new public key, or nil if something
    #   went wrong.
    # @initreq verify
    def ec_pubkey_tweak_add(pubkey, tweak)
      pubkey = Argument::PublicKeyInOutVar.new(pubkey)
      tweak = Argument::SecretKeyIn.new(tweak)

      result = @lib.secp256k1_ec_pubkey_tweak_add(self, pubkey.pointer, pubkey.length, tweak.string)

      case result
      when 0
        nil
      when 1
        pubkey.value
      else
        fail 'unexpected result'
      end
    end

    # Multiplies two private keys together by calling `secp256k1_ec_privkey_tweak_mul`.
    #
    # @param seckey A 32-byte string holding a secret key.
    # @param tweak A 32-byte string holding a secret key.
    # @return A 32-byte string holding the secret key that is the product
    #   of `seckey` and `tweak`, or nil if something went wrong.
    def ec_privkey_tweak_mul(seckey, tweak)
      seckey = Argument::SecretKeyInOut.new(seckey)
      tweak = Argument::SecretKeyIn.new(tweak)

      result = @lib.secp256k1_ec_privkey_tweak_mul(self, seckey.pointer, tweak.string)

      case result
      when 0
        nil
      when 1
        seckey.value
      else
        fail 'unexpected result'
      end
    end

    # Multiplies a public key by a private key by calling `secp256k1_ec_pubkey_tweak_mul`.
    #
    # @param pubkey A string holding the public key.
    # @param tweak A 32-byte string holding a secret key.
    # @return A string holding the new public key, or nil if something went wrong.
    # @initreq verify
    def ec_pubkey_tweak_mul(pubkey, tweak)
      pubkey = Argument::PublicKeyInOutVar.new(pubkey)
      tweak = Argument::SecretKeyIn.new(tweak)

      result = @lib.secp256k1_ec_pubkey_tweak_mul(self, pubkey.pointer, pubkey.length, tweak.string)

      case result
      when 0
        nil
      when 1
        pubkey.value
      else
        fail 'unexpected result'
      end
    end

    # This is not part of the public API of the gem.  It may change in
    # the future without notice.  This method makes it so we can pass
    # a Context object to FFI and it automatically converts it to a
    # pointer.
    #
    # @api private
    def to_ptr
      @ptr
    end
  end
end
