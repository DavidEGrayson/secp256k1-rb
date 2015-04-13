require 'spec_helper'

describe 'Secp256k1::Context unit tests' do
  # Unit tests for the Context class.  These do not actually call
  # the external library.

  let(:lib) do
    d = double('lib')
    allow(d).to receive(:secp256k1_context_destroy) { |_ptr| }
    allow(d).to receive(:secp256k1_context_create) { FFI::Pointer.new(0) }
    d
  end

  subject(:context) { Secp256k1::Context.new(lib: lib) }

  describe 'initialization' do
    it 'calls secp256k1_context_create with flags=0 by default' do
      expect(lib).to receive(:secp256k1_context_create).with(0)
      Secp256k1::Context.new(lib: lib)
    end

    it 'calls secp256k1_context_create with flags=1 if verify is specified' do
      expect(lib).to receive(:secp256k1_context_create).with(1)
      Secp256k1::Context.new(lib: lib, verify: true)
    end

    it 'calls secp256k1_context_create with flags=2 if sign is specified' do
      expect(lib).to receive(:secp256k1_context_create).with(1)
      Secp256k1::Context.new(lib: lib, verify: true)
    end
  end

  it 'has working garbage collection' do
    # This test is important because if we make a proc to serve as the destroyer
    # and the context ends up in the closure of the proc, garbage collection
    # does not work.  This test only works on MRI as far as I know.  The
    # before_proc is necessary to make sure the context object does not get
    # garbage collected before we take our first object count.
    before_proc = lambda do
      a = Secp256k1::Context.new(lib: lib)
      ObjectSpace.each_object(Secp256k1::Context).count
    end
    before_count = before_proc.call
    GC.start
    after_count = ObjectSpace.each_object(Secp256k1::Context).count
    expect(before_count).to be > after_count
  end if RUBY_ENGINE == 'ruby'
end

describe 'Secp256k1::Context with nothing enabled' do
  before(:all) do
    @context = Secp256k1::Context.new
  end

  let(:context) { @context }

  describe 'ec_seckey_verify' do
    let(:ex) { ExampleSig1 }

    it 'returns 1 for a valid secret key' do
      result = context.ec_seckey_verify(ex.seckey)
      expect(result).to eq 1
    end

    it 'returns 0 for an invalid key (all ones)' do
      result = context.ec_seckey_verify("\xFF" * 32)
      expect(result).to eq 0
    end

    it 'returns 0 for an invalid key (all zeros)' do
      result = context.ec_seckey_verify("\x00" * 32)
      expect(result).to eq 0
    end
  end

  describe 'ec_pubkey_verify' do
    let(:ex) { ExampleSig1 }

    it 'returns 1 for a valid public key (compressed)' do
      result = context.ec_pubkey_verify(ex.pubkey_compressed)
      expect(result).to eq 1
    end

    it 'returns 1 for a valid public key (uncompressed)' do
      result = context.ec_pubkey_verify(ex.pubkey_uncompressed)
      expect(result).to eq 1
    end

    it 'returns 0 for an invalid public key' do
      result = context.ec_pubkey_verify(ex.pubkey_uncompressed.succ)
      expect(result).to eq 0
    end
  end

  describe 'ec_pubkey_decompress' do
    it 'can decompress a compressed public key' do
      pubkey = context.ec_pubkey_decompress(ExampleSig1.pubkey_compressed)
      expect(pubkey).to eq ExampleSig1.pubkey_uncompressed
    end

    it 'can preserve a decompressed public key' do
      pubkey = context.ec_pubkey_decompress(ExampleSig1.pubkey_uncompressed)
      expect(pubkey).to eq ExampleSig1.pubkey_uncompressed
    end

    it 'returns nil if the compressed key was wrong' do
      pubkey = context.ec_pubkey_decompress("\xFF" * 33)
      expect(pubkey).to eq nil
    end

    it 'raises an ArgumentError if the compressed key was a bad length' do
      expect { context.ec_pubkey_decompress('hi') }.to raise_error \
        ArgumentError, 'pubkey has invalid length'
    end
  end

  describe 'ec_privkey_import' do
    it 'can import a DER pviate key (compressed)' do
      seckey = context.ec_privkey_import(ExampleSig1.privkey_der_uncompressed)
      expect(seckey).to eq ExampleSig1.seckey
    end

    it 'can import a DER pviate key (uncompressed)' do
      seckey = context.ec_privkey_import(ExampleSig1.privkey_der_compressed)
      expect(seckey).to eq ExampleSig1.seckey
    end

    it 'returns nil if the DER was invalid' do
      expect(context.ec_privkey_import('junk')).to eq nil
    end
  end

  describe 'ec_privkey_tweak_add' do
    let(:ex) { Example2 }

    it 'adds correctly' do
      sum = context.ec_privkey_tweak_add(ex.privkey1, ex.privkey2)
      expect(sum).to eq ex.privkey_sum
    end

    it 'returns nil if the second argument is too big' do
      sum = context.ec_privkey_tweak_add(ex.privkey1, "\xFF" * 32)
      expect(sum).to eq nil
    end
  end

  describe 'ec_privkey_tweak_mul' do
    let(:ex) { Example2 }

    it 'multiplies correctly' do
      product = context.ec_privkey_tweak_mul(ex.privkey1, ex.privkey2)
      expect(product).to eq ex.privkey_product
    end
  end
end

describe 'Secp256k1::Context with signing enabled' do
  before(:all) do
    @context = Secp256k1::Context.new(sign: true)
  end

  let(:context) { @context }

  describe 'ecdsa_sign' do
    let(:ex) { ExampleSig1 }

    it 'gives the right signature (default algorithm)' do
      sig = context.ecdsa_sign(ex.message_hash, ex.seckey, :default)
      expect(sig).to eq ex.signature_nonce_default
    end

    it 'gives the right signature (no algorithm specified)' do
      sig = context.ecdsa_sign(ex.message_hash, ex.seckey)
      expect(sig).to eq ex.signature_nonce_default
    end

    it 'gives the right signature (rfc6979)' do
      sig = context.ecdsa_sign(ex.message_hash, ex.seckey, :rfc6979)
      expect(sig).to eq ex.signature_rfc6979
    end

    it 'gives the right signature (arbitrary nonce)' do
      nonce_proc = proc { ex.nonce_arbitrary }
      sig = context.ecdsa_sign(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq ex.signature
    end

    it 'returns nil if the nonce proc returns nil' do
      nonce_proc = proc {}
      sig = context.ecdsa_sign(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq nil
    end

    it 'allows the nonce proc to raise exceptions' do
      nonce_proc = proc { fail 'hi' }
      expect { context.ecdsa_sign(ex.message_hash, ex.seckey, nonce_proc) }
        .to raise_error 'hi'
    end
  end

  describe 'ecdsa_sign_compact' do
    let(:ex) { ExampleSig1 }

    it 'gives the right signature (default algorithm)' do
      sig = context.ecdsa_sign_compact(ex.message_hash, ex.seckey, :default)
      expect(sig).to eq ex.signature_compact_nonce_default
    end

    it 'gives the right signature (no algorithm specified)' do
      sig = context.ecdsa_sign_compact(ex.message_hash, ex.seckey)
      expect(sig).to eq ex.signature_compact_nonce_default
    end

    it 'gives the right signature (rfc6979)' do
      sig = context.ecdsa_sign_compact(ex.message_hash, ex.seckey, :rfc6979)
      expect(sig).to eq ex.signature_compact_rfc6979
    end

    it 'gives the right signature (arbitrary nonce)' do
      nonce_proc = proc { ex.nonce_arbitrary }
      sig = context.ecdsa_sign_compact(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq ex.signature_compact
    end

    it 'returns nil if the nonce proc returns nil' do
      nonce_proc = proc {}
      sig = context.ecdsa_sign_compact(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq nil
    end
  end

  describe 'ec_pubkey_create' do
    it 'can create a public key (compressed)' do
      pubkey = context.ec_pubkey_create(ExampleSig1.seckey, true)
      expect(pubkey).to eq ExampleSig1.pubkey_compressed
    end

    it 'can create a public key (uncompressed)' do
      pubkey = context.ec_pubkey_create(ExampleSig1.seckey, false)
      expect(pubkey).to eq ExampleSig1.pubkey_uncompressed
    end

    it 'returns nil for invalid secret keys' do
      pubkey = context.ec_pubkey_create("\x00" * 32, false)
      expect(pubkey).to eq nil
    end
  end

  describe 'ec_privkey_export' do
    let(:ex) { ExampleSig1 }

    it 'can export a private key to DER format (compressed)' do
      der = context.ec_privkey_export(ex.seckey, true)
      expect(der).to eq ex.privkey_der_compressed
    end

    it 'can export a private key to DER format (uncompressed)' do
      der = context.ec_privkey_export(ex.seckey, false)
      expect(der).to eq ex.privkey_der_uncompressed
    end

    it 'returns nil if the secret key is zero' do
      der = context.ec_privkey_export("\x00" * 32, false)
      expect(der).to eq nil
    end
  end
end

describe 'Secp256k1::Context with verifying enabled' do
  before(:all) do
    @context = Secp256k1::Context.new(verify: true)
  end

  let(:context) { @context }

  describe 'ecdsa_verify' do
    let(:ex) { ExampleSig1 }

    it 'can verify a correct signature with low S value' do
      result = context.ecdsa_verify(ex.message_hash, ex.signature, ex.pubkey)
      expect(result).to eq 1  # expect correct signature
    end

    it 'can verify a correct signature with high S value' do
      result = context.ecdsa_verify(ex.message_hash, ex.signature_alt, ex.pubkey)
      expect(result).to eq 1  # expect correct signature
    end

    it 'returns 1 for incorrect signatures' do
      result = context.ecdsa_verify(ex.message_hash, ex.signature.succ, ex.pubkey)
      expect(result).to eq 0
    end

    it 'returns -1 for invalid public keys' do
      result = context.ecdsa_verify(ex.message_hash, ex.signature, 'junk')
      expect(result).to eq(-1)
    end

    it 'returns -2 for invalid signatures' do
      result = context.ecdsa_verify(ex.message_hash, 'junk', ex.pubkey)
      expect(result).to eq(-2)
    end
  end

  describe 'ecdsa_recover_compact' do
    let(:ex) { ExampleSig1 }

    it 'can recover public key from a compact signature (uncompressed)' do
      sig64, recid = ex.signature_compact
      pubkey = context.ecdsa_recover_compact(ex.message_hash, sig64, false, recid)
      expect(pubkey).to eq ex.pubkey_uncompressed
    end

    it 'can recover public key from a compact signature (compressed)' do
      sig64, recid = ex.signature_compact
      pubkey = context.ecdsa_recover_compact(ex.message_hash, sig64, true, recid)
      expect(pubkey).to eq ex.pubkey
    end

    it 'returns nil if something is wrong' do
      pubkey = context.ecdsa_recover_compact(ex.message_hash, "\x00" * 64, true, 0)
      expect(pubkey).to eq nil
    end
  end

  describe 'ec_pubkey_tweak_add' do
    let(:ex) { Example2 }

    it 'adds correctly (compressed)' do
      sum = context.ec_pubkey_tweak_add(ex.pubkey1, ex.privkey2)
      expect(sum).to eq ex.pubkey_sum
    end

    it 'adds correctly (uncompressed)' do
      sum = context.ec_pubkey_tweak_add(ex.pubkey1_uncompressed, ex.privkey2)
      expect(sum).to eq ex.pubkey_sum_uncompressed
    end

    it 'returns nil if the pubkey is invalid' do
      sum = context.ec_pubkey_tweak_add("\xFF" * 33, ex.privkey2)
      expect(sum).to eq nil
    end

    it 'returns nil if the tweak is invalid' do
      sum = context.ec_pubkey_tweak_add(ex.pubkey1, "\xFF" * 32)
      expect(sum).to eq nil
    end
  end

  describe 'ec_pubkey_tweak_mul' do
    let(:ex) { Example2 }

    it 'multiplies correctly (compressed)' do
      product = context.ec_pubkey_tweak_mul(ex.pubkey1, ex.privkey2)
      expect(product).to eq ex.pubkey_product
    end

    it 'multiplies correctly (uncompressed)' do
      product = context.ec_pubkey_tweak_mul(ex.pubkey1_uncompressed, ex.privkey2)
      expect(product).to eq ex.pubkey_product_uncompressed
    end

    it 'returns nil if the pubkey is invalid' do
      product = context.ec_pubkey_tweak_mul("\xFF" * 33, ex.privkey2)
      expect(product).to eq nil
    end

    it 'returns nil if the tweak is invalid' do
      product = context.ec_pubkey_tweak_mul(ex.pubkey1, "\xFF" * 32)
      expect(product).to eq nil
    end
  end
end

describe 'Secp256k1::Context cloning' do
  before(:all) do
    @context1 = Secp256k1::Context.new(verify: true)
    @context2 = @context1.context_clone
  end

  specify 'the cloned context has a different pointer' do
    expect(@context1.instance_variable_get(:@ptr).address).to_not eq \
      @context2.instance_variable_get(:@ptr).address
  end

  specify 'the clonsed context is usable' do
    ex = ExampleSig1
    result = @context2.ecdsa_verify(ex.message_hash, ex.signature, ex.pubkey)
    expect(result).to eq 1  # expect correct signature
  end
end
