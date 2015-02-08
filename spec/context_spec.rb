require 'spec_helper'

describe 'Secp256k1::Context unit tests' do
  # Unit tests for the Context class.  These do not actually call
  # the external library.

  let(:lib) do
    d = double('lib')
    allow(d).to receive(:secp256k1_context_destroy) { |ptr| }
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
end

describe 'Secp256k1::Context late initialization for signing' do
  before(:all) do
    @context = Secp256k1::Context.new
    @context.initialize_sign
  end

  it 'can sign' do
    ex = ExampleSig1
    sig = @context.ecdsa_sign(ex.message_hash, ex.seckey, :default)
    expect(sig).to eq ex.signature_nonce_default
  end
end

describe 'Secp256k1::Context late initialization for verifying' do
  before(:all) do
    @context = Secp256k1::Context.new
    @context.initialize_verify
  end

  it 'can verify' do
    ex = ExampleSig1
    result = @context.ecdsa_verify(ex.message_hash, ex.signature, ex.pubkey)
    expect(result).to eq 1  # expect correct signature
  end
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
      nonce_proc = Proc.new { ex.nonce_arbitrary }
      sig = context.ecdsa_sign(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq ex.signature
    end

    it 'returns nil if the nonce proc returns nil' do
      nonce_proc = Proc.new { }
      sig = context.ecdsa_sign(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq nil
    end

    it 'allows the nonce proc to raise exceptions' do
      nonce_proc = Proc.new { raise 'hi' }
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
      nonce_proc = Proc.new { ex.nonce_arbitrary }
      sig = context.ecdsa_sign_compact(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq ex.signature_compact
    end

    it 'returns nil if the nonce proc returns nil' do
      nonce_proc = Proc.new { }
      sig = context.ecdsa_sign_compact(ex.message_hash, ex.seckey, nonce_proc)
      expect(sig).to eq nil
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
      expect(result).to eq -1
    end

    it 'returns -2 for invalid signatures' do
      result = context.ecdsa_verify(ex.message_hash, 'junk', ex.pubkey)
      expect(result).to eq -2
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
end
