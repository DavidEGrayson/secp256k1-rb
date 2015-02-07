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
    sig = @context.ecdsa_sign(ex.message_hash, ex.secret_key, :default)
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
    result = @context.ecdsa_verify(ex.message_hash, ex.signature, ex.public_key)
    expect(result).to eq 1  # expect correct signature
  end
end

describe 'Secp256k1::Context with signing enabled' do
  before(:all) do
    @context = Secp256k1::Context.new(sign: true)
  end

  let(:context) { @context }

  describe 'ecdsa_sign' do
    let(:ex) { ExampleSig1 }
    let(:nonce_spec) { Proc.new { ex.nonce } }

    it 'gives the right signature (default algorithm)' do
      sig = context.ecdsa_sign(ex.message_hash, ex.secret_key, :default)
      expect(sig).to eq ex.signature_nonce_default
    end

    it 'gives the right signature (no algorithm specified)' do
      sig = context.ecdsa_sign(ex.message_hash, ex.secret_key)
      expect(sig).to eq ex.signature_nonce_default
    end

    it 'gives the right signature (rfc6979)' do
      sig = context.ecdsa_sign(ex.message_hash, ex.secret_key, :rfc6979)
      expect(sig).to eq ex.signature_rfc6979
    end

    it 'gives the right signature (arbitrary nonce)' do
      nonce_proc = Proc.new { ex.nonce }
      sig = context.ecdsa_sign(ex.message_hash, ex.secret_key, nonce_proc)
      expect(sig).to eq ex.signature
    end

    it 'returns nil if the nonce proc returns nil' do
      nonce_proc = Proc.new { }
      sig = context.ecdsa_sign(ex.message_hash, ex.secret_key, nonce_proc)
      expect(sig).to eq nil
    end

    it 'allows the nonce proc to raise exceptions' do
      nonce_proc = Proc.new { raise 'hi' }
      expect { context.ecdsa_sign(ex.message_hash, ex.secret_key, nonce_proc) }
        .to raise_error 'hi'
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
      result = context.ecdsa_verify(ex.message_hash, ex.signature, ex.public_key)
      expect(result).to eq 1  # expect correct signature
    end

    it 'can verify a correct signature with high S value' do
      result = context.ecdsa_verify(ex.message_hash, ex.signature_alt, ex.public_key)
      expect(result).to eq 1  # expect correct signature
    end

    it 'returns 1 for incorrect signatures' do
      result = context.ecdsa_verify(ex.message_hash, ex.signature.succ, ex.public_key)
      expect(result).to eq 0
    end

    it 'returns -1 for bad public keys' do
      result = context.ecdsa_verify(ex.message_hash, ex.signature, 'junk')
      expect(result).to eq -1
    end

    it 'returns -2 for invalid signatures' do
      result = context.ecdsa_verify(ex.message_hash, 'junk', ex.public_key)
      expect(result).to eq -2
    end
  end
end
