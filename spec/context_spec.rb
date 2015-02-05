require 'spec_helper'

describe 'Secp256k1::Context unit tests' do
  # Unit tests for the Context class.  These do not actually call
  # the external library.

  let(:lib) do
    d = double('lib')
    d.stub(:secp256k1_context_destroy) { |ptr| }
    d.stub(:secp256k1_context_create) { FFI::Pointer.new(0) }
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

describe 'Secp256k1::Context integration tests' do
  before(:all) do
    @context = Secp256k1::Context.new(verify: true, sign: true)
  end

  let(:context) { @context }

  describe 'ecdsa_sign' do
    let(:ex) { ExampleSig1 }
    let(:nonce_spec) { Proc.new { ex.nonce } }

    it 'gives the right signature' do
      sig = context.ecdsa_sign(ex.message_hash, ex.secret_key, nonce_spec)
      expect(sig).to eq ex.signature
    end

    it 'raises an ArgumentError if secret_key is not a string' do
      bad_sig = 1234
      expect { context.ecdsa_sign(ex.message_hash, bad_sig, nonce_spec) }
        .to raise_error ArgumentError, 'secret key argument must be a string'
    end
  end

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
  end
end
