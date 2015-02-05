# Unit tests for the Context class.  These do not actually call
# the external library.

require 'spec_helper'

describe Secp256k1::Context do
  let(:lib) { double('lib') }
  subject(:context) { described_class.new(lib: lib) }

  describe 'initialization' do
    it 'calls secp256k1_context_create with flags=0 by default' do
      expect(lib).to receive(:secp256k1_context_create).with(0)
      described_class.new(lib: lib)
    end

    it 'calls secp256k1_context_create with flags=1 if verify is specified' do
      expect(lib).to receive(:secp256k1_context_create).with(1)
      described_class.new(lib: lib, verify: true)
    end

    it 'calls secp256k1_context_create with flags=2 if sign is specified' do
      expect(lib).to receive(:secp256k1_context_create).with(1)
      described_class.new(lib: lib, verify: true)
    end
  end
end
