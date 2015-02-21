require 'spec_helper'

describe Secp256k1 do
  shared_examples_for 'rfc6979 function' do |method|
    it 'returns the right nonce for attempt 0' do
      ex = ExampleSig1
      nonce = Secp256k1.send(method, ex.message_hash, ex.seckey, 0)
      expect(nonce).to eq ex.nonce_rfc6979_0
    end

    it 'returns the right nonce for attempt 1' do
      ex = ExampleSig1
      nonce = Secp256k1.send(method, ex.message_hash, ex.seckey, 1)
      expect(nonce).to eq ex.nonce_rfc6979_1
    end
  end

  describe 'nonce_function_default' do
    it_behaves_like 'rfc6979 function', :nonce_function_default

    it 'returns nil if the nonce could not be generated' do
      ex = ExampleSig1
      expect(Secp256k1::ForeignLibrary)
        .to receive(:secp256k1_nonce_function_default)
        .and_return(proc { 0 })
      nonce = Secp256k1.nonce_function_default(ex.message_hash, ex.seckey, 1)
      expect(nonce).to eq nil
    end
  end

  describe 'nonce_function_rfc6979' do
    it_behaves_like 'rfc6979 function', :nonce_function_rfc6979
  end
end
