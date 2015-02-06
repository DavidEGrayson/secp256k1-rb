require 'spec_helper'

describe Secp256k1 do
  describe 'nonce_function_default' do
    it 'returns the right nonce for attempt 0' do
      ex = ExampleSig1
      nonce = Secp256k1.nonce_function_default(ex.message_hash, ex.secret_key, 0)
      expect(nonce).to eq ex.nonce_rfc6979_0
    end

    it 'returns the right nonce for attempt 1' do
      ex = ExampleSig1
      nonce = Secp256k1.nonce_function_default(ex.message_hash, ex.secret_key, 1)
      expect(nonce).to eq ex.nonce_rfc6979_1
    end
  end

  describe 'nonce_function_rfc6979' do
    xit
  end
end
