# TODO: remove this file

# encoding: ascii-8bit

require_relative 'spec_helper'

describe Secp256k1 do
  context '(started)' do
    before(:all) do
      Secp256k1.start verify: true, sign: true
    end

    after(:all) do
      Secp256k1.stop
    end

    it 'sign compact and recover' do
      priv, pub = Secp256k1.generate_key_pair
      signature = Secp256k1.sign_compact("derp", priv)
      expect(signature.bytesize).to eql(65)
      pub2 = Secp256k1.recover_compact("derp", signature)
      expect(pub2.bytesize).to eql(33)
      expect(pub2).to eql(pub)
    end

    it 'sign compact and recover (uncompressed)' do
      # uncompressed
      priv, pub = Secp256k1.generate_key_pair(compressed=false)
      signature = Secp256k1.sign_compact("derp", priv, compressed=false)
      expect(signature.bytesize).to eql(65)
      pub2 = Secp256k1.recover_compact("derp", signature)
      expect(pub2.bytesize).to eql(65)
      expect(pub2).to eql(pub)
    end
  end

end
