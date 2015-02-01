# encoding: ascii-8bit

require_relative 'spec_helper'

describe Secp256k1 do
  describe 'start' do
    it 'always returns nil' do
      allow(Secp256k1).to receive(:secp256k1_start).and_return(1234)
      expect(Secp256k1.start({})).to eq nil
    end

    it 'when given an empty hash calls secp256k1_ecdsa_start with 0' do
      expect(Secp256k1).to receive(:secp256k1_start).with(0)
      Secp256k1.start({})
    end

    it 'when given {verify: true} calls secp256k1_ecdsa_start with 1' do
      expect(Secp256k1).to receive(:secp256k1_start).with(1)
      Secp256k1.start(verify: true)
    end

    it 'when given {sign: true} calls secp256k1_ecdsa_start with 2' do
      expect(Secp256k1).to receive(:secp256k1_start).with(2)
      Secp256k1.start(sign: true)
    end

    it 'when given {verify: true, sign: true} calls secp256k1_ecdsa_start with 3' do
      expect(Secp256k1).to receive(:secp256k1_start).with(3)
      Secp256k1.start(verify: true, sign: true)
    end
  end

  describe 'stop' do
    it 'returns nil' do
      allow(Secp256k1).to receive(:secp256k1_stop).and_return(1234)
      expect(Secp256k1.stop).to eq nil
    end

    it 'calls secp256k1_stop with no arguments' do
      expect(Secp256k1).to receive(:secp256k1_stop).with(no_args)
      Secp256k1.stop
    end
  end

  context '(started)' do
    before(:all) do
      Secp256k1.start verify: true, sign: true
    end

    after(:all) do
      Secp256k1.stop
    end

    it 'sign and verify' do
      priv, pub = Secp256k1.generate_key_pair
      signature = Secp256k1.sign("derp", priv)
      expect(Secp256k1.verify("derp", signature, pub)).to eql(true)
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
