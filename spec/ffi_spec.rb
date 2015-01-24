# encoding: ascii-8bit

require_relative 'spec_helper.rb'
require 'secp256k1'

describe 'libsecp256k1' do

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
