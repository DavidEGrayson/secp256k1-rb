require 'spec_helper'

describe Secp256k1::Argument::MessageHash do
  it 'lets 32-byte strings pass through' do
    str = "\x00" * 32
    arg = described_class.new(str)
    expect(arg.for_ffi).to eql str
  end

  it 'uses to_str on non-string objects that respond to it' do
    str = "\x00" * 32
    d = double(to_str: str)
    arg = described_class.new(str)
    expect(arg.for_ffi).to eql str
  end

  it 'raises an ArgumentError if the msg32 is not a string' do
    expect { described_class.new(1234) }
      .to raise_error ArgumentError, 'msg32 must be a string'
  end

  it 'raises an ArgumentError if msg32 is not 32 bytes' do
    bad_hash = "\x00" * 31
    expect { described_class.new("\x00" * 31) }
      .to raise_error ArgumentError, 'msg32 must be 32 bytes long'
  end
end
