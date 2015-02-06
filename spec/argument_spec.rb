require 'spec_helper'

describe Secp256k1::Argument::MessageHash do
  it 'lets 32-byte strings pass through' do
    str = "\x00" * 32
    arg = described_class.new(str)
    expect(arg.string).to eql str
  end

  it 'raises an ArgumentError if the arg is not a string' do
    expect { described_class.new(1234) }
      .to raise_error ArgumentError, 'msg32 must be a string'
  end

  it 'raises an ArgumentError if arg is not 32 bytes' do
    expect { described_class.new("\x00" * 31) }
      .to raise_error ArgumentError, 'msg32 must be 32 bytes long'
  end
end

describe Secp256k1::Argument::NonceFunction do
  describe 'wrapper proc' do
    before do
      @arg_n_proc = nil
      @wrapped_proc_return = nil
      @nonce_buffer = FFI::MemoryPointer.new(:uchar, 32)
      @proc = Proc.new do |n|
        @arg_n_to_proc = n
        @wrapped_proc_return
      end
      @wrapper_proc = described_class.new(@proc).func
    end

    it 'is a Proc' do
      expect(@wrapper_proc).to be_a_kind_of Proc
    end

    it 'takes 5 arguments' do
      expect(@wrapper_proc.arity).to eq 5
    end

    it 'passes the 4th argument (attempt number) to the wrapped proc' do
      @wrapper_proc.call(nil, nil, nil, 4, nil)
      expect(@arg_n_to_proc).to eq 4
    end

    context 'when the wrapped proc returns a 32-byte string' do
      before do
        @wrapped_proc_return = "\x55" * 32
      end

      it 'returns 1' do
        result = @wrapper_proc.call(@nonce_buffer, nil, nil, 4, nil)
        expect(result).to eq 1
      end

      it 'puts the nonce data into the buffer pointed to by the first argument' do
        result = @wrapper_proc.call(@nonce_buffer, nil, nil, 4, nil)
        expect(@nonce_buffer.read_string(32)).to eq @wrapped_proc_return
      end
    end

    it 'when the wrapped proc returns nil, returns 0' do
      @wrapped_proc_return = nil
      result = @wrapper_proc.call(nil, nil, nil, 4, nil)
      expect(result).to eq 0
    end

    it 'when the wrapped proc returns a bad-length string, returns 0' do
      @wrapped_proc_return = "\x00" * 31
      expect { @wrapper_proc.call(nil, nil, nil, 4, nil) }
        .to raise_error 'nonce must be 32 bytes long'
    end

    it 'when the wrapped proc returns junk, raises an exception' do
      @wrapped_proc_return = Object.new
      expect { @wrapper_proc.call(nil, nil, nil, 4, nil) }
        .to raise_error 'nonce must be a string'
    end
  end

  it 'accepts procs' do
    proc = Proc.new { }
    arg = described_class.new(proc)
    arg.func.call(nil, nil, nil, 4, nil)
  end

  it 'converts :default to secp256k1_nonce_function_default' do
    arg = described_class.new(:default)
    expect(arg.func).to eq Secp256k1::ForeignLibrary.secp256k1_nonce_function_default
  end

  it 'converts nil to secp256k1_nonce_function_default also' do
    arg = described_class.new(nil)
    expect(arg.func).to eq Secp256k1::ForeignLibrary.secp256k1_nonce_function_default
  end

  it 'converts :rfc6979 to secp256k1_nonce_function_rfc6979' do
    arg = described_class.new(:rfc6979)
    expect(arg.func).to eq Secp256k1::ForeignLibrary.secp256k1_nonce_function_rfc6979
  end
end

describe Secp256k1::Argument::NonceOut do
  subject(:arg) { described_class.new }

  it 'makes a 32-byte buffer for ffi' do
    expect(arg.pointer).to be_a FFI::MemoryPointer
    expect(arg.pointer.size).to eq 32
  end

  it 'converts the buffer to a string for ruby' do
    str = "\x60\x00" * 16
    arg.pointer.put_bytes(0, str)
    expect(arg.value).to eq str
  end
end


describe Secp256k1::Argument::SecretKeyIn do
  it 'lets 32-byte strings pass through' do
    str = "\x00" * 32
    arg = described_class.new(str)
    expect(arg.string).to eql str
  end

  it 'raises an ArgumentError if arg is not a string' do
    expect { described_class.new(1234) }
      .to raise_error ArgumentError, 'seckey must be a string'
  end

  it 'raises an ArgumentError if arg is not 32 bytes' do
    expect { described_class.new("\x00" * 31) }
      .to raise_error ArgumentError, 'seckey must be 32 bytes long'
  end
end

describe Secp256k1::Argument::SignatureOut do
  subject(:arg) { described_class.new }

  it 'makes a 72-byte buffer for ffi' do
    expect(arg.pointer).to be_a FFI::MemoryPointer
    expect(arg.pointer.size).to eq 72
  end

  it 'makes a pointer to the int 72' do
    expect(arg.size_pointer).to be_a FFI::MemoryPointer
    expect(arg.size_pointer.read_int).to eq 72
  end

  it 'converts the buffer to a string for ruby' do
    str = 'satoshi'
    arg.pointer.put_bytes(0, str)
    arg.size_pointer.write_int(str.bytesize)
    expect(arg.value).to eq str
  end
end
