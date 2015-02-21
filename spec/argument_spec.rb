require 'spec_helper'

describe Secp256k1::Argument::StringIn do
  it 'raises an ArgumentError if the arg is not a string' do
    expect { described_class.new(1234, :foo) }
      .to raise_error ArgumentError, 'foo must be a string'
  end

  describe 'with specific length' do
    let(:length) { 44 }
    let(:opts) { { length: length } }

    it 'lets strings with the right length pass through' do
      str = "\x00" * length
      arg = described_class.new(str, :foo, opts)
      expect(arg.string).to eql str
    end

    it 'raises an ArgumentError if arg is not 32 bytes' do
      expect { described_class.new("\x00" * 31, :foo, opts) }
        .to raise_error ArgumentError, 'foo must be 44 bytes long'
    end
  end
end

describe Secp256k1::Argument::NonceFunction do
  describe 'wrapper proc' do
    let(:msg32) { "\xAA".force_encoding('ASCII-8BIT') * 32 }
    let(:msg32_ptr) do
      msg32_ptr = FFI::MemoryPointer.new(:uchar, 32)
      msg32_ptr.write_string msg32
    end

    let(:seckey) { "\xBB".force_encoding('ASCII-8BIT') * 32 }

    let(:seckey_ptr) do
      seckey_ptr = FFI::MemoryPointer.new(:uchar, 32)
      seckey_ptr.write_string seckey
    end

    before do
      @wrapped_proc_return = nil
      @nonce_buffer = FFI::MemoryPointer.new(:uchar, 32)
      @proc = proc do |msg32, seckey, n|
        @arg_msg32_to_proc = msg32
        @arg_seckey_to_proc = seckey
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

    it 'passes the right arguments to the wrapped proc' do
      @wrapper_proc.call(nil, msg32_ptr, seckey_ptr, 4, nil)
      expect(@arg_n_to_proc).to eq 4
      expect(@arg_seckey_to_proc).to eq seckey
      expect(@arg_msg32_to_proc).to eq msg32
    end

    context 'when the wrapped proc returns a 32-byte string' do
      before do
        @wrapped_proc_return = "\x55" * 32
      end

      it 'returns 1' do
        result = @wrapper_proc.call(@nonce_buffer, msg32_ptr, seckey_ptr, 4, nil)
        expect(result).to eq 1
      end

      it 'puts the nonce data into the buffer pointed to by the first argument' do
        @wrapper_proc.call(@nonce_buffer, msg32_ptr, seckey_ptr, 4, nil)
        expect(@nonce_buffer.read_string(32)).to eq @wrapped_proc_return
      end
    end

    it 'when the wrapped proc returns nil, returns 0' do
      @wrapped_proc_return = nil
      result = @wrapper_proc.call(nil, msg32_ptr, seckey_ptr, 4, nil)
      expect(result).to eq 0
    end

    it 'when the wrapped proc returns a bad-length string, returns 0' do
      @wrapped_proc_return = "\x00" * 31
      expect { @wrapper_proc.call(nil, msg32_ptr, seckey_ptr, 4, nil) }
        .to raise_error 'nonce must be 32 bytes long'
    end

    it 'when the wrapped proc returns junk, raises an exception' do
      @wrapped_proc_return = Object.new
      expect { @wrapper_proc.call(nil, msg32_ptr, seckey_ptr, 4, nil) }
        .to raise_error 'nonce must be a string'
    end
  end

  it 'converts :default to secp256k1_nonce_function_default' do
    arg = described_class.new(:default)
    expect(arg.func).to eq Secp256k1::ForeignLibrary.secp256k1_nonce_function_default
  end

  it 'converts nil to nil' do
    arg = described_class.new(nil)
    expect(arg.func).to eq nil
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

describe Secp256k1::Argument::FixedStringOut do
  let(:length) { 14 }
  subject(:arg) { described_class.new(length) }

  it 'makes a buffer with the right length' do
    expect(arg.pointer).to be_a FFI::MemoryPointer
    expect(arg.pointer.size).to eq length
  end

  it 'converts the buffer to a string for ruby' do
    str = 'a' * length
    arg.pointer.put_bytes(0, str)
    expect(arg.value).to eq str
  end
end

describe Secp256k1::Argument::FixedStringInOut do
  let(:length) { 5 }
  subject(:arg) { described_class.new('david', :name, length) }

  it 'raises an ArgumentError if the input is not a string' do
    expect { described_class.new(1234, :foo, 7) }.to raise_error \
      ArgumentError, 'foo must be a string'
  end

  it 'raises an ArgumentError if the input is the wrong length' do
    expect { described_class.new('abcdefgh', :foo, 7) }.to raise_error \
      ArgumentError, 'foo must be 7 bytes long'
  end

  it 'makes a buffer with the right length' do
    expect(arg.pointer).to be_a FFI::MemoryPointer
    expect(arg.pointer.size).to eq length
  end

  it 'sets the buffer to the right contents' do
    expect(arg.pointer.read_bytes(length)).to eq 'david'
  end

  it 'converts the buffer to a string for ruby' do
    str = 'a' * length
    arg.pointer.put_bytes(0, str)
    expect(arg.value).to eq str
  end
end

describe Secp256k1::Argument::RecidOut do
  subject(:arg) { described_class.new }

  it 'makes pointer for an int' do
    expect(arg.pointer).to be_a FFI::MemoryPointer
    expect(arg.pointer.size).to eq FFI.type_size(FFI::Type::INT)
  end

  it 'can get the value from the pointer' do
    arg.pointer.write_int(0x0addbeef)
    expect(arg.value).to eq 0x0addbeef
  end
end

describe Secp256k1::Argument::VarStringOut do
  let(:length) { 22 }
  subject(:arg) { described_class.new(length) }

  it 'makes a buffer for ffi with the right length' do
    expect(arg.pointer).to be_a FFI::MemoryPointer
    expect(arg.pointer.size).to eq length
  end

  it 'makes a pointer to an int holding the length' do
    expect(arg.size_pointer).to be_a FFI::MemoryPointer
    expect(arg.size_pointer.read_int).to eq length
  end

  it 'converts the buffer to a string for ruby' do
    str = 'satoshi'
    arg.pointer.put_bytes(0, str)
    arg.size_pointer.write_int(str.bytesize)
    expect(arg.value).to eq str
  end
end

describe Secp256k1::Argument::Boolean do
  it 'converts true to 1' do
    expect(described_class.new(true, :foo).to_i).to eq 1
  end

  it 'converts false to 0' do
    expect(described_class.new(true, :foo).to_i).to eq 1
  end

  it 'converts nil to 0' do
    expect(described_class.new(true, :foo).to_i).to eq 1
  end

  it 'raises an exception for anything else' do
    expect { described_class.new(1, :foo) }.to raise_error \
      ArgumentError, 'foo must be true, false, or nil'
  end
end

describe Secp256k1::Argument::VarStringInOut do
  let(:max_length) { 7 }

  it 'raises an ArgumentError if the input is not a string' do
    expect { described_class.new(1234, :foo, 7) }.to raise_error \
      ArgumentError, 'foo must be a string'
  end

  it 'raises an ArgumentError if the input is too long' do
    expect { described_class.new('abcdefgh', :foo, 7) }.to raise_error \
      ArgumentError, 'foo is too long'
  end

  describe 'buffer' do
    subject(:pointer) { described_class.new('hi', :foo, 7).pointer }

    it 'is large enough to hold a max_length string' do
      expect(pointer.size).to eq max_length
    end

    it 'initially holds in_value' do
      expect(pointer.read_string(2)).to eq 'hi'
    end
  end

  describe 'size_pointer' do
    subject(:size_pointer) { described_class.new('hi', :foo, 7).size_pointer }

    it 'points to an int' do
      expect(size_pointer.size).to eq FFI.type_size(FFI::Type::INT)
    end

    it 'initially has in_value.length' do
      expect(size_pointer.read_int).to eq 2
    end
  end

  describe 'length' do
    subject(:length) { described_class.new('hi', :foo, 7).length }

    it 'initially has in_value.length' do
      expect(length).to eq 2
    end
  end

  describe 'value' do
    it 'gets the string value specified by the two pointers' do
      arg = described_class.new('hi', :foo, max_length)
      expect(arg.value).to eq 'hi'
      arg.pointer.put_bytes(0, 'bye')
      arg.size_pointer.write_int(3)
      expect(arg.value).to eq 'bye'
    end
  end
end
