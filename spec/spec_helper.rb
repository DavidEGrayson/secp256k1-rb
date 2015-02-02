# coding: ascii-8bit

require 'coveralls'
Coveralls.wear!

require 'secp256k1'
require 'ostruct'

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    # This option will default to `true` in RSpec 4. It makes the `description`
    # and `failure_message` of custom matchers include text for helper methods
    # defined using `chain`, e.g.:
    # be_bigger_than(2).and_smaller_than(4).description
    #   # => "be bigger than 2 and smaller than 4"
    # ...rather than:
    #   # => "be bigger than 2"
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    # Prevents you from mocking or stubbing a method that does not exist on
    # a real object. This is generally recommended, and will default to
    # `true` in RSpec 4.
    mocks.verify_partial_doubles = true
  end
end

class String
  def hex_inspect
    '"' + each_byte.map { |b| '\x%02x' % b }.join + '"'
  end
end

ExampleSig1 = OpenStruct.new.tap do |e|
  e.secret_key = "\x42\x8a\xd2\x2c\xf5\x5a\x77\x07" \
                 "\xf2\xd6\x87\x39\x66\xab\x80\x09" \
                 "\x10\xd8\xb4\x0c\xc6\xc8\x6d\x23" \
                 "\x84\xc5\xa5\x79\x6d\x52\x78\x47"

  e.public_key = "\x03" \
                 "\x8f\xcf\x3e\xc3\xa4\xb5\x09\x87" \
                 "\x16\x92\x93\x93\x58\xf5\x0c\x25" \
                 "\xf8\xbe\xd3\x28\x64\x67\xf8\xa1" \
                 "\xed\xd3\x2c\x50\xb7\x5a\xe1\x9f"

  e.message_hash = "\x07\xd0\x46\xd5\xfa\xc1\x2b\x3f" \
                   "\x82\xda\xf5\x03\x5b\x9a\xae\x86" \
                   "\xdb\x5a\xdc\x82\x75\xeb\xfb\xf0" \
                   "\x5e\xc8\x30\x05\xa4\xa8\xba\x3e"

  e.nonce = "\xb8\xe7\xee\xd1\x9f\x47\xf0\xc0" \
            "\x55\x5b\xd6\xa5\xfc\xd5\xb2\xf7" \
            "\x8f\xcd\x21\xd3\xb0\xbc\xff\x6a" \
            "\x46\x6d\xe8\xd0\xb8\x4a\x05\x7a"

  e.signature = "\x30\x45" \
                "\x02\x21" \
                "\x00\xe7\x87\x1d\xaf\xd2\x06\x90\x2b\xeb\x30\x8a\x56\xe9\x9b\x5f" \
                "\x34\xbf\xe1\xd8\xf6\xc1\x0b\x97\x4f\x3d\xc3\x0e\xf5\xf6\xf0\x52\x86" \
                "\x02\x20" \
                "\x6b\x87\x9a\xca\x90\x16\xde\x4e\xca\xc9\x15\xcf\x7a\x04\xb7\x6d" \
                "\x22\xfe\x9b\xfd\xc1\x88\xf4\x10\x3f\xaf\xd7\x1f\x70\x76\xda\x5f"

  # Signature with a high S value, not compliant with BIP 0062.
  e.signature_alt = "\x30\x46" \
                    "\x02\x21" \
                    "\x00\xe7\x87\x1d\xaf\xd2\x06\x90\x2b\xeb\x30\x8a\x56\xe9\x9b\x5f" \
                    "\x34\xbf\xe1\xd8\xf6\xc1\x0b\x97\x4f\x3d\xc3\x0e\xf5\xf6\xf0\x52\x86" \
                    "\x02\x21" \
                    "\x00\x94\x78\x65\x35\x6f\xe9\x21\xb1\x35\x36\xea\x30\x85\xfb\x48" \
                    "\x91\x97\xb0\x40\xe8\xed\xbf\xac\x2b\x80\x22\x87\x6d\x5f\xbf\x66\xe2"
end


