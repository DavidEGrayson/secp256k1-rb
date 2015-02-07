# coding: ascii-8bit

require 'coveralls'
Coveralls.wear! if Coveralls.will_run?

require 'secp256k1'
require 'ostruct'

require_relative 'hex_inspect'

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

ExampleSig1 = OpenStruct.new.tap do |e|
  e.secret_key = "\x42\x8a\xd2\x2c\xf5\x5a\x77\x07" \
                 "\xf2\xd6\x87\x39\x66\xab\x80\x09" \
                 "\x10\xd8\xb4\x0c\xc6\xc8\x6d\x23" \
                 "\x84\xc5\xa5\x79\x6d\x52\x78\x47"

  e.pubkey =
    "\x03" \
    "\x8f\xcf\x3e\xc3\xa4\xb5\x09\x87" \
    "\x16\x92\x93\x93\x58\xf5\x0c\x25" \
    "\xf8\xbe\xd3\x28\x64\x67\xf8\xa1" \
    "\xed\xd3\x2c\x50\xb7\x5a\xe1\x9f"

  e.pubkey_uncompressed =
    "\x04" \
    "\x8f\xcf\x3e\xc3\xa4\xb5\x09\x87" \
    "\x16\x92\x93\x93\x58\xf5\x0c\x25" \
    "\xf8\xbe\xd3\x28\x64\x67\xf8\xa1" \
    "\xed\xd3\x2c\x50\xb7\x5a\xe1\x9f" \
    "\x9b\x3d\xdd\x54\xc6\x55\x12\x1b" \
    "\x91\xca\xd2\xa5\x80\x9f\x0a\x91" \
    "\x96\xc8\x0c\x73\x6a\x89\x77\x1e" \
    "\x3c\x4a\x81\x0c\x19\x70\x61\xf7"

  e.message_hash = "\x07\xd0\x46\xd5\xfa\xc1\x2b\x3f" \
                   "\x82\xda\xf5\x03\x5b\x9a\xae\x86" \
                   "\xdb\x5a\xdc\x82\x75\xeb\xfb\xf0" \
                   "\x5e\xc8\x30\x05\xa4\xa8\xba\x3e"

  # arbitrary nonce
  e.nonce = "\xb8\xe7\xee\xd1\x9f\x47\xf0\xc0" \
            "\x55\x5b\xd6\xa5\xfc\xd5\xb2\xf7" \
            "\x8f\xcd\x21\xd3\xb0\xbc\xff\x6a" \
            "\x46\x6d\xe8\xd0\xb8\x4a\x05\x7a"

  # first nonce generated by RFC6979
  e.nonce_rfc6979_0 = "\x19\xc6\x09\x3f\x40\xd1\x68\x07" \
                      "\x2e\x92\xfe\x8b\x87\xbb\x30\x72" \
                      "\xdb\x4b\x20\xe9\x79\xea\xd6\xe7" \
                      "\x8a\xf2\x27\xc6\x4f\x82\x0c\x60"

  # second nonce generated by RFC6979
  e.nonce_rfc6979_1 = "\x61\x57\xa1\x65\x0a\xb4\x5f\x62" \
                      "\xab\xe8\x84\xb4\xe2\x18\xc0\xa8" \
                      "\x7c\x66\x9e\x11\x8b\x34\x2c\xcc" \
                      "\x37\x8a\x72\x52\x84\x27\x65\xf9"

  # Signature using arbitrary nonce.
  e.signature = "\x30\x45" \
                "\x02\x21" \
                "\x00\xe7\x87\x1d\xaf\xd2\x06\x90\x2b\xeb\x30\x8a\x56\xe9\x9b\x5f" \
                "\x34\xbf\xe1\xd8\xf6\xc1\x0b\x97\x4f\x3d\xc3\x0e\xf5\xf6\xf0\x52\x86" \
                "\x02\x20" \
                "\x6b\x87\x9a\xca\x90\x16\xde\x4e\xca\xc9\x15\xcf\x7a\x04\xb7\x6d" \
                "\x22\xfe\x9b\xfd\xc1\x88\xf4\x10\x3f\xaf\xd7\x1f\x70\x76\xda\x5f"

  # Compact signature using arbitrary nonce.
  e.signature_compact = [
    "\xe7\x87\x1d\xaf\xd2\x06\x90\x2b\xeb\x30\x8a\x56\xe9\x9b\x5f\x34" \
    "\xbf\xe1\xd8\xf6\xc1\x0b\x97\x4f\x3d\xc3\x0e\xf5\xf6\xf0\x52\x86" \
    "\x6b\x87\x9a\xca\x90\x16\xde\x4e\xca\xc9\x15\xcf\x7a\x04\xb7\x6d" \
    "\x22\xfe\x9b\xfd\xc1\x88\xf4\x10\x3f\xaf\xd7\x1f\x70\x76\xda\x5f",
    1
  ]

  # Signature using arbitrary nonce, high S value.
  e.signature_alt =
    "\x30\x46" \
    "\x02\x21" \
    "\x00\xe7\x87\x1d\xaf\xd2\x06\x90\x2b\xeb\x30\x8a\x56\xe9\x9b\x5f" \
    "\x34\xbf\xe1\xd8\xf6\xc1\x0b\x97\x4f\x3d\xc3\x0e\xf5\xf6\xf0\x52\x86" \
    "\x02\x21" \
    "\x00\x94\x78\x65\x35\x6f\xe9\x21\xb1\x35\x36\xea\x30\x85\xfb\x48" \
    "\x91\x97\xb0\x40\xe8\xed\xbf\xac\x2b\x80\x22\x87\x6d\x5f\xbf\x66\xe2"

  # Signature using RFC6979.
  e.signature_rfc6979 =
    "\x30\x45" \
    "\x02\x21" \
    "\x00\x86\x5d\x52\xcf\x06\x20\x7d\xcd\x90\x7d\x95\xd9\xe7\x44\x64" \
    "\x64\x51\xfc\x4a\xc1\x90\x3d\xaa\x5f\xc2\xd9\xd4\x7c\x5b\x44\xee\xcf" \
    "\x02\x20" \
    "\x29\x44\xf1\xbf\x65\x1c\x14\x5a\xcb\x4f\xb8\xd8\x1b\x13\xab\x9f" \
    "\x86\xcb\x69\xba\xda\xde\x98\x1b\x22\x36\x0b\x2c\x80\x5d\xe9\x7c"

  # Compact signature using RFC6979 (and recovery id).
  e.signature_compact_rfc6979 = [
    "\x86\x5d\x52\xcf\x06\x20\x7d\xcd\x90\x7d\x95\xd9\xe7\x44\x64\x64" \
    "\x51\xfc\x4a\xc1\x90\x3d\xaa\x5f\xc2\xd9\xd4\x7c\x5b\x44\xee\xcf" \
    "\x29\x44\xf1\xbf\x65\x1c\x14\x5a\xcb\x4f\xb8\xd8\x1b\x13\xab\x9f" \
    "\x86\xcb\x69\xba\xda\xde\x98\x1b\x22\x36\x0b\x2c\x80\x5d\xe9\x7c",
    0
  ]

  e.signature_nonce_default = e.signature_rfc6979
  e.signature_compact_nonce_default = e.signature_compact_rfc6979
end


