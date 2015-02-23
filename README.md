[![Build Status](https://travis-ci.org/DavidEGrayson/secp256k1-rb.svg?branch=master)](https://travis-ci.org/DavidEGrayson/secp256k1-rb)
[![Coverage Status](https://img.shields.io/coveralls/DavidEGrayson/secp256k1-rb.svg)](https://coveralls.io/r/DavidEGrayson/secp256k1-rb)
[![Gem Version](https://badge.fury.io/rb/secp256k1.svg)](http://badge.fury.io/rb/secp256k1)

# secp256k1: a Ruby wrapper for libsecp256k1

This Ruby gem wraps [libsecp256k1](https://github.com/bitcoin/secp256k1), an optimized C library for EC operations on the secp256k1 curve.  The C library was originally written by Peter Wiulle for Bitcoin Core.  This wrapper was originally written by Andy Alness, originally gemified by Micah Winkelspecht, and is currently being developed by [David Grayson](https://github.com/DavidEGrayson).

Features of this wrapper (which have not all been achieved yet):

* Provides access to all features of the secp256k1 library.
* Does not add any new features.
* Avoids making arbitrary decisions when possible.
* Provides a safe interface: there should be no way for a user of the wrapper to cause undefined behavior or memory leaks.  (One exception is multiple threads are used in an unsafe way.)
* Exception messages produced by this wrapper are less verbose than they could be to help avoid leaking secret information.


## This code is under construction!

This code is in a transitionary period for a few reasons:

* The `secp256k1` gem from rubygems.org comes from https://github.com/GemHQ/secp256k1-rb, not from the this repository.  That gem does not work with the latest version of libsecp256k1.
* The code in this repository depends on a [pull request](https://github.com/bitcoin/secp256k1/pull/208) from @sipa to libsecp256k1 which has not been merged in yet, as of 2015-02-06.
* The code in this repository is not complete yet, and is being developed by @DavidEGrayson.  It will not be considered complete and releasable until all features of the library are exposed and no TODO items are remaining.

Until these issues are resolved, the installation instructions below will not work and you will have to do some futzing to get this code to work.  You can look at `.travis.yml` for some helpful commands to run.

## Installation instructions

If you are using Mac OS X and Homebrew, run these commands to install required development tools:

```
$ brew install autoconf automake libtool
```

Then download and install the library:

```
$ git clone git@github.com:bitcoin/secp256k1.git
$ cd secp256k1
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

Then install the secp256k1 gem:

````
$ gem install secp256k1
````

Or add this line to your Gemfile:

````
gem 'secp256k1'
````

## Making a context

After requiring the library, you should create a context.  The context holds precomputed tables of data that are needed later when you are calling other methods in the library.  When creating the context, you must specify what features of the library you need.  To create a fully-functional context, do this:

```ruby
Secp256k1::Context.new(sign: true, verify: true)
```

If you call a method that requires a feature that has not been initialized yet in the context object, then libsecp256k1 will abort the entire process it is running inside.

Creating a context is a relatively expensive operation in terms of time and memory, so you should generally just do it once when your code is loaded.  If your program has multiple, independent sections that use the library, it is fine for each different section to create its own context.

If you are writing a simple script, you might create a context with a few lines like this at the top of the file.

```ruby
require 'secp256k1'
context = Secp256k1::Context.new(sign: true, verify: true)
# do stuff with context
```

If you are writing a library, you might create a context like this:

```ruby
require 'secp256k1'

class MyClass
  Context = Secp256k1::Context.new(sign: true, verify: true)

  def your_method
    # do stuff with Context
  end
end
```


## Generating a secret key

An ECDSA secret key is a random number between 1 and the order of the group being used.  This library represents secret keys as 32-byte binary strings that hold the number in Big Endian format (most significant bytes first).

If you trust the `SecureRandom` class provided by your Ruby implementation, you could generate a secret key using this code:

```ruby
seckey = SecureRandom.random_bytes(32)
```

Keys generated in this way have a very small probability of being outside the allowed range.  If you want to be 100% sure that you generated a valid secret key, you can verify it:

```ruby
seckey = SecureRandom.random_bytes(32)
if context.ec_seckey_verify(seckey) != 1
  raise 'invalid secret key'
end
```


## Computing the public key for a secret key

You can generate the public key from the secret key.  The public key is a pair of coordinates representing a point on the curve.  Each public key has two interchangeable binary representations: a 33-byte compressed format, and a 65-byte uncompressed format.  The code below shows how to generate either format:

```ruby
# Create a compressed, 33-byte public key
pubkey = context.ec_pubkey_create(seckey, true)

# Create an uncompressed, 65-byte public key
pubkey = context.ec_pubkey_create(seckey, false)
```

## Signing a message

This example shows how to generate a signature for a message.  In this example, we will use SHA-256 as our digest algorithm, but other algorithms can be used, as long as they produce a 32-byte string.

This example assumes that you have required the `secp256k1` library, that you have a `Secp256k1::Context` object named `context`, and that you have the secret key stored in a variable named `seckey`.

```ruby
require 'digest'
message = 'libsecp256k1 is cool.'
digest = Digest::SHA256.digest(message)
signature = context.ecdsa_sign(message, seckey)
```

For advanced users, there is an optional third argument that controls how to generate the nonce/ephemeral key for the signature.  It is recommended to not specify the third argument, in which case a deterministic nonce-generation algorithm will be used (RFC6979).

## Verifying a signature

The code below shows how to verify an ECDSA signature.  It assumes you have strings representing the digest, signature, and public key.

```ruby
if context.ecdsa_verify(digest, signature, pubkey) == 1
  # signature is valid
else
  # signature is not valid
end
```

## Supported platforms

This library supports Ruby (MRI) 1.9.3 and later.  It also supports any Ruby implemenation that is both compatible with one of those MRI versions and has support for the `ffi` gem.  This includes JRuby, and Rubinius.