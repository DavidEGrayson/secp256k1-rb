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
* Avoids making assumptions about the behavior of the library that do not come from the official documentation.
* Exception messages produced by this wrapper are less verbose than they could be to help avoid leaking secret information.


## Installation instructions

If you are using Mac OS X and Homebrew, run these commands to install required development tools:

````
$ brew install autoconf
$ brew install automake
$ brew install libtool
````

Then download and install the library:

````
$ git clone git@github.com:bitcoin/secp256k1.git
$ cd secp256k1
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
````

Then install the secp256k1 gem:

````
$ gem install secp256k1
````

Or add this line to your Gemfile:

````
gem 'secp256k1'
````
