# Secp256k1: A ruby wrapper for libsecp256k1

This is a ruby wrapper for using libsecp256k1 in Ruby. The c library was originally written by Peter Wiulle for use in Bitcoin core libraries to replace OpenSSL for Bitcoin cryptographic functions.
This FFI wrapper was originally written by Andy Alness and gemified by Micah Winkelspecht.

## Installation instructions

You must first install libsecp256k1

````
    $ brew install autoconf
    $ brew install automake
    $ brew install libtool

    $ git clone git@github.com:bitcoin/secp256k1.git
    $ cd secp256k1

    $ ./autogem.sh
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