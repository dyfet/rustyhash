# About Tychosoft Rusty Hash

The purpose of this package is to introduce consistent hashing in Rust that is
consistent with my other implementations in use in other languages. Consistent
hashing is foundational to distributed computing and specialized data practices
such as dynamic node assignment for distributed caches and dynamic load
balancing, table sharding, etc.

Consistent hashing also has to be implemented consistently regardless of system
platform (endianness) or language. You do not want a service that runs on a
different endian architecture or that is written in another language to select
nodes differently.

I focus on two things in this library; a generic consistent hasher for reducing
hash digests to 64 bit values using the top 8 bytes of a hash digest in big
endian (network) byte order, and a hash ring which is often used to distribute
services to keys. The latter must have identical behavior, especially around
vnodes and ring collissions. This implementation matches the C++ reference
implimentation in ModernCLI, and my go services implimentation at
https://gitlab.com/tychosoft/service

## Dependencies

Net 8 or later is required since I use sha3. Otherwise this has no direct
external dependencies. It is only implementation bound, to match other
languages.

## Distributions

The primary means to distribute rusty hash is as a mozilla crate and the latest
release should be made available thru the mozilla crate site. A stand-alone
detached source tarball may also be produced from a repository checkout.

