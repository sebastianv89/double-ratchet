# Double Ratchet

[![](https://img.shields.io/crates/v/double-ratchet.svg)][crates]
[![](https://docs.rs/double-ratchet/badge.svg)][docs]
[![](https://api.travis-ci.org/sebastianv89/double-ratchet.svg)](https://travis-ci.org/sebastianv89/double-ratchet)


A pure Rust implementation of the Double Ratchet, as [specified][specs] by
Trevor Perrin and Moxie Marlinspike.

The Double Ratchet allows two users to communicate securely: it provides its
users with a *confidential* and *authentic* channel, which includes *forward
secrecy* and *future secrecy*. After initialization with a shared secret key
and an authenticated public key, the Double Ratchet will automatically handle
all key management required to support this channel, which includes handling
the decryption of messages that arrive out-of-order.

The Double Ratchet itself requires a public key crypto system that can perform
[Diffie-Hellman][dh] (DH) operations, a secret key crypto system that provides
[authenticated encryption with associated data][aead] (AEAD) and two [key
derivation functions][kdf] (KDF). This crate aims to be agnostic towards the
implementation of these functions: users of the crate implement the
`CryptoProvider` trait and the `DoubleRatchet` struct should take care of the
rest (but contact me if you have a use-case where the interface is not
sufficient and I'll see if I can accommodate).


## Examples

The following example corresponds to the way the Double Ratchet is used in the
[Signal protocol][signal].  For more details about the implementation, see
`tests/signal.rs`, which also supplies `SignalCryptoProvider`. We assume
that Alice and Bob share a secret key `SK` and Alice knows Bob's public
key.

```rust
use double_ratchet::{DoubleRatchet};
use rand_os::RandOs;
let mut rng = OsRng::new().unwrap();

type DR = DoubleRatchet<SignalCryptoProvider>;

// Alice intializes and sends the first message
let mut alice = DR::new_alice(&SK, bobs_public_prekey, None, &mut rng);
let pt0 = b"Hello Bob";
let (h0, ct0) = alice.ratchet_encrypt(pt0, b"A2B", &mut rng);

// Bob initializes and receives the first message
let mut bob = DR::new_bob(&SK, bobs_prekey_pair, None);
assert_eq!(
    Ok(Vec::from(&pt0[..])),
    bob.ratchet_decrypt(&h0, &ct0, b"A2B")
);

// After receiving the first message, Bob can send his replies
let pt1 = b"Hi Alice";
let (h1, ct1) = alice.ratchet_encrypt(pt1, b"B2A", &mut rng);
let pt2 = b"How are you?";
let (h2, ct2) = bob.ratchet_encrypt(pt2, b"B2A", &mut rng);
assert_eq!(
    Ok(Vec::from(&pt_b_0[..])),
    alice.ratchet_decrypt(&h_b_0, &ct_b_0, b"B2A")
);

// Note that Alice has not yet received Bob's first message...
let pt3 = b"Good and you?";
let (h3, ct3) = alice.ratchet_encrypt(pt3, b"A2B", &mut rng);
assert_eq!(
    Ok(Vec::from(&pt3[..])),
    bob.ratchet_decrypt(&h3, &ct3, b"A2B")
);
// ...but when she does get it she will be able to decrypt
assert_eq!(
    Ok(Vec::from(&pt1[..])),
    alice.ratchet_decrypt(&h1, &ct1, b"B2A")
);
```


## Installation

The Double Ratchet crate is distributed through [crates.io][crates]: install it
by adding the following to your `Cargo.toml`:

```toml
[dependencies]
double-ratchet = "0.1"
```

The `std` feature is enabled by default. To remove the dependency on the
standard library requires nightly because of dependency on the [`alloc`
crate](https://doc.rust-lang.org/alloc/): compile with `--no-default-features
--features "nightly"`.


## Documentation

The documentation is available [here][docs].


## Future plans

This isn't even my final form! I intend to add at least the following features
and am open for suggestions for more features.

- [ ] a Header Encrypted variant of the Double Ratchet
- [ ] generalize the `KeyStore` to allow automatic deletion of very old keys
- [ ] provide a way for saving/restoring a `DoubleRatchet` to storage
- [ ] Provide a non-allocating interface for encryption/decryption


[aead]: https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)
[crates]: https://crates.io/crates/double-ratchet
[dh]: https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange
[docs]: https://docs.rs/double-ratchet
[kdf]: https://en.wikipedia.org/wiki/Key_derivation_function
[signal]: https://signal.org/
[specs]: https://signal.org/docs/specifications/doubleratchet/

