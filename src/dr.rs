use core::{cmp, fmt, hash::Hash};
use hashbrown::HashMap;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

// TODO: avoid heap allocations in encrypt/decrypt interfaces
// TODO: make stuff like MAX_SKIP and MKS_CAPACITY dynamic
// TODO: HeaderEncrypted version

// Upper limit on the receive chain ratchet steps when trying to decrypt. Prevents a
// denial-of-service attack where the attacker
const MAX_SKIP: usize = 1000;

/// Message Counter (as seen in the header)
pub type Counter = u32;

/// The `DoubleRatchet` can encrypt/decrypt messages while providing forward secrecy and
/// post-compromise security.
///
/// The `DoubleRatchet` struct provides an implementation of the Double Ratchet Algorithm as
/// defined in its [specification], including the unspecified symmetric initialization. After
/// initialization (with `new_alice` or `new_bob`) the user can interact with the `DoubleRatchet`
/// using the `ratchet_encrypt` and `ratchet_decrypt` methods, which automatically takes care of
/// deriving the correct keys and updating the internal state.
///
/// # Initialization
///
/// When Alice and Bob want to use the `DoubleRatchet`, they need to initialize it using different
/// constructors. The "Alice" or "Bob" role follows from the design of the authenticated key
/// exchange that is used to initialize the secure communications channel. Two "modes" are
/// possible, depending on whether just one or both of the parties must be able to send the first
/// data message. See `new_alice` and `new_bob` for further details.
///
/// # Provided security
///
/// Conditional on the correct implementation of the `CryptoProvider`, the `DoubleRatchet` provides
/// confidentiality of the plaintext and authentication of both the ciphertext and associated data.
/// It does not provide anonymity, as the headers have to be sent in plain text and are sufficient
/// for identifying the communicating parties. See `CryptoProvider` for further details on the
/// required security properties.
///
/// Forward secrecy (sometimes called the key-erasure property) preserves confidentiality of old
/// messages in case of a device compromise. The `DoubleRatchet` provides forward secrecy by
/// deriving a fresh key for every message: the sender deletes it immediately after encrypting and
/// the receiver deletes it immediately after successful decryption. Messages may arrive out of
/// order, in which case the receiver is able to derive and store the keys for the skipped messages
/// without compromising the forward secrecy of other messages. See [secure deletion] for further
/// discussion.
///
/// Post-compromise security (sometimes called future secrecy or the self-healing property)
/// restores confidentiality of new messages in case of a past device compromise. The
/// `DoubleRatchet` provides future secrecy by generating a fresh `KeyPair` for every reply that is
/// being sent. See [recovery from compromise] for further discussion and [post-compromise] for an
/// in-depth analysis of the subject.
///
/// # Examples
///
/// If Alice is guaranteed to send the first message to Bob, she can initialize her `DoubleRatchet`
/// as shown here, without providing the symmetric `initial_receive` key. It is assumed that
/// `shared_secret` and `bobs_public_key` are the result of some secure key exchange. A higher
/// level protocol may force Alice to always send an empty initial message in order to fully
/// initialize both parties.
///
/// ```
/// # use double_ratchet::{mock, KeyPair, DoubleRatchet, EncryptUninit};
/// # type MyCryptoProvider = mock::CryptoProvider;
/// # let mut csprng = mock::Rng::default();
/// # let bobs_keypair = mock::KeyPair::new(&mut csprng);
/// # let bobs_public_key = bobs_keypair.public().clone();
/// # let shared_secret = [42, 0];
/// type DR = DoubleRatchet<MyCryptoProvider>;
/// /// Alice and Bob have agreed on `shared_secret` and `bobs_public_key`
/// let mut alice = DR::new_alice(&shared_secret, bobs_public_key, None, &mut csprng);
/// let mut bob = DR::new_bob(shared_secret, bobs_keypair, None);
///
/// /// Bob cannot send to Alice
/// assert_eq!(Err(EncryptUninit), bob.try_ratchet_encrypt(b"Hi Alice", b"B2A", &mut csprng));
///
/// /// Alice can send to Bob
/// let (head, ct) = alice.ratchet_encrypt(b"Hello Bob", b"A2B", &mut csprng);
/// let pt = bob.ratchet_decrypt(&head, &ct, b"A2B").unwrap();
/// assert_eq!(&pt[..], b"Hello Bob");
///
/// /// Now Bob can send to Alice
/// let (head, ct) = bob.ratchet_encrypt(b"Hi Alice", b"B2A", &mut csprng);
/// let pt = alice.ratchet_decrypt(&head, &ct, b"B2A").unwrap();
/// assert_eq!(&pt[..], b"Hi Alice");
/// ```
///
/// If it is required that either party can send the first message, the key exchange must provide
/// us with an `extra_shared_secret`.
///
/// ```
/// # use double_ratchet::{mock, KeyPair, DoubleRatchet};
/// # type MyCryptoProvider = mock::CryptoProvider;
/// # let mut csprng = mock::Rng::default();
/// # let bobs_keypair = mock::KeyPair::new(&mut csprng);
/// # let bobs_public_key = bobs_keypair.public().clone();
/// # let shared_secret = [42, 0];
/// # let extra_shared_secret = [42, 0, 0];
/// # type DR = DoubleRatchet<MyCryptoProvider>;
/// let mut alice = DR::new_alice(&shared_secret, bobs_public_key, Some(extra_shared_secret), &mut csprng);
/// let mut bob = DR::new_bob(shared_secret, bobs_keypair, Some(extra_shared_secret));
///
/// /// Either Alice or Bob can send the first message
/// let (head_bob, ct_bob) = bob.ratchet_encrypt(b"Hi Alice", b"from Bob to Alice", &mut csprng);
/// let (head_alice, ct_alice) = alice.ratchet_encrypt(b"Hello Bob", b"from Alice to Bob", &mut csprng);
/// let pt_bob = alice.ratchet_decrypt(&head_bob, &ct_bob, b"from Bob to Alice").unwrap();
/// let pt_alice = bob.ratchet_decrypt(&head_alice, &ct_alice, b"from Alice to Bob").unwrap();
/// assert_eq!(&pt_alice[..], b"Hello Bob");
/// assert_eq!(&pt_bob[..], b"Hi Alice");
/// ```
///
/// [post-compromise]: https://eprint.iacr.org/2016/221
/// [specification]: https://signal.org/docs/specifications/doubleratchet/#double-ratchet-1
/// [secure deletion]: https://signal.org/docs/specifications/doubleratchet/#secure-deletion
/// [recovery from compromise]: https://signal.org/docs/specifications/doubleratchet/#recovery-from-compromise
pub struct DoubleRatchet<CP: CryptoProvider> {
    dhs: CP::KeyPair,
    dhr: Option<CP::PublicKey>,
    rk: CP::RootKey,
    cks: Option<CP::ChainKey>,
    ckr: Option<CP::ChainKey>,
    ns: Counter,
    nr: Counter,
    pn: Counter,
    mkskipped: KeyStore<CP>,
}

impl<CP> fmt::Debug for DoubleRatchet<CP>
where
    CP: CryptoProvider,
    CP::KeyPair: fmt::Debug,
    CP::PublicKey: fmt::Debug,
    CP::RootKey: fmt::Debug,
    CP::ChainKey: fmt::Debug,
    CP::MessageKey: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DoubleRatchet {{ dhs: {:?}, dhr: {:?}, rk: {:?}, cks: {:?}, ckr: {:?}, ns: {:?}, \
             nr: {:?}, pn: {:?}, mkskipped: {:?} }}",
            self.dhs,
            self.dhr,
            self.rk,
            self.cks,
            self.ckr,
            self.ns,
            self.nr,
            self.pn,
            self.mkskipped
        )
    }
}

impl<CP: CryptoProvider> DoubleRatchet<CP> where {
    /// Initialize "Alice": the sender of the first message.
    ///
    /// This implements `RatchetInitAlice` as defined in the [specification] when `initial_receive
    /// = None`: after initialization Alice must send a message to Bob before he is able to provide
    /// a reply.
    ///
    /// Alternatively Alice provides an extra symmetric key: `initial_receive = Some(key)`, so that
    /// both Alice and Bob can send the first message. Note however that even when Alice and Bob
    /// initialize this way the initialization is asymmetric in the sense that Alice requires Bob's
    /// public key.
    ///
    /// Either Alice and Bob must supply the same extra symmetric key or both must supply `None`.
    ///
    /// # Security considerations
    ///
    /// For security, initialization through `new_alice` has the following requirements:
    ///  - `shared_secret` must be both *confidential* and *authenticated*
    ///  - `them` must be *authenticated*
    ///  - `initial_receive` is `None` or `Some(key)` where `key` is *confidential* and *authenticated*
    ///
    /// [specification]: https://signal.org/docs/specifications/doubleratchet/#initialization
    pub fn new_alice<R: CryptoRng + RngCore>(
        shared_secret: &CP::RootKey,
        them: CP::PublicKey,
        initial_receive: Option<CP::ChainKey>,
        rng: &mut R,
    ) -> Self {
        let dhs = CP::KeyPair::new(rng);
        let (rk, cks) = CP::kdf_rk(shared_secret, &CP::diffie_hellman(&dhs, &them));
        Self {
            dhs,
            dhr: Some(them),
            rk,
            cks: Some(cks),
            ckr: initial_receive,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: KeyStore::new(),
        }
    }

    /// Initialize "Bob": the receiver of the first message.
    ///
    /// This implements `RatchetInitBob` as defined in the [specification] when `initial_send =
    /// None`: after initialization Bob must receive a message from Alice before he can send his
    /// first message.
    ///
    /// Alternatively Bob provides an extra symmetric key: `initial_send = Some(key)`, so that both
    /// Alice and Bob can send the first message. Note however that even when Alice and Bob
    /// initialize this way the initialization is asymmetric in the sense that Bob must provide his
    /// public key to Alice.
    ///
    /// Either Alice and Bob must supply the same extra symmetric key or both must supply `None`.
    ///
    /// # Security considerations
    ///
    /// For security, initialization through `new_bob` has the following requirements:
    ///  - `shared_secret` must be both *confidential* and *authenticated*
    ///  - the private key of `us` must remain secret on Bob's device
    ///  - `initial_send` is `None` or `Some(key)` where `key` is *confidential* and *authenticated*
    ///
    /// [specification]: https://signal.org/docs/specifications/doubleratchet/#initialization
    pub fn new_bob(
        shared_secret: CP::RootKey,
        us: CP::KeyPair,
        initial_send: Option<CP::ChainKey>,
    ) -> Self {
        Self {
            dhs: us,
            dhr: None,
            rk: shared_secret,
            cks: initial_send,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: KeyStore::new(),
        }
    }

    /// Try to encrypt the `plaintext`. See `ratchet_encrypt` for details.
    ///
    /// Fails with `EncryptUninit` when `self` is not yet initialized for encrypting.
    pub fn try_ratchet_encrypt<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<(Header<CP::PublicKey>, Vec<u8>), EncryptUninit> {
        if self.can_encrypt() {
            Ok(self.ratchet_encrypt(plaintext, associated_data, rng))
        } else {
            Err(EncryptUninit)
        }
    }

    /// Encrypt the `plaintext`, ratchet forward and return the (header, ciphertext) pair.
    ///
    /// Implements `RatchetEncrypt` as defined in the [specification]. The header should be sent
    /// along the ciphertext in order for the recipient to be able to `ratchet_decrypt`. The
    /// ciphertext is encrypted in some
    /// [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) mode, which encrypts the
    /// `plaintext` and authenticates the `plaintext`, `associated_data` and the header.
    ///
    /// The internal state of the `DoubleRatchet` is automatically updated so that the next message
    /// key be sent with a fresh key.
    ///
    /// Note that `rng` is only used for updating the internal state and not for encrypting the
    /// data.
    ///
    /// # Panics
    ///
    /// Panics if `self` is not initialized for sending yet. If this is a concern, use
    /// `try_ratchet_encrypt` instead to avoid panics.
    ///
    /// [specification]: https://signal.org/docs/specifications/doubleratchet/#encrypting-messages
    pub fn ratchet_encrypt<R: CryptoRng + RngCore>(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> (Header<CP::PublicKey>, Vec<u8>) {
        // TODO: is this the correct place for clear_stack_on_return?
        let (h, mk) = self.ratchet_send_chain(rng);
        let pt = CP::encrypt(&mk, plaintext, &Self::concat(&h, associated_data));
        (h, pt)
    }

    // Are we initialized such that we can encrypt messages?
    fn can_encrypt(&self) -> bool {
        self.cks.is_some() || self.dhr.is_some()
    }

    // Ratcheting forward the DH chain for sending is delayed until the first message in that chain
    // is going to be sent.
    //
    // [specification]: https://signal.org/docs/specifications/doubleratchet/#deferring-new-ratchet-key-generation
    //
    // # Panics
    //
    // Panics if encrypting is not yet initialized
    fn ratchet_send_chain<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
    ) -> (Header<CP::PublicKey>, CP::MessageKey) {
        if self.cks.is_none() {
            let dhr = self
                .dhr
                .as_ref()
                .expect("not yet initialized for encryption");
            self.dhs = CP::KeyPair::new(rng);
            let (rk, cks) = CP::kdf_rk(&self.rk, &CP::diffie_hellman(&self.dhs, dhr));
            self.rk = rk;
            self.cks = Some(cks);
            self.pn = self.ns;
            self.ns = 0;
        }
        let h = Header {
            dh: self.dhs.public().clone(),
            n: self.ns,
            pn: self.pn,
        };
        let (cks, mk) = CP::kdf_ck(self.cks.as_ref().unwrap());
        self.cks = Some(cks);
        self.ns += 1;
        (h, mk)
    }

    /// Verify-decrypt the `ciphertext`, update `self` and return the plaintext.
    ///
    /// Implements `RatchetDecrypt` as defined in the [specification]. Decryption of the ciphertext
    /// includes verifying the authenticity of the `header`, `ciphertext` and `associated_data`
    /// (optional).
    ///
    /// `self` is automatically updated upon successful decryption. This includes ratcheting
    /// forward the receiving key-chain and DH key-chain (if necessary) and storing the
    /// `MessageKeys` of any skipped messages so these messages can be decrypted if they arrive out
    /// of order.
    ///
    /// Returns a `DecryptError` when the plaintext could not be decrypted: `self` remains
    /// unchanged in that case. There could be many reasons: inspect the returned error-value for
    /// further details.
    ///
    /// [specification]: https://signal.org/docs/specifications/doubleratchet/#decrypting-messages-1
    pub fn ratchet_decrypt(
        &mut self,
        header: &Header<CP::PublicKey>,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        // TODO: is this the correct place for clear_stack_on_return?
        let (diff, pt) =
            self.try_decrypt(header, ciphertext, &Self::concat(&header, associated_data))?;
        self.update(diff, header);
        Ok(pt)
    }

    // The actual decryption. Gets a (non-mutable) reference to self to ensure that the state is
    // not changed. Upon successful decryption the state must be updated. The minimum amount of work
    // is done in order to retrieve the correct `MessageKey`: the returned `Diff` object contains
    // the result of that work to avoid doing the work again.
    fn try_decrypt(
        &self,
        h: &Header<CP::PublicKey>,
        ct: &[u8],
        ad: &[u8],
    ) -> Result<(Diff<CP>, Vec<u8>), DecryptError> {
        use Diff::*;
        if let Some(mk) = self.mkskipped.get(&h.dh, h.n) {
            Ok((OldKey, CP::decrypt(mk, ct, ad)?))
        } else if self.dhr.as_ref() == Some(&h.dh) {
            let (ckr, mut mks) =
                Self::skip_message_keys(self.ckr.as_ref().unwrap(), self.get_current_skip(h)?);
            let mk = mks.pop().unwrap();
            Ok((CurrentChain(ckr, mks), CP::decrypt(&mk, ct, ad)?))
        } else {
            let (rk, ckr) = CP::kdf_rk(&self.rk, &CP::diffie_hellman(&self.dhs, &h.dh));
            let (ckr, mut mks) = Self::skip_message_keys(&ckr, self.get_next_skip(h)?);
            let mk = mks.pop().unwrap();
            Ok((NextChain(rk, ckr, mks), CP::decrypt(&mk, ct, ad)?))
        }
    }

    // Calculate how many messages should be skipped in the current receive chain to get the
    // required `MessageKey`. Also check if `h` is valid.
    fn get_current_skip(&self, h: &Header<CP::PublicKey>) -> Result<usize, DecryptError> {
        let skip =
            h.n.checked_sub(self.nr)
                .ok_or(DecryptError::MessageKeyNotFound)? as usize;
        if MAX_SKIP < skip {
            Err(DecryptError::SkipTooLarge)
        } else if self.mkskipped.can_store(skip) {
            Ok(skip)
        } else {
            Err(DecryptError::StorageFull)
        }
    }

    // Calculate how many messages should be skipped in the next receive chain to get the required
    // `MessageKey`. Also check if `h` is valid.
    fn get_next_skip(&self, h: &Header<CP::PublicKey>) -> Result<usize, DecryptError> {
        // without malicious participants this error can only be triggered if the local MessageKey
        // has already been deleted.
        let prev_skip =
            h.pn.checked_sub(self.nr)
                .ok_or(DecryptError::MessageKeyNotFound)? as usize;
        let skip = h.n as usize;
        if MAX_SKIP < cmp::max(prev_skip, skip) {
            Err(DecryptError::SkipTooLarge)
        } else if self
            .mkskipped
            .can_store((prev_skip + skip).saturating_sub(1))
        {
            Ok(skip)
        } else {
            Err(DecryptError::StorageFull)
        }
    }

    // Update the internal state. Assumes that the validity of `h` has already been checked.
    fn update(&mut self, diff: Diff<CP>, h: &Header<CP::PublicKey>) {
        use Diff::*;
        match diff {
            OldKey => self.mkskipped.remove(&h.dh, h.n),
            CurrentChain(ckr, mks) => {
                self.mkskipped.extend(&h.dh, self.nr, mks);
                self.ckr = Some(ckr);
                self.nr = h.n + 1;
            }
            NextChain(rk, ckr, mks) => {
                if self.ckr.is_some() && self.nr < h.pn {
                    let ckr = self.ckr.as_ref().unwrap();
                    let (_, prev_mks) = Self::skip_message_keys(ckr, (h.pn - self.nr - 1) as usize);
                    let dhr = self.dhr.as_ref().unwrap();
                    self.mkskipped.extend(dhr, self.nr, prev_mks);
                }
                self.dhr = Some(h.dh.clone());
                self.rk = rk;
                self.cks = None;
                self.ckr = Some(ckr);
                self.nr = h.n + 1;
                self.mkskipped.extend(&h.dh, 0, mks);
            }
        }
    }

    // Do `skip + 1` ratchet steps in the receive chain. Return the last ChainKey
    // and all computed MessageKeys.
    fn skip_message_keys(ckr: &CP::ChainKey, skip: usize) -> (CP::ChainKey, Vec<CP::MessageKey>) {
        // Note: should use std::iter::unfold (currently still in nightly)
        let mut mks = Vec::with_capacity(skip + 1);
        let (mut ckr, mk) = CP::kdf_ck(&ckr);
        mks.push(mk);
        for _ in 0..skip {
            let cm = CP::kdf_ck(&ckr);
            ckr = cm.0;
            mks.push(cm.1);
        }
        (ckr, mks)
    }

    // Concatenate `h` and `ad` in a single byte-vector.
    fn concat(h: &Header<CP::PublicKey>, ad: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(ad);
        h.extend_bytes_into(&mut v);
        v
    }
}

/// The Header that should be sent alongside the ciphertext.
///
/// The Header contains the information for the `DoubleRatchet` to find the correct `MessageKey` to
/// decrypt the message. It is generated by `ratchet_encrypt`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header<PublicKey> {
    /// The public half of the key-pair of the sender
    pub dh: PublicKey,

    /// Counts the number of messages that have been sent in the current symmetric ratchet
    pub n: Counter,

    /// Counts the number of messages that have been sent in the previous symmetric ratchet
    pub pn: Counter,
}

impl<PK: AsRef<[u8]>> Header<PK> {
    // yikes
    fn extend_bytes_into(&self, v: &mut Vec<u8>) {
        v.extend_from_slice(self.dh.as_ref());
        v.extend_from_slice(&self.n.to_be_bytes());
        v.extend_from_slice(&self.pn.to_be_bytes());
    }
}

/// Provider of the required cryptographic types and functions.
///
/// The implementer of this trait provides the `DoubleRatchet` with the required external functions
/// as given in the [specification].
///
/// # Security considerations
///
/// The details of the `CryptoProvider` are critical for providing security of the communication.
/// The `DoubleRatchet` can only guarantee security of communication when instantiated with a
/// `CryptoProvider` with secure types and functions. The [specification] provides some sensible
/// [recommendations] and for example code using the `DoubleRatchet` see `tests/signal.rs`.
///
/// [specification]: https://signal.org/docs/specifications/doubleratchet/#external-functions
/// [recommendations]: https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms
pub trait CryptoProvider {
    /// A public key for use in the Diffie-Hellman calculation.
    ///
    /// It is assumed that a `PublicKey` holds a valid key, so if any verification is required the
    /// constructor of this type would be a good place to do so.
    type PublicKey: AsRef<[u8]> + Clone + Eq + Hash;

    /// A private/public key-pair for use in the Diffie-Hellman calculation.
    type KeyPair: KeyPair<PublicKey = Self::PublicKey>;

    /// The result of a Diffie-Hellman calculation.
    type SharedSecret;

    /// A `RootKey` is used in the outer Diffie-Hellman ratchet.
    type RootKey;

    /// A `ChainKey` is used in the inner symmetric ratchets.
    type ChainKey;

    /// A `MessageKey` is used to encrypt/decrypt messages.
    ///
    /// The implementation of this type could be a complex type: for example an implementation that
    /// works by the encrypt-then-MAC paradigm may require a tuple consisting of an encryption key
    /// and a MAC key.
    type MessageKey;

    /// Perform the Diffie-Hellman operation.
    fn diffie_hellman(us: &Self::KeyPair, them: &Self::PublicKey) -> Self::SharedSecret;

    /// Derive a new root-key/chain-key pair from the old root-key and a fresh shared secret.
    fn kdf_rk(
        root_key: &Self::RootKey,
        shared_secret: &Self::SharedSecret,
    ) -> (Self::RootKey, Self::ChainKey);

    /// Derive a new chain-key/message-key pair from the old chain-key.
    fn kdf_ck(chain_key: &Self::ChainKey) -> (Self::ChainKey, Self::MessageKey);

    /// Authenticate-encrypt the plaintext and associated data.
    ///
    /// This method MUST authenticate `associated_data`, because it contains the header bytes.
    fn encrypt(key: &Self::MessageKey, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8>;

    /// Verify-decrypt the ciphertext and associated data.
    fn decrypt(
        key: &Self::MessageKey,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError>;
}

/// A private-/public-key pair
///
/// This trait is required for `CryptoProvider::KeyPair`
pub trait KeyPair {
    /// Type of the public half of the key pair
    ///
    /// This type should be equal to `CryptoProvider::PublicKey`
    type PublicKey;

    /// Generate a new random `KeyPair`
    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    /// Get a reference to the public half of the key pair
    fn public(&self) -> &Self::PublicKey;
}

// Maximum amount of skipped message keys that can be stored
const MKS_CAPACITY: usize = 2000;

// A KeyStore holds the skipped `MessageKey`s.
//
// When messages can arrive out of order, the DoubleRatchet must store the MessageKeys
// corresponding to the messages that were skipped over. See also the [specification] for further
// discussion.
//
// [specification]: https://signal.org/docs/specifications/doubleratchet/#deletion-of-skipped-message-keys
struct KeyStore<CP: CryptoProvider>(HashMap<CP::PublicKey, HashMap<Counter, CP::MessageKey>>);

impl<CP> fmt::Debug for KeyStore<CP>
where
    CP: CryptoProvider,
    CP::PublicKey: fmt::Debug,
    CP::MessageKey: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyStore({:?})", self.0)
    }
}

impl<CP: CryptoProvider> KeyStore<CP> {
    fn new() -> Self {
        Self(HashMap::new())
    }

    // Get the MessageKey at `(dh, n)` if it is stored
    fn get(&self, dh: &CP::PublicKey, n: Counter) -> Option<&CP::MessageKey> {
        self.0.get(dh)?.get(&n)
    }

    // Do `n` more MessageKeys fit in the KeyStore?
    fn can_store(&self, n: usize) -> bool {
        let current: usize = self.0.values().map(HashMap::len).sum();
        current + n <= MKS_CAPACITY
    }

    // Extend the storage with `mks`
    //
    // Keys are stored at `dh` and `n` counting upwards:
    //   (dh, n  ): mks[0]
    //   (dh, n+1): mks[1]
    //   ...
    fn extend(&mut self, dh: &CP::PublicKey, n: Counter, mks: Vec<CP::MessageKey>) {
        let values = (n..).zip(mks.into_iter());
        if let Some(v) = self.0.get_mut(dh) {
            v.extend(values);
        } else {
            self.0.insert(dh.clone(), values.collect());
        }
    }

    // Remove the MessageKey at index `(dh, n)`
    //
    // Assumes the MessageKey is indeed stored.
    fn remove(&mut self, dh: &CP::PublicKey, n: Counter) {
        debug_assert!(self.0.contains_key(dh));
        let hm = self.0.get_mut(dh).unwrap();
        debug_assert!(hm.contains_key(&n));
        if hm.len() == 1 {
            self.0.remove(dh);
        } else {
            hm.remove(&n);
        }
    }
}

// Required information for updating the state after successful decryption
enum Diff<CP: CryptoProvider> {
    // Key was found amongst old key
    OldKey,

    // Key was part of the current receive chain
    CurrentChain(CP::ChainKey, Vec<CP::MessageKey>),

    // Key was part of the next receive chain
    NextChain(CP::RootKey, CP::ChainKey, Vec<CP::MessageKey>),
}

/// Error that occurs on `try_ratchet_encrypt` before the state is initialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptUninit;

#[cfg(feature = "std")]
impl Error for EncryptUninit {}

impl fmt::Display for EncryptUninit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Encrypt not yet initialized (you must receive a message first)"
        )
    }
}

/// Error that may occur during `ratchet_decrypt`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// Could not verify-decrypt the ciphertext + associated data + header
    DecryptFailure,

    /// Could not find the message key required for decryption
    ///
    /// Note that this implementation is not always able to detect when an old `MessageKey` can't
    /// be found: a `DecryptFailure` may be triggered instead.
    MessageKeyNotFound,

    /// Header message counter is too large (either `n` or `pn`)
    SkipTooLarge,

    /// Storage of skipped message keys is full
    StorageFull,
}

#[cfg(feature = "std")]
impl Error for DecryptError {}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DecryptError::*;
        match self {
            DecryptFailure => write!(f, "Error during verify-decrypting"),
            MessageKeyNotFound => {
                write!(f, "Could not find the message key required for decryption")
            }
            SkipTooLarge => write!(f, "Header message counter is too large"),
            StorageFull => write!(f, "Storage for skipped messages is full"),
        }
    }
}

// Create a mock CryptoProvider for testing purposes. See `tests/signal.rs` for a proper example
// implementation.
#[cfg(feature = "test")]
#[allow(unused)]
#[allow(missing_docs)]
pub mod mock {
    use super::*;

    pub type DoubleRatchet = super::DoubleRatchet<CryptoProvider>;
    pub struct CryptoProvider;

    impl super::CryptoProvider for CryptoProvider {
        type KeyPair = KeyPair;
        type PublicKey = PublicKey;
        type SharedSecret = u8;

        type RootKey = [u8; 2];
        type ChainKey = [u8; 3];
        type MessageKey = [u8; 3];

        fn diffie_hellman(us: &KeyPair, them: &PublicKey) -> u8 {
            us.0[0].wrapping_add(them.0[0])
        }

        fn kdf_rk(rk: &[u8; 2], s: &u8) -> ([u8; 2], [u8; 3]) {
            ([rk[0], *s], [rk[0], rk[1], 0])
        }

        fn kdf_ck(ck: &[u8; 3]) -> ([u8; 3], [u8; 3]) {
            ([ck[0], ck[1], ck[2].wrapping_add(1)], *ck)
        }

        fn encrypt(mk: &[u8; 3], pt: &[u8], ad: &[u8]) -> Vec<u8> {
            let mut ct = Vec::from(&mk[..]);
            ct.extend_from_slice(pt);
            ct.extend_from_slice(ad);
            ct
        }

        fn decrypt(mk: &[u8; 3], ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, super::DecryptError> {
            if ct.len() < 3 + ad.len() || ct[..3] != mk[..] || !ct.ends_with(ad) {
                Err(super::DecryptError::DecryptFailure)
            } else {
                Ok(Vec::from(&ct[3..ct.len() - ad.len()]))
            }
        }
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    pub struct PublicKey([u8; 1]);
    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug)]
    pub struct KeyPair([u8; 1], PublicKey);
    impl super::KeyPair for KeyPair {
        type PublicKey = PublicKey;
        #[allow(clippy::cast_possible_truncation)]
        fn new<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
            let n = rng.next_u32() as u8;
            Self([n], PublicKey([n + 1]))
        }

        fn public(&self) -> &PublicKey {
            &self.1
        }
    }

    // FIXME: this functionality exists already, but breaks the build...
    // use rand::rngs::mock::StepRng;
    #[derive(Default)]
    pub struct Rng(u64);
    impl rand_core::RngCore for Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 += 1;
            self.0
        }
        #[allow(clippy::cast_possible_truncation)]
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, out);
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(out);
            Ok(())
        }
    }
    impl super::CryptoRng for Rng {}
}

#[cfg(test)]
mod tests {
    use super::*;

    type DR = DoubleRatchet<mock::CryptoProvider>;

    fn asymmetric_setup(rng: &mut mock::Rng) -> (DR, DR) {
        let secret = [42, 0];
        let pair = mock::KeyPair::new(rng);
        let pubkey = pair.public().clone();
        let alice = DR::new_alice(&secret, pubkey, None, rng);
        let bob = DR::new_bob(secret, pair, None);
        (alice, bob)
    }

    fn symmetric_setup(rng: &mut mock::Rng) -> (DR, DR) {
        let secret = [42, 0];
        let ck_init = [42, 0, 0];
        let pair = mock::KeyPair::new(rng);
        let pubkey = pair.public().clone();
        let alice = DR::new_alice(&secret, pubkey, Some(ck_init), rng);
        let bob = DR::new_bob(secret, pair, Some(ck_init));
        (alice, bob)
    }

    #[test]
    fn test_asymmetric_setup() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);

        // Alice can encrypt, Bob can't
        let (pt_a, ad_a) = (b"Hi Bobby", b"A2B");
        let (pt_b, ad_b) = (b"What's up Al?", b"B2A");
        let (h_a, ct_a) = alice.ratchet_encrypt(pt_a, ad_a, &mut rng);
        assert_eq!(
            Err(EncryptUninit),
            bob.try_ratchet_encrypt(pt_b, ad_b, &mut rng)
        );
        assert_eq!(
            Ok(Vec::from(&pt_a[..])),
            bob.ratchet_decrypt(&h_a, &ct_a, ad_a)
        );

        // but after decryption Bob can encrypt
        let (h_b, ct_b) = bob.ratchet_encrypt(pt_b, ad_b, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_b[..])),
            alice.ratchet_decrypt(&h_b, &ct_b, ad_b)
        );
    }

    #[test]
    fn test_symmetric_setup() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = symmetric_setup(&mut rng);

        // Alice can encrypt, Bob can't
        let (pt_a, ad_a) = (b"Hi Bobby", b"A2B");
        let (pt_b, ad_b) = (b"What's up Al?", b"B2A");
        let (h_a, ct_a) = alice.ratchet_encrypt(pt_a, ad_a, &mut rng);
        let (h_b, ct_b) = bob.ratchet_encrypt(pt_b, ad_b, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_a[..])),
            bob.ratchet_decrypt(&h_a, &ct_a, ad_a)
        );
        assert_eq!(
            Ok(Vec::from(&pt_b[..])),
            alice.ratchet_decrypt(&h_b, &ct_b, ad_b)
        );
    }

    #[test]
    fn symmetric_out_of_order() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        let (ad_a, ad_b) = (b"A2B", b"B2A");

        // Alice's message arrive out of order, some are even missing
        let pt_a_0 = b"Hi Bobby";
        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(pt_a_0, ad_a, &mut rng);
        for _ in 1..9 {
            alice.ratchet_encrypt(b"hello?", ad_a, &mut rng); // drop these messages
        }
        let pt_a_9 = b"are you there?";
        let (h_a_9, ct_a_9) = alice.ratchet_encrypt(pt_a_9, ad_a, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_a_9[..])),
            bob.ratchet_decrypt(&h_a_9, &ct_a_9, ad_a)
        );
        assert_eq!(
            Ok(Vec::from(&pt_a_0[..])),
            bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a)
        );

        // Bob's replies also arrive out of order
        let pt_b_0 = b"Yes I'm here";
        let (h_b_0, ct_b_0) = bob.ratchet_encrypt(pt_b_0, ad_b, &mut rng);
        for _ in 1..9 {
            bob.ratchet_encrypt(b"why?", ad_b, &mut rng); // drop these messages
        }
        let pt_b_9 = b"Tell me why!!!";
        let (h_b_9, ct_b_9) = bob.ratchet_encrypt(pt_b_9, ad_b, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_b_9[..])),
            alice.ratchet_decrypt(&h_b_9, &ct_b_9, ad_b)
        );
        assert_eq!(
            Ok(Vec::from(&pt_b_0[..])),
            alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b)
        );
    }

    #[test]
    fn dh_out_of_order() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        let (ad_a, ad_b) = (b"A2B", b"B2A");

        let pt_a_0 = b"Good day Robert";
        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(pt_a_0, ad_a, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_a_0[..])),
            bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a)
        );
        let pt_a_1 = b"Do you like Rust?";
        let (h_a_1, ct_a_1) = alice.ratchet_encrypt(pt_a_1, ad_a, &mut rng);
        // Bob misses pt_a_1

        let pt_b_0 = b"Salutations Allison";
        let (h_b_0, ct_b_0) = bob.ratchet_encrypt(pt_b_0, ad_b, &mut rng);
        // Alice misses pt_b_0
        let pt_b_1 = b"How is your day going?";
        let (h_b_1, ct_b_1) = bob.ratchet_encrypt(pt_b_1, ad_b, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_b_1[..])),
            alice.ratchet_decrypt(&h_b_1, &ct_b_1, ad_b)
        );

        let pt_a_2 = b"My day is fine.";
        let (h_a_2, ct_a_2) = alice.ratchet_encrypt(pt_a_2, ad_a, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_a_2[..])),
            bob.ratchet_decrypt(&h_a_2, &ct_a_2, ad_a)
        );
        // now Bob receives pt_a_1
        assert_eq!(
            Ok(Vec::from(&pt_a_1[..])),
            bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a)
        );

        let pt_b_2 = b"Yes I like Rust";
        let (h_b_2, ct_b_2) = bob.ratchet_encrypt(pt_b_2, ad_b, &mut rng);
        assert_eq!(
            Ok(Vec::from(&pt_b_2[..])),
            alice.ratchet_decrypt(&h_b_2, &ct_b_2, ad_b)
        );
        // now Alice receives pt_b_0
        assert_eq!(
            Ok(Vec::from(&pt_b_0[..])),
            alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b)
        );
    }

    #[test]
    #[should_panic(expected = "not yet initialized for encryption")]
    fn encrypt_error() {
        let mut rng = mock::Rng::default();
        let (_alice, mut bob) = asymmetric_setup(&mut rng);

        assert_eq!(
            Err(EncryptUninit),
            bob.try_ratchet_encrypt(b"", b"", &mut rng)
        );
        bob.ratchet_encrypt(b"", b"", &mut rng);
    }

    #[test]
    fn decrypt_failure() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        let (ad_a, ad_b) = (b"A2B", b"B2A");

        // Next chain
        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(b"Hi Bob", ad_a, &mut rng);
        let mut ct_a_0_err = ct_a_0.clone();
        ct_a_0_err[2] ^= 0x80;
        let mut h_a_0_err = h_a_0.clone();
        h_a_0_err.pn = 1;
        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_0, &ct_a_0_err, ad_a)
        );
        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_0_err, &ct_a_0, ad_a)
        );
        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_b)
        );

        // Current Chain
        let (h_a_1, ct_a_1) = alice.ratchet_encrypt(b"Hi Bob", ad_a, &mut rng);
        bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).unwrap();
        let (h_a_2, ct_a_2) = alice.ratchet_encrypt(b"Hi Bob", ad_a, &mut rng);
        let mut h_a_2_err = h_a_2.clone();
        h_a_2_err.pn += 1;
        let mut ct_a_2_err = ct_a_2.clone();
        ct_a_2_err[0] ^= 0x04;

        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_2, &ct_a_2_err, ad_a)
        );
        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_2_err, &ct_a_2, ad_a)
        );
        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_2, &ct_a_2, ad_b)
        );

        // Previous chain
        let (h_b, ct_b) = bob.ratchet_encrypt(b"Hi Alice", ad_b, &mut rng);
        alice.ratchet_decrypt(&h_b, &ct_b, ad_b).unwrap();
        let (h_a_3, ct_a_3) = alice.ratchet_encrypt(b"Hi Bob", ad_a, &mut rng);
        bob.ratchet_decrypt(&h_a_3, &ct_a_3, ad_a).unwrap();

        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_2, &ct_a_2_err, ad_a)
        );
        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_2_err, &ct_a_2, ad_a)
        );
        assert_eq!(
            Err(DecryptError::DecryptFailure),
            bob.ratchet_decrypt(&h_a_2, &ct_a_2, ad_b)
        );
    }

    #[test]
    fn double_sending() {
        // The implementation is unable to consistently detect why decryption fails when receiving
        // double messages: the only requirement should be that *any* error is triggered.

        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        let (ad_a, ad_b) = (b"A2B", b"B2A");

        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(b"Whatever", ad_a, &mut rng);
        bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a).unwrap();
        assert!(bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a).is_err());

        let (h_b_0, ct_b_0) = bob.ratchet_encrypt(b"Whatever", ad_b, &mut rng);
        alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b).unwrap();
        assert!(alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b).is_err());
        let (h_a_1, ct_a_1) = alice.ratchet_encrypt(b"Whatever", ad_a, &mut rng);
        bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).unwrap();
        assert!(bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).is_err());
        let (h_b_1, ct_b_1) = bob.ratchet_encrypt(b"Whatever", ad_b, &mut rng);
        alice.ratchet_decrypt(&h_b_1, &ct_b_1, ad_b).unwrap();
        assert!(alice.ratchet_decrypt(&h_b_1, &ct_b_1, ad_b).is_err());

        assert!(bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a).is_err());
        assert!(alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b).is_err());
    }

    #[test]
    fn invalid_header() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        let (ad_a, ad_b) = (b"A2B", b"B2A");
        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(b"Hi Bob", ad_a, &mut rng);
        bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a).unwrap();
        let (h_b_0, ct_b_0) = bob.ratchet_encrypt(b"Hi Alice", ad_b, &mut rng);
        alice.ratchet_decrypt(&h_b_0, &ct_b_0, ad_b).unwrap();
        let (mut h_a_1, ct_a_1) = alice.ratchet_encrypt(b"I will lie to you now", ad_a, &mut rng);
        assert_eq!(h_a_1.pn, 1);
        h_a_1.pn = 0;
        assert!(bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a).is_err());
    }

    #[test]
    fn skip_too_large() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        let (ad_a, ad_b) = (b"A2B", b"B2A");
        let (h_a_0, ct_a_0) = alice.ratchet_encrypt(b"Hi Bob", ad_a, &mut rng);
        for _ in 0..=MAX_SKIP {
            alice.ratchet_encrypt(b"Not sending this", ad_a, &mut rng);
        }
        let (h_a_1, ct_a_1) = alice.ratchet_encrypt(b"n > MAXSKIP", ad_a, &mut rng);
        assert_eq!(
            Err(DecryptError::SkipTooLarge),
            bob.ratchet_decrypt(&h_a_1, &ct_a_1, ad_a)
        );
        bob.ratchet_decrypt(&h_a_0, &ct_a_0, ad_a).unwrap();
        let (h_b, ct_b) = bob.ratchet_encrypt(b"Hi Alice", ad_b, &mut rng);
        alice.ratchet_decrypt(&h_b, &ct_b, ad_b).unwrap();
        let (h_a_2, ct_a_2) = alice.ratchet_encrypt(b"pn > MAXSKIP", ad_a, &mut rng);
        assert_eq!(
            Err(DecryptError::SkipTooLarge),
            bob.ratchet_decrypt(&h_a_2, &ct_a_2, ad_a)
        );
    }

    #[test]
    fn storage_full() {
        let mut rng = mock::Rng::default();
        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        let ad_a = b"A2B";

        let mut stored = 0;
        while stored < MKS_CAPACITY {
            for _ in 0..cmp::min(MAX_SKIP, MKS_CAPACITY - stored) {
                alice.ratchet_encrypt(b"Not sending this", ad_a, &mut rng);
            }
            let (h_a, ct_a) = alice.ratchet_encrypt(b"Hello Bob", ad_a, &mut rng);
            bob.ratchet_decrypt(&h_a, &ct_a, ad_a).unwrap();
            stored += MAX_SKIP;
            &bob.mkskipped.0.values().map(|hm| hm.len()).sum::<usize>();
        }
        alice.ratchet_encrypt(b"Bob can't store this key anymore", ad_a, &mut rng);
        let (h_a, ct_a) = alice.ratchet_encrypt(b"Gotcha, Bob!", ad_a, &mut rng);
        assert_eq!(
            Err(DecryptError::StorageFull),
            bob.ratchet_decrypt(&h_a, &ct_a, ad_a)
        );
    }

    #[test]
    fn cannot_crash_other() {
        // Malicious parties should not be able to crash the other end (this was an
        // issue in an old implementation).

        let mut rng = mock::Rng::default();
        let (ad_a, ad_b) = (b"A2B", b"B2A");

        let (mut alice, mut bob) = symmetric_setup(&mut rng);
        alice.pn = 10;
        bob.pn = 10;
        let (h_a, ct_a) = alice.ratchet_encrypt(b"not important", ad_a, &mut rng);
        let (h_b, ct_b) = bob.ratchet_encrypt(b"not important", ad_b, &mut rng);
        let _ = alice.ratchet_decrypt(&h_b, &ct_b, ad_b);
        let _ = bob.ratchet_decrypt(&h_a, &ct_a, ad_a);

        let (mut alice, mut bob) = asymmetric_setup(&mut rng);
        alice.pn = 10;
        let (h_a, ct_a) = alice.ratchet_encrypt(b"not important", ad_a, &mut rng);
        let _ = bob.ratchet_decrypt(&h_a, &ct_a, ad_a);
        bob.pn = 10;
        let (h_b, ct_b) = bob.ratchet_encrypt(b"not important", ad_b, &mut rng);
        let _ = alice.ratchet_decrypt(&h_b, &ct_b, ad_b);
    }
}
