use crypto_box::{PublicKey, SalsaBox, SecretKey, aead::Aead};
use rustler::{Atom, Binary, Env, OwnedBinary};
use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;

mod atoms {
    rustler::atoms! {
        allocation_failed,
        authentication_failed,
        bad_key_size,
        bad_nonce_size
    }
}

/// Failure modes of the pure NaCl box helpers, mapped to atoms at the NIF edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CryptoError {
    AuthenticationFailed,
    BadKeySize,
    BadNonceSize,
}

impl CryptoError {
    fn to_atom(self) -> Atom {
        match self {
            CryptoError::AuthenticationFailed => atoms::authentication_failed(),
            CryptoError::BadKeySize => atoms::bad_key_size(),
            CryptoError::BadNonceSize => atoms::bad_nonce_size(),
        }
    }
}

#[rustler::nif]
fn loaded() -> bool {
    true
}

#[rustler::nif]
fn public_key<'a>(env: Env<'a>, private_key: Binary<'_>) -> Result<Binary<'a>, Atom> {
    let public_key = derive_public_key(private_key.as_slice()).map_err(CryptoError::to_atom)?;
    encode_binary(env, &public_key)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn seal<'a>(
    env: Env<'a>,
    private_key: Binary<'_>,
    peer_public_key: Binary<'_>,
    nonce: Binary<'_>,
    plaintext: Binary<'_>,
) -> Result<Binary<'a>, Atom> {
    let boxed = seal_box(
        private_key.as_slice(),
        peer_public_key.as_slice(),
        nonce.as_slice(),
        plaintext.as_slice(),
    )
    .map_err(CryptoError::to_atom)?;

    encode_binary(env, &boxed)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn open<'a>(
    env: Env<'a>,
    private_key: Binary<'_>,
    peer_public_key: Binary<'_>,
    boxed: Binary<'_>,
) -> Result<Binary<'a>, Atom> {
    let plaintext = open_box(
        private_key.as_slice(),
        peer_public_key.as_slice(),
        boxed.as_slice(),
    )
    .map_err(CryptoError::to_atom)?;

    encode_binary(env, &plaintext)
}

fn derive_public_key(private_key: &[u8]) -> Result<[u8; KEY_LENGTH], CryptoError> {
    let private_key = key_bytes(private_key)?;
    Ok(*SecretKey::from(*private_key).public_key().as_bytes())
}

fn seal_box(
    private_key: &[u8],
    peer_public_key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let private_key = key_bytes(private_key)?;
    let peer_public_key = key_bytes(peer_public_key)?;
    let nonce: [u8; NONCE_LENGTH] = nonce.try_into().map_err(|_| CryptoError::BadNonceSize)?;
    let cipher = SalsaBox::new(
        &PublicKey::from(*peer_public_key),
        &SecretKey::from(*private_key),
    );
    let ciphertext = cipher
        .encrypt(&nonce.into(), plaintext)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut boxed = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    boxed.extend_from_slice(&nonce);
    boxed.extend_from_slice(&ciphertext);
    Ok(boxed)
}

fn open_box(
    private_key: &[u8],
    peer_public_key: &[u8],
    boxed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let private_key = key_bytes(private_key)?;
    let peer_public_key = key_bytes(peer_public_key)?;
    let (nonce, ciphertext) = boxed
        .split_at_checked(NONCE_LENGTH)
        .ok_or(CryptoError::BadNonceSize)?;
    let cipher = SalsaBox::new(
        &PublicKey::from(*peer_public_key),
        &SecretKey::from(*private_key),
    );
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Copies a 32 byte key out of a NIF binary.
///
/// The copy is wrapped in `Zeroizing` so this array is wiped when it drops.
/// That narrows, but does not close, the exposure window: `SecretKey::from`
/// takes the array by value, and crypto_box 0.9.1's `Drop for SecretKey`
/// zeroizes only the derived scalar, not the raw bytes it was given. Closing
/// that gap needs an upstream change; until then the second copy lives for
/// the duration of one seal/open call.
fn key_bytes(bytes: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>, CryptoError> {
    bytes
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::BadKeySize)
}

fn encode_binary<'a>(env: Env<'a>, bytes: &[u8]) -> Result<Binary<'a>, Atom> {
    let mut binary = OwnedBinary::new(bytes.len()).ok_or_else(atoms::allocation_failed)?;
    binary.as_mut_slice().copy_from_slice(bytes);
    Ok(binary.release(env))
}

rustler::init!("Elixir.Derpex.Crypto.Native");

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    const SENDER_PRIVATE_KEY: [u8; KEY_LENGTH] = [7; KEY_LENGTH];
    const RECIPIENT_PRIVATE_KEY: [u8; KEY_LENGTH] = [9; KEY_LENGTH];
    const NONCE: [u8; NONCE_LENGTH] = [3; NONCE_LENGTH];

    fn sender_public_key() -> [u8; KEY_LENGTH] {
        derive_public_key(&SENDER_PRIVATE_KEY).expect("sender public key")
    }

    fn recipient_public_key() -> [u8; KEY_LENGTH] {
        derive_public_key(&RECIPIENT_PRIVATE_KEY).expect("recipient public key")
    }

    #[test]
    fn seals_and_opens_a_round_trip() {
        let boxed = seal_box(
            &SENDER_PRIVATE_KEY,
            &recipient_public_key(),
            &NONCE,
            b"derpex",
        )
        .expect("seal");

        assert_eq!(&boxed[..NONCE_LENGTH], &NONCE[..]);
        assert_eq!(
            open_box(&RECIPIENT_PRIVATE_KEY, &sender_public_key(), &boxed),
            Ok(b"derpex".to_vec())
        );
    }

    #[test]
    fn zeroizes_the_key_copy() {
        let mut key: Zeroizing<[u8; KEY_LENGTH]> = key_bytes(&SENDER_PRIVATE_KEY).expect("key");

        assert_eq!(key[..], SENDER_PRIVATE_KEY[..]);

        key.zeroize();

        assert_eq!(key[..], [0u8; KEY_LENGTH][..]);
    }

    #[test]
    fn rejects_a_short_nonce() {
        assert_eq!(
            seal_box(
                &SENDER_PRIVATE_KEY,
                &recipient_public_key(),
                &NONCE[..NONCE_LENGTH - 1],
                b"derpex"
            ),
            Err(CryptoError::BadNonceSize)
        );

        assert_eq!(
            open_box(
                &RECIPIENT_PRIVATE_KEY,
                &sender_public_key(),
                &[0; NONCE_LENGTH - 1]
            ),
            Err(CryptoError::BadNonceSize)
        );
    }

    #[test]
    fn rejects_a_wrong_key_length() {
        assert_eq!(
            derive_public_key(&SENDER_PRIVATE_KEY[..KEY_LENGTH - 1]),
            Err(CryptoError::BadKeySize)
        );

        assert_eq!(
            seal_box(
                &SENDER_PRIVATE_KEY[..KEY_LENGTH - 1],
                &recipient_public_key(),
                &NONCE,
                b"derpex"
            ),
            Err(CryptoError::BadKeySize)
        );

        assert_eq!(
            open_box(
                &RECIPIENT_PRIVATE_KEY,
                &sender_public_key()[..KEY_LENGTH - 1],
                &[0; NONCE_LENGTH + 16]
            ),
            Err(CryptoError::BadKeySize)
        );
    }

    #[test]
    fn rejects_a_tampered_ciphertext() {
        let mut boxed = seal_box(
            &SENDER_PRIVATE_KEY,
            &recipient_public_key(),
            &NONCE,
            b"derpex",
        )
        .expect("seal");

        let last = boxed.len() - 1;
        boxed[last] ^= 0x01;

        assert_eq!(
            open_box(&RECIPIENT_PRIVATE_KEY, &sender_public_key(), &boxed),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}
