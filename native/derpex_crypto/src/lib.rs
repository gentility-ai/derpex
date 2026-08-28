use crypto_box::{PublicKey, SalsaBox, SecretKey, aead::Aead};
use rustler::{Atom, Binary, Env, OwnedBinary};

mod atoms {
    rustler::atoms! {
        allocation_failed,
        authentication_failed,
        bad_key_size,
        bad_nonce_size
    }
}

#[rustler::nif]
fn loaded() -> bool {
    true
}

#[rustler::nif]
fn public_key<'a>(env: Env<'a>, private_key: Binary<'_>) -> Result<Binary<'a>, Atom> {
    let private_key = key_bytes(private_key)?;
    let secret = SecretKey::from(private_key);
    encode_binary(env, secret.public_key().as_bytes())
}

#[rustler::nif]
fn seal<'a>(
    env: Env<'a>,
    private_key: Binary<'_>,
    peer_public_key: Binary<'_>,
    nonce: Binary<'_>,
    plaintext: Binary<'_>,
) -> Result<Binary<'a>, Atom> {
    let private_key = key_bytes(private_key)?;
    let peer_public_key = key_bytes(peer_public_key)?;
    let nonce: [u8; 24] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| atoms::bad_nonce_size())?;
    let secret = SecretKey::from(private_key);
    let peer = PublicKey::from(peer_public_key);
    let cipher = SalsaBox::new(&peer, &secret);
    let ciphertext = cipher
        .encrypt(&nonce.into(), plaintext.as_slice())
        .map_err(|_| atoms::authentication_failed())?;
    let mut boxed = Vec::with_capacity(nonce.len() + ciphertext.len());
    boxed.extend_from_slice(&nonce);
    boxed.extend_from_slice(&ciphertext);
    encode_binary(env, &boxed)
}

#[rustler::nif]
fn open<'a>(
    env: Env<'a>,
    private_key: Binary<'_>,
    peer_public_key: Binary<'_>,
    boxed: Binary<'_>,
) -> Result<Binary<'a>, Atom> {
    let private_key = key_bytes(private_key)?;
    let peer_public_key = key_bytes(peer_public_key)?;
    let (nonce, ciphertext) = boxed
        .as_slice()
        .split_at_checked(24)
        .ok_or_else(atoms::bad_nonce_size)?;
    let secret = SecretKey::from(private_key);
    let peer = PublicKey::from(peer_public_key);
    let cipher = SalsaBox::new(&peer, &secret);
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| atoms::authentication_failed())?;
    encode_binary(env, &plaintext)
}

fn key_bytes(binary: Binary<'_>) -> Result<[u8; 32], Atom> {
    binary
        .as_slice()
        .try_into()
        .map_err(|_| atoms::bad_key_size())
}

fn encode_binary<'a>(env: Env<'a>, bytes: &[u8]) -> Result<Binary<'a>, Atom> {
    let mut binary = OwnedBinary::new(bytes.len()).ok_or_else(atoms::allocation_failed)?;
    binary.as_mut_slice().copy_from_slice(bytes);
    Ok(binary.release(env))
}

rustler::init!("Elixir.Derpex.Crypto.Native");
