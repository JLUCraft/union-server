//! Minecraft login encryption and its authenticated Yggdrasil profile.
use crate::{
    forwarding::Profile,
    protocol::{self, Fields, Packet},
    skins::SkinSite,
};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{Result, ensure};
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey,
    pkcs8::EncodePublicKey,
    rand_core::{OsRng, RngCore},
};
use sha1::{Digest, Sha1};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const SECRET_BYTES: usize = 16;
const WRITE_BUFFER: usize = 16 * 1024;
type Encryptor = cfb8::Encryptor<aes::Aes128>;
type Decryptor = cfb8::Decryptor<aes::Aes128>;

pub(crate) struct Encrypted<S> {
    stream: S,
    encryptor: Encryptor,
    decryptor: Decryptor,
    pending: Vec<u8>,
    written: usize,
}
impl<S> Encrypted<S> {
    pub(crate) fn new(stream: S, secret: &[u8; SECRET_BYTES]) -> Self {
        Self {
            stream,
            encryptor: Encryptor::new(secret.into(), secret.into()),
            decryptor: Decryptor::new(secret.into(), secret.into()),
            pending: Vec::new(),
            written: 0,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Encrypted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let start = output.filled().len();
        match Pin::new(&mut this.stream).poll_read(cx, output) {
            Poll::Ready(Ok(())) => {
                for byte in &mut output.filled_mut()[start..] {
                    this.decryptor
                        .decrypt_block_mut(std::slice::from_mut(byte).into());
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> Encrypted<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let count = std::task::ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.pending[self.written..])
            )?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += count;
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Encrypted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx))?;
        let count = input.len().min(WRITE_BUFFER);
        this.pending.extend_from_slice(&input[..count]);
        for byte in &mut this.pending {
            this.encryptor
                .encrypt_block_mut(std::slice::from_mut(byte).into());
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.drain(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

pub(crate) fn server_id(secret: &[u8], public: &[u8]) -> String {
    let mut bytes: [u8; 20] = Sha1::new()
        .chain_update(secret)
        .chain_update(public)
        .finalize()
        .into();
    let negative = bytes[0] & 0x80 != 0;
    if negative {
        let mut carry = true;
        for byte in bytes.iter_mut().rev() {
            let (next, overflow) = (!*byte).overflowing_add(u8::from(carry));
            *byte = next;
            carry = overflow;
        }
    }
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let magnitude = hex.trim_start_matches('0');
    format!(
        "{}{}",
        if negative { "-" } else { "" },
        if magnitude.is_empty() { "0" } else { magnitude }
    )
}
fn byte_array(fields: &mut Fields<'_>, maximum: usize) -> Result<Vec<u8>> {
    let length = usize::try_from(fields.int()?)?;
    ensure!(length <= maximum, "encryption field too large");
    Ok(fields.bytes(length)?.to_vec())
}
pub(crate) async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    login: &Packet,
    key: &RsaPrivateKey,
    site: &SkinSite,
) -> Result<(Encrypted<S>, Profile)> {
    ensure!(login.id == protocol::LOGIN_START, "expected login start");
    let mut fields = Fields::new(&login.body);
    let name = fields.text(16)?.to_owned();
    let uuid = uuid::Uuid::from_slice(fields.bytes(16)?)?;
    fields.finish()?;
    crate::forwarding::validate_name(&name)?;
    let public = key.to_public_key().to_public_key_der()?;
    let public = public.as_bytes();
    let mut token = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut token);
    let mut body = Vec::new();
    protocol::string("", &mut body)?;
    for bytes in [public, &token] {
        protocol::varint(u32::try_from(bytes.len())?, &mut body);
        body.extend(bytes);
    }
    body.push(1);
    protocol::write_packet(
        &mut stream,
        Packet {
            id: protocol::LOGIN_ENCRYPTION_REQUEST,
            body,
        },
        None,
    )
    .await?;
    let response = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
    ensure!(response.id == 1, "expected encryption response");
    let mut fields = Fields::new(&response.body);
    let secret = byte_array(&mut fields, 256)?;
    let challenge = byte_array(&mut fields, 256)?;
    fields.finish()?;
    let secret = key.decrypt_blinded(&mut OsRng, Pkcs1v15Encrypt, &secret)?;
    let challenge = key.decrypt_blinded(&mut OsRng, Pkcs1v15Encrypt, &challenge)?;
    ensure!(
        bool::from(challenge.as_slice().ct_eq(&token)),
        "invalid login challenge"
    );
    let secret: [u8; SECRET_BYTES] = secret
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid shared secret"))?;
    let stream = Encrypted::new(stream, &secret);
    let profile = site
        .has_joined(uuid, &name, &server_id(&secret, public))
        .await?;
    Ok((stream, profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::AsyncStreamCipher;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn session_digest_uses_signed_java_hex() {
        assert_eq!(
            server_id(b"Notch", b""),
            "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
        );
        assert_eq!(
            server_id(b"jeb_", b""),
            "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1"
        );
    }

    #[tokio::test]
    async fn encrypted_stream_preserves_cipher_state_through_backpressure_and_fragmentation()
    -> Result<()> {
        let secret = [7u8; SECRET_BYTES];
        let mut plaintext = vec![0u8; WRITE_BUFFER * 2 + 17];
        OsRng.fill_bytes(&mut plaintext);
        let mut expected = plaintext.clone();
        Encryptor::new(&secret.into(), &secret.into()).encrypt(&mut expected);
        let (client, mut server) = tokio::io::duplex(7);
        let returned = expected.clone();
        let remote = tokio::spawn(async move {
            let mut received = vec![0u8; expected.len()];
            server.read_exact(&mut received).await?;
            assert_eq!(received, expected);
            for chunk in returned.chunks(13) {
                server.write_all(chunk).await?;
            }
            server.shutdown().await?;
            Ok::<_, io::Error>(())
        });
        let mut client = Encrypted::new(client, &secret);
        client.write_all(&plaintext).await?;
        client.flush().await?;
        let mut received = Vec::new();
        client.read_to_end(&mut received).await?;
        assert_eq!(received, plaintext);
        remote.await??;
        Ok(())
    }
}
