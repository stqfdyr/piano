//! Length-prefixed frames, async for the daemon and blocking for the CLI.

use std::io::{self, Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest request the daemon reads; requests are a command name and small arguments.
pub const MAX_REQUEST: usize = 64 * 1024;
/// Largest response the CLI reads.
pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;

fn too_large(len: usize, max: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("frame of {len} bytes exceeds {max}"),
    )
}

fn header(len: usize) -> io::Result<[u8; 4]> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| too_large(len, u32::MAX as usize))
}

pub async fn read(r: &mut (impl AsyncRead + Unpin), max: usize) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    let len = u32::from_be_bytes(head) as usize;
    if len > max {
        return Err(too_large(len, max));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

pub async fn write(w: &mut (impl AsyncWrite + Unpin), body: &[u8]) -> io::Result<()> {
    w.write_all(&header(body.len())?).await?;
    w.write_all(body).await?;
    w.flush().await
}

pub fn read_blocking(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head)?;
    let len = u32::from_be_bytes(head) as usize;
    if len > max {
        return Err(too_large(len, max));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

pub fn write_blocking(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    w.write_all(&header(body.len())?)?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_and_size_limit() {
        let mut buf = Vec::new();
        write(&mut buf, b"{\"v\":1}").await.unwrap();
        assert_eq!(&buf[..4], &[0, 0, 0, 7]);
        assert_eq!(read(&mut buf.as_slice(), 7).await.unwrap(), b"{\"v\":1}");
        let err = read(&mut buf.as_slice(), 6).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let mut blocking = Vec::new();
        write_blocking(&mut blocking, b"{}").unwrap();
        assert_eq!(read_blocking(&mut blocking.as_slice(), 2).unwrap(), b"{}");
    }

    #[tokio::test]
    async fn a_truncated_frame_is_an_error() {
        let err = read(&mut [0u8, 0, 0, 9, b'{'].as_slice(), 64)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
