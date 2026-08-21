// Stream I/O for SASL lines and framed messages.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use oxibus_core::header::MessageHeader;
use oxibus_core::message::Message;
use tokio::io::Interest;
use tokio::net::UnixStream;

use crate::credentials::{peer_credentials, PeerCredentials};
use crate::fds;

const MAX_AUTH_LINE_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct Writer {
    stream: Arc<UnixStream>,
}

impl Writer {
    async fn write_all_with_fds(&self, mut buf: &[u8], out_fds: &[RawFd]) -> io::Result<()> {
        let mut first = true;
        while !buf.is_empty() {
            self.stream.ready(Interest::WRITABLE).await?;
            let stream = &self.stream;
            let attach: &[RawFd] = if first { out_fds } else { &[] };
            let result: io::Result<usize> = stream.try_io(Interest::WRITABLE, || {
                fds::send_with_fds(stream.as_raw_fd(), buf, attach)
            });
            match result {
                Ok(n) => {
                    first = false;
                    buf = &buf[n..];
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub async fn send_initial_nul(&self) -> io::Result<()> {
        self.write_all_with_fds(&[0u8], &[]).await
    }

    pub async fn write_line(&self, line: &str) -> io::Result<()> {
        let mut out = Vec::with_capacity(line.len() + 2);
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
        self.write_all_with_fds(&out, &[]).await
    }

    pub async fn write_message(&self, msg: &Message) -> io::Result<()> {
        let bytes = msg
            .to_bytes()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.write_all_with_fds(&bytes, &msg.fds).await
    }
}

pub struct Transport {
    stream: Arc<UnixStream>,
    read_buf: Vec<u8>,
    pending_fds: Vec<RawFd>,
    credentials: PeerCredentials,
    max_message_size: u32,
}

impl Transport {
    pub fn new(stream: UnixStream) -> io::Result<Self> {
        let fd = stream.as_raw_fd();
        let credentials = peer_credentials(fd)?;
        Ok(Self {
            stream: Arc::new(stream),
            read_buf: Vec::new(),
            pending_fds: Vec::new(),
            credentials,
            max_message_size: oxibus_core::types::DEFAULT_MAX_MESSAGE_LEN,
        })
    }

    pub fn set_max_message_size(&mut self, max: u32) {
        self.max_message_size = max;
    }

    pub fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    pub fn raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    pub fn writer(&self) -> Writer {
        Writer {
            stream: self.stream.clone(),
        }
    }

    async fn fill_more(&mut self) -> io::Result<()> {
        loop {
            self.stream.ready(Interest::READABLE).await?;
            let mut chunk = [0u8; 65536];
            let stream = &self.stream;
            let result: io::Result<(usize, Vec<RawFd>)> = stream.try_io(Interest::READABLE, || {
                fds::recv_with_fds(stream.as_raw_fd(), &mut chunk)
            });
            match result {
                Ok((0, _)) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed"));
                }
                Ok((n, recv_fds)) => {
                    self.read_buf.extend_from_slice(&chunk[..n]);
                    self.pending_fds.extend(recv_fds);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn send_initial_nul(&self) -> io::Result<()> {
        self.writer().send_initial_nul().await
    }

    pub async fn read_initial_nul(&mut self) -> io::Result<()> {
        while self.read_buf.is_empty() {
            self.fill_more().await?;
        }
        if self.read_buf[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected leading NUL byte",
            ));
        }
        self.read_buf.drain(0..1);
        Ok(())
    }

    pub async fn read_line(&mut self) -> io::Result<String> {
        loop {
            if let Some(pos) = find_crlf(&self.read_buf) {
                let line = self.read_buf.drain(0..pos).collect::<Vec<u8>>();
                self.read_buf.drain(0..2);
                let s = String::from_utf8(line).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 SASL line")
                })?;
                return Ok(s);
            }
            if self.read_buf.len() > MAX_AUTH_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SASL line too long",
                ));
            }
            self.fill_more().await?;
        }
    }

    pub async fn write_line(&self, line: &str) -> io::Result<()> {
        self.writer().write_line(line).await
    }

    pub async fn read_message(&mut self) -> io::Result<Message> {
        let frame_len = loop {
            match MessageHeader::peek_frame_len(&self.read_buf) {
                Ok(Some(len)) => break len,
                Ok(None) => self.fill_more().await?,
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
                }
            }
        };
        if frame_len > self.max_message_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "message of {frame_len} bytes exceeds max_message_size ({})",
                    self.max_message_size
                ),
            ));
        }
        while self.read_buf.len() < frame_len {
            self.fill_more().await?;
        }
        let frame: Vec<u8> = self.read_buf.drain(0..frame_len).collect();

        let (header, _) = MessageHeader::read(&frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let declared_fds = header.unix_fds() as usize;
        let taken_fds: Vec<RawFd> = if declared_fds > 0 {
            self.pending_fds
                .drain(0..declared_fds.min(self.pending_fds.len()))
                .collect()
        } else {
            Vec::new()
        };

        Message::from_bytes(&frame, taken_fds)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    pub async fn write_message(&self, msg: &Message) -> io::Result<()> {
        self.writer().write_message(msg).await
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sasl_line_and_nul_roundtrip() {
        let (a, b) = UnixStream::pair().unwrap();
        let ta = Transport::new(a).unwrap();
        let mut tb = Transport::new(b).unwrap();

        ta.send_initial_nul().await.unwrap();
        ta.write_line("AUTH EXTERNAL").await.unwrap();

        tb.read_initial_nul().await.unwrap();
        let line = tb.read_line().await.unwrap();
        assert_eq!(line, "AUTH EXTERNAL");
    }

    #[tokio::test]
    async fn message_roundtrip_over_pair() {
        use oxibus_core::{MessageBuilder, ObjectPath, SerialGenerator};

        let (a, b) = UnixStream::pair().unwrap();
        let ta = Transport::new(a).unwrap();
        let mut tb = Transport::new(b).unwrap();

        let serial = SerialGenerator::new();
        let msg = MessageBuilder::method_call(ObjectPath::new("/").unwrap(), "Ping")
            .build(serial.next());
        ta.write_message(&msg).await.unwrap();

        let got = tb.read_message().await.unwrap();
        assert_eq!(got.member(), Some("Ping"));
    }

    #[tokio::test]
    async fn oversized_message_is_rejected_before_buffering_body() {
        use oxibus_core::{ArrayValue, MessageBuilder, ObjectPath, SerialGenerator, Type, Value};

        let (a, b) = UnixStream::pair().unwrap();
        let ta = Transport::new(a).unwrap();
        let mut tb = Transport::new(b).unwrap();
        tb.set_max_message_size(64);

        let serial = SerialGenerator::new();
        let big_array = Value::Array(ArrayValue::new(
            Type::Byte,
            vec![Value::Byte(0); 200],
        ));
        let msg = MessageBuilder::method_call(ObjectPath::new("/").unwrap(), "Ping")
            .arg(big_array)
            .build(serial.next());
        ta.write_message(&msg).await.unwrap();

        let err = tb.read_message().await.unwrap_err();
        assert!(err.to_string().contains("exceeds max_message_size"));
    }

    #[tokio::test]
    async fn writer_can_be_cloned_and_used_from_another_task() {
        let (a, b) = UnixStream::pair().unwrap();
        let ta = Transport::new(a).unwrap();
        let mut tb = Transport::new(b).unwrap();

        let writer = ta.writer();
        let writer2 = writer.clone();
        let handle = tokio::spawn(async move { writer2.write_line("PING").await });

        handle.await.unwrap().unwrap();
        let line = tb.read_line().await.unwrap();
        assert_eq!(line, "PING");
    }
}
