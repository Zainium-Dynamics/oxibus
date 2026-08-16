//! Client-side SASL state machine.

use sha1::{Digest, Sha1};

use crate::keyring::Keyring;
use crate::mechanism::Mechanism;

/// Outcome of feeding one line to [`ClientAuth`], describing what the
/// caller should do next.
#[derive(Debug)]
pub enum ClientAction {
    /// Send this line to the server.
    Send(String),
    /// Server said OK — auth succeeded. Call [`ClientAuth::finish_lines`]
    /// to get the line(s) needed to finish the handshake (and learn
    /// whether an `AGREE_UNIX_FD` reply must still be consumed) before
    /// switching to binary framing.
    Authenticated,
    /// This mechanism was rejected; try the next one via
    /// [`ClientAuth::try_next_mechanism`], or fail the connection if none
    /// are left.
    MechanismRejected {
        /// Mechanism names the server reports it accepts, taken verbatim
        /// from the `REJECTED` line (not filtered to ones we understand).
        server_supported: Vec<String>,
    },
    /// The server sent something that violates the SASL protocol; the
    /// connection should be closed. Carries a human-readable description.
    ProtocolError(String),
}

enum State {
    Init,
    WaitingForDataOrOk {
        mechanism: Mechanism,
        cookie_pending_id: Option<u32>,
    },
    WaitingForAgreeUnixFd,
    Authenticated,
}

/// Client-side SASL state machine: drives an ordered list of mechanisms
/// through the auth handshake, one at a time, until one succeeds or all
/// are exhausted.
pub struct ClientAuth {
    mechanisms: Vec<Mechanism>,
    tried: usize,
    state: State,
    want_unix_fd: bool,
    home_dir: Option<std::path::PathBuf>,
}

impl ClientAuth {
    /// Create a state machine that will try `mechanisms` in order,
    /// starting with the first once [`ClientAuth::start`] is called. If
    /// `want_unix_fd` is set, `NEGOTIATE_UNIX_FD` is queued once
    /// authenticated ([`ClientAuth::finish_lines`]).
    pub fn new(mechanisms: Vec<Mechanism>, want_unix_fd: bool) -> Self {
        Self {
            mechanisms,
            tried: 0,
            state: State::Init,
            want_unix_fd,
            home_dir: std::env::var_os("HOME").map(std::path::PathBuf::from),
        }
    }

    /// The first line to send once the leading NUL byte has gone out.
    pub fn start(&mut self) -> String {
        self.begin_mechanism(0)
    }

    fn begin_mechanism(&mut self, index: usize) -> String {
        self.tried = index;
        let mechanism = self.mechanisms[index];
        self.state = State::WaitingForDataOrOk {
            mechanism,
            cookie_pending_id: None,
        };
        match mechanism {
            Mechanism::External => {
                let uid = oxibus_transport::current_uid().to_string();
                format!("AUTH EXTERNAL {}", hex::encode(uid))
            }
            Mechanism::Anonymous => {
                format!("AUTH ANONYMOUS {}", hex::encode("oxibus"))
            }
            Mechanism::DbusCookieSha1 => {
                let uid = oxibus_transport::current_uid().to_string();
                format!("AUTH DBUS_COOKIE_SHA1 {}", hex::encode(uid))
            }
        }
    }

    /// Whether there is another mechanism left to try after the current
    /// one.
    pub fn has_more_mechanisms(&self) -> bool {
        self.tried + 1 < self.mechanisms.len()
    }

    /// Advance to the next mechanism in the list and return the `AUTH`
    /// line to send for it, or `None` if the list is exhausted.
    pub fn try_next_mechanism(&mut self) -> Option<String> {
        if self.has_more_mechanisms() {
            Some(self.begin_mechanism(self.tried + 1))
        } else {
            None
        }
    }

    /// Feed one CRLF-stripped line received from the server and return
    /// the resulting action.
    pub fn feed_line(&mut self, line: &str) -> ClientAction {
        let (command, rest) = line.split_once(' ').unwrap_or((line, ""));
        match command {
            "OK" => {
                self.state = State::Authenticated;
                ClientAction::Authenticated
            }
            "REJECTED" => ClientAction::MechanismRejected {
                server_supported: rest.split_whitespace().map(String::from).collect(),
            },
            "DATA" => self.handle_data(rest.trim()),
            "ERROR" => ClientAction::ProtocolError(rest.to_string()),
            "AGREE_UNIX_FD" => ClientAction::Authenticated,
            other => ClientAction::ProtocolError(format!("unexpected server command: {other}")),
        }
    }

    fn handle_data(&mut self, hex_payload: &str) -> ClientAction {
        let State::WaitingForDataOrOk {
            mechanism,
            cookie_pending_id,
        } = &self.state
        else {
            return ClientAction::ProtocolError("DATA received in wrong state".into());
        };
        let mechanism = *mechanism;
        let data = match hex::decode(hex_payload) {
            Ok(d) => d,
            Err(_) => return ClientAction::ProtocolError("bad hex in DATA".into()),
        };

        match mechanism {
            Mechanism::External | Mechanism::Anonymous => {
                // Server is re-prompting (e.g. we sent AUTH with no initial
                // response); reply with the same identity/trace string.
                ClientAction::Send(self.begin_mechanism(self.tried))
            }
            Mechanism::DbusCookieSha1 => {
                if cookie_pending_id.is_some() {
                    // Shouldn't normally receive a second DATA challenge;
                    // treat as protocol error rather than looping forever.
                    return ClientAction::ProtocolError(
                        "unexpected second DATA challenge for DBUS_COOKIE_SHA1".into(),
                    );
                }
                self.respond_to_cookie_challenge(&data)
            }
        }
    }

    fn respond_to_cookie_challenge(&mut self, data: &[u8]) -> ClientAction {
        let Ok(text) = std::str::from_utf8(data) else {
            return ClientAction::ProtocolError("non-UTF8 cookie challenge".into());
        };
        let mut it = text.splitn(3, ' ');
        let (Some(context), Some(cookie_id_str), Some(server_challenge_hex)) =
            (it.next(), it.next(), it.next())
        else {
            return ClientAction::ProtocolError("malformed cookie challenge".into());
        };
        let Ok(cookie_id) = cookie_id_str.parse::<u32>() else {
            return ClientAction::ProtocolError("bad cookie id".into());
        };

        let Some(home) = self.home_dir.clone() else {
            return ClientAction::ProtocolError("no HOME for keyring".into());
        };
        let keyring = match Keyring::load(&home, context) {
            Ok(k) => k,
            Err(e) => return ClientAction::ProtocolError(e.to_string()),
        };
        let Some(cookie_hex) = keyring.hex_key(cookie_id) else {
            return ClientAction::ProtocolError(format!("unknown cookie id {cookie_id}"));
        };

        let mut client_challenge_raw = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut client_challenge_raw);
        let client_challenge_hex = hex::encode(client_challenge_raw);

        let to_hash = format!("{server_challenge_hex}:{client_challenge_hex}:{cookie_hex}");
        let hash_hex = hex::encode(Sha1::digest(to_hash.as_bytes()));
        let response = format!("{client_challenge_hex} {hash_hex}");

        self.state = State::WaitingForDataOrOk {
            mechanism: Mechanism::DbusCookieSha1,
            cookie_pending_id: Some(cookie_id),
        };
        let _ = context; // only used for keyring lookup above
        ClientAction::Send(format!("DATA {}", hex::encode(response)))
    }

    /// Call once authenticated: returns the line(s) needed to finish the
    /// handshake and switch to binary framing. If this returns `true` for
    /// `unix_fd_requested`, the caller MUST read and discard exactly one
    /// more SASL line (the server's `AGREE_UNIX_FD`) before switching the
    /// transport to binary framing — it is pipelined ahead of `BEGIN`'s
    /// effect but still arrives as a text line first.
    pub fn finish_lines(&mut self) -> (Vec<String>, bool) {
        if self.want_unix_fd {
            self.state = State::WaitingForAgreeUnixFd;
            (
                vec!["NEGOTIATE_UNIX_FD".to_string(), "BEGIN".to_string()],
                true,
            )
        } else {
            (vec!["BEGIN".to_string()], false)
        }
    }
}
