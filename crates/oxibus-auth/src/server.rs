// Server-side SASL state machine.

use sha1::{Digest, Sha1};

use oxibus_transport::PeerCredentials;

use crate::keyring::{DEFAULT_CONTEXT, Keyring};
use crate::mechanism::{Mechanism, mechanism_list_string};

const N_CHALLENGE_BYTES: usize = 128 / 8;
const MAX_FAILURES: u32 = 6;

#[derive(Debug, Clone, Default)]
struct CookieState {
    cookie_id: Option<u32>,
    server_challenge_hex: Option<String>,
}

#[derive(Debug, Clone)]
enum State {
    WaitingForAuth,
    WaitingForData {
        mechanism: Mechanism,
        cookie: CookieState,
    },
    WaitingForBegin {
        uid: Option<u32>,
    },
}

#[derive(Debug)]
pub enum ServerAction {
    Send(Vec<String>),
    Begin {
        uid: Option<u32>,
    },
    Disconnect(String),
}

pub struct ServerAuth {
    peer: PeerCredentials,
    allowed_mechanisms: Vec<Mechanism>,
    allow_anonymous: bool,
    guid_hex: String,
    state: State,
    failures: u32,
    unix_fd_negotiated: bool,
    home_dir: Option<std::path::PathBuf>,
}

impl ServerAuth {
    pub fn new(
        peer: PeerCredentials,
        allowed_mechanisms: Vec<Mechanism>,
        allow_anonymous: bool,
        guid_hex: String,
    ) -> Self {
        Self {
            peer,
            allowed_mechanisms,
            allow_anonymous,
            guid_hex,
            state: State::WaitingForAuth,
            failures: 0,
            unix_fd_negotiated: false,
            home_dir: std::env::var_os("HOME").map(std::path::PathBuf::from),
        }
    }

    pub fn unix_fd_negotiated(&self) -> bool {
        self.unix_fd_negotiated
    }

    fn rejected(&mut self) -> ServerAction {
        self.failures += 1;
        self.state = State::WaitingForAuth;
        if self.failures >= MAX_FAILURES {
            return ServerAction::Disconnect("too many authentication failures".into());
        }
        ServerAction::Send(vec![format!(
            "REJECTED {}",
            mechanism_list_string(&self.allowed_mechanisms)
        )])
    }

    fn ok(&mut self, uid: Option<u32>) -> ServerAction {
        self.state = State::WaitingForBegin { uid };
        ServerAction::Send(vec![format!("OK {}", self.guid_hex)])
    }

    fn error(&self, msg: &str) -> ServerAction {
        ServerAction::Send(vec![format!("ERROR \"{msg}\"")])
    }

    pub fn feed_line(&mut self, line: &str) -> ServerAction {
        let (command, rest) = split_command(line);
        match &self.state {
            State::WaitingForAuth => self.handle_waiting_for_auth(command, rest),
            State::WaitingForData { .. } => self.handle_waiting_for_data(command, rest),
            State::WaitingForBegin { .. } => self.handle_waiting_for_begin(command, rest),
        }
    }

    fn handle_waiting_for_auth(&mut self, command: &str, rest: &str) -> ServerAction {
        match command {
            "AUTH" => {
                if rest.is_empty() {
                    return self.rejected();
                }
                let mut parts = rest.splitn(2, ' ');
                let mech_name = parts.next().unwrap_or("");
                let initial_hex = parts.next();

                let Some(mechanism) = Mechanism::parse(mech_name) else {
                    return self.rejected();
                };
                if !self.allowed_mechanisms.contains(&mechanism) {
                    return self.rejected();
                }
                if mechanism == Mechanism::Anonymous && !self.allow_anonymous {
                    return self.rejected();
                }

                match initial_hex {
                    Some(hex_data) => {
                        let Ok(data) = decode_hex_ascii(hex_data) else {
                            return self.rejected();
                        };
                        self.state = State::WaitingForData {
                            mechanism,
                            cookie: CookieState::default(),
                        };
                        self.dispatch_mechanism_data(mechanism, &data, true)
                    }
                    None => {
                        self.state = State::WaitingForData {
                            mechanism,
                            cookie: CookieState::default(),
                        };
                        ServerAction::Send(vec!["DATA ".to_string()])
                    }
                }
            }
            "ERROR" => self.rejected(),
            _ => self.error("Sent unexpected command while expecting AUTH"),
        }
    }

    fn handle_waiting_for_data(&mut self, command: &str, rest: &str) -> ServerAction {
        let State::WaitingForData { mechanism, .. } = self.state.clone() else {
            unreachable!()
        };
        match command {
            "DATA" => {
                let Ok(data) = decode_hex_ascii(rest) else {
                    return self.rejected();
                };
                self.dispatch_mechanism_data(mechanism, &data, false)
            }
            "CANCEL" => self.rejected(),
            "ERROR" => self.rejected(),
            "BEGIN" => self.error("Sent BEGIN while expecting DATA"),
            "AUTH" => self.error("Sent AUTH while expecting DATA"),
            _ => self.error("Unknown command while expecting DATA"),
        }
    }

    fn handle_waiting_for_begin(&mut self, command: &str, _rest: &str) -> ServerAction {
        let State::WaitingForBegin { uid } = self.state else {
            unreachable!()
        };
        match command {
            "BEGIN" => ServerAction::Begin { uid },
            "NEGOTIATE_UNIX_FD" => {
                self.unix_fd_negotiated = true;
                ServerAction::Send(vec!["AGREE_UNIX_FD".to_string()])
            }
            "CANCEL" => self.rejected(),
            "ERROR" => self.rejected(),
            _ => self.error("Unknown command while expecting BEGIN"),
        }
    }

    fn dispatch_mechanism_data(
        &mut self,
        mechanism: Mechanism,
        data: &[u8],
        already_asked_now: bool,
    ) -> ServerAction {
        match mechanism {
            Mechanism::External => self.handle_external(data, already_asked_now),
            Mechanism::Anonymous => self.handle_anonymous(),
            Mechanism::DbusCookieSha1 => self.handle_cookie_sha1(data),
        }
    }

    fn handle_external(&mut self, data: &[u8], _already_asked_now: bool) -> ServerAction {
        let desired_uid: Option<u32> = if data.is_empty() {
            Some(self.peer.uid)
        } else {
            std::str::from_utf8(data)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
        };
        match desired_uid {
            Some(uid) if uid == self.peer.uid => self.ok(Some(uid)),
            _ => self.rejected(),
        }
    }

    fn handle_anonymous(&mut self) -> ServerAction {
        self.ok(None)
    }

    fn handle_cookie_sha1(&mut self, data: &[u8]) -> ServerAction {
        let State::WaitingForData { cookie, .. } = self.state.clone() else {
            unreachable!()
        };
        match cookie.cookie_id {
            None => self.cookie_sha1_first_response(data),
            Some(cookie_id) => self.cookie_sha1_second_response(cookie_id, &cookie, data),
        }
    }

    fn cookie_sha1_first_response(&mut self, data: &[u8]) -> ServerAction {
        let desired_uid: Option<u32> = if data.is_empty() {
            Some(self.peer.uid)
        } else {
            std::str::from_utf8(data)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
        };
        let our_uid = oxibus_transport::current_uid();
        if desired_uid != Some(self.peer.uid) || self.peer.uid != our_uid {
            return self.rejected();
        }
        let Some(home) = self.home_dir.clone() else {
            return self.rejected();
        };

        let mut keyring = match Keyring::load(&home, DEFAULT_CONTEXT) {
            Ok(k) => k,
            Err(_) => return self.rejected(),
        };
        let cookie_id = match keyring.best_key() {
            Ok(id) => id,
            Err(_) => return self.rejected(),
        };

        let mut challenge_raw = [0u8; N_CHALLENGE_BYTES];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge_raw);
        let challenge_hex = hex::encode(challenge_raw);

        let reply = format!("{DEFAULT_CONTEXT} {cookie_id} {challenge_hex}");
        self.state = State::WaitingForData {
            mechanism: Mechanism::DbusCookieSha1,
            cookie: CookieState {
                cookie_id: Some(cookie_id),
                server_challenge_hex: Some(challenge_hex),
            },
        };
        ServerAction::Send(vec![format!("DATA {}", hex::encode(reply))])
    }

    fn cookie_sha1_second_response(
        &mut self,
        cookie_id: u32,
        cookie: &CookieState,
        data: &[u8],
    ) -> ServerAction {
        let Ok(text) = std::str::from_utf8(data) else {
            return self.rejected();
        };
        let Some((client_challenge_hex, client_hash_hex)) = text.split_once(' ') else {
            return self.rejected();
        };
        if client_challenge_hex.is_empty() || client_hash_hex.is_empty() {
            return self.rejected();
        }

        let Some(home) = self.home_dir.clone() else {
            return self.rejected();
        };
        let keyring = match Keyring::load(&home, DEFAULT_CONTEXT) {
            Ok(k) => k,
            Err(_) => return self.rejected(),
        };
        let Some(cookie_hex) = keyring.hex_key(cookie_id) else {
            return self.rejected();
        };
        let server_challenge_hex = cookie.server_challenge_hex.clone().unwrap_or_default();

        let to_hash = format!("{server_challenge_hex}:{client_challenge_hex}:{cookie_hex}");
        let expected_hash = hex::encode(Sha1::digest(to_hash.as_bytes()));

        if expected_hash != client_hash_hex {
            return self.rejected();
        }
        self.ok(Some(self.peer.uid))
    }
}

fn split_command(line: &str) -> (&str, &str) {
    match line.split_once(' ') {
        Some((cmd, rest)) => (cmd, rest.trim_start()),
        None => (line, ""),
    }
}

fn decode_hex_ascii(hex_str: &str) -> Result<Vec<u8>, ()> {
    hex::decode(hex_str).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32) -> PeerCredentials {
        PeerCredentials {
            uid,
            gid: uid,
            pid: 1,
        }
    }

    #[test]
    fn external_with_initial_response_matching_peer_authenticates() {
        let my_uid = oxibus_transport::current_uid();
        let mut auth = ServerAuth::new(
            peer(my_uid),
            vec![Mechanism::External],
            false,
            "deadbeef".into(),
        );
        let hex_uid = hex::encode(my_uid.to_string());
        let action = auth.feed_line(&format!("AUTH EXTERNAL {hex_uid}"));
        match action {
            ServerAction::Send(lines) => assert!(lines[0].starts_with("OK ")),
            other => panic!("expected OK, got {other:?}"),
        }
        let begin = auth.feed_line("BEGIN");
        assert!(matches!(begin, ServerAction::Begin { uid: Some(u) } if u == my_uid));
    }

    #[test]
    fn external_with_mismatched_uid_is_rejected() {
        let mut auth = ServerAuth::new(
            peer(1000),
            vec![Mechanism::External],
            false,
            "deadbeef".into(),
        );
        let hex_uid = hex::encode("9999");
        let action = auth.feed_line(&format!("AUTH EXTERNAL {hex_uid}"));
        match action {
            ServerAction::Send(lines) => assert!(lines[0].starts_with("REJECTED")),
            other => panic!("expected REJECTED, got {other:?}"),
        }
    }

    #[test]
    fn unknown_mechanism_is_rejected() {
        let mut auth = ServerAuth::new(peer(1000), vec![Mechanism::External], false, "g".into());
        let action = auth.feed_line("AUTH BOGUS");
        assert!(matches!(action, ServerAction::Send(_)));
    }

    #[test]
    fn anonymous_disallowed_by_default() {
        let mut auth = ServerAuth::new(peer(1000), vec![Mechanism::Anonymous], false, "g".into());
        let action = auth.feed_line("AUTH ANONYMOUS 74657374");
        match action {
            ServerAction::Send(lines) => assert!(lines[0].starts_with("REJECTED")),
            other => panic!("expected REJECTED, got {other:?}"),
        }
    }

    #[test]
    fn anonymous_allowed_authenticates_with_no_uid() {
        let mut auth = ServerAuth::new(peer(1000), vec![Mechanism::Anonymous], true, "g".into());
        let action = auth.feed_line("AUTH ANONYMOUS 74657374");
        assert!(matches!(action, ServerAction::Send(ref l) if l[0].starts_with("OK ")));
        let begin = auth.feed_line("BEGIN");
        assert!(matches!(begin, ServerAction::Begin { uid: None }));
    }

    #[test]
    fn max_failures_disconnects() {
        let mut auth = ServerAuth::new(peer(1000), vec![Mechanism::External], false, "g".into());
        let mut last = ServerAction::Send(vec![]);
        for _ in 0..MAX_FAILURES {
            last = auth.feed_line("AUTH BOGUS");
        }
        assert!(matches!(last, ServerAction::Disconnect(_)));
    }

    #[test]
    fn cookie_sha1_full_handshake() {
        let my_uid = oxibus_transport::current_uid();
        let home =
            std::env::temp_dir().join(format!("oxibus-auth-cookie-test-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
        }

        let mut server = ServerAuth::new(
            peer(my_uid),
            vec![Mechanism::DbusCookieSha1],
            false,
            "guid1".into(),
        );

        let hex_uid = hex::encode(my_uid.to_string());
        let first = server.feed_line(&format!("AUTH DBUS_COOKIE_SHA1 {hex_uid}"));
        let ServerAction::Send(lines) = first else {
            panic!("expected DATA challenge")
        };
        assert!(lines[0].starts_with("DATA "));
        let challenge_hex_payload = lines[0].strip_prefix("DATA ").unwrap();
        let payload = String::from_utf8(hex::decode(challenge_hex_payload).unwrap()).unwrap();
        let mut it = payload.splitn(3, ' ');
        let context = it.next().unwrap();
        let cookie_id: u32 = it.next().unwrap().parse().unwrap();
        let server_challenge_hex = it.next().unwrap().to_string();
        assert_eq!(context, DEFAULT_CONTEXT);

        let keyring = Keyring::load(&home, DEFAULT_CONTEXT).unwrap();
        let cookie_hex = keyring.hex_key(cookie_id).unwrap();

        let client_challenge_hex = hex::encode([7u8; 16]);
        let to_hash = format!("{server_challenge_hex}:{client_challenge_hex}:{cookie_hex}");
        let hash_hex = hex::encode(Sha1::digest(to_hash.as_bytes()));
        let response = format!("{client_challenge_hex} {hash_hex}");

        let second = server.feed_line(&format!("DATA {}", hex::encode(response)));
        match second {
            ServerAction::Send(lines) => assert!(lines[0].starts_with("OK ")),
            other => panic!("expected OK, got {other:?}"),
        }

        std::fs::remove_dir_all(&home).ok();
    }
}
