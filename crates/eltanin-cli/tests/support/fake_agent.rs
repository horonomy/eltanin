//! A scripted UDS agent double for `eltanin-cli` integration tests
//! (F-M1-008, HORO-846). Unlike a single-`accept()` harness, this runs a
//! real accept *loop* — a renewal test needs 3+ connections, not one.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use eltanin_core::envelope::Versioned;
use eltanin_protocol::framing::{decode_frame_len, decode_request, encode_response};
use eltanin_protocol::request::ClientRequest;
use eltanin_protocol::response::{AgentResponse, ResponseBody};

type Handler = dyn FnMut(&ClientRequest) -> AgentResponse + Send;

/// A running fake agent. Dropping this does not stop the accept-loop
/// thread (the test process exits at the end of the test binary
/// regardless) — tests only need its socket path and recorded requests.
pub struct FakeAgent {
    socket_path: PathBuf,
    requests: Arc<Mutex<Vec<ClientRequest>>>,
}

static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

impl FakeAgent {
    /// Start a fake agent whose responses are computed by `handler`,
    /// called once per received request in the order requests arrive.
    #[must_use]
    pub fn start(handler: impl FnMut(&ClientRequest) -> AgentResponse + Send + 'static) -> Self {
        let n = NEXT_SOCKET.fetch_add(1, Ordering::SeqCst);
        let socket_path = std::env::temp_dir().join(format!(
            "eltanin-cli-fake-agent-{}-{n}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind fake agent socket");

        let requests: Arc<Mutex<Vec<ClientRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Mutex<Box<Handler>>> = Arc::new(Mutex::new(Box::new(handler)));

        let requests_for_loop = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let requests = Arc::clone(&requests_for_loop);
                let handler = Arc::clone(&handler);
                thread::spawn(move || serve_one(stream, &requests, &handler));
            }
        });

        Self {
            socket_path,
            requests,
        }
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Every request received so far, in arrival order.
    #[must_use]
    pub fn requests(&self) -> Vec<ClientRequest> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

fn serve_one(
    mut stream: UnixStream,
    requests: &Arc<Mutex<Vec<ClientRequest>>>,
    handler: &Arc<Mutex<Box<Handler>>>,
) {
    let mut header = [0u8; 4];
    if stream.read_exact(&mut header).is_err() {
        return;
    }
    let Ok(len) = decode_frame_len(header) else {
        return;
    };
    let mut body = vec![0u8; len];
    if stream.read_exact(&mut body).is_err() {
        return;
    }
    let Ok(request) = decode_request(&body) else {
        return;
    };

    requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(request.payload.body.clone());

    let response_body =
        (handler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))(&request.payload.body);
    let response = Versioned::current(ResponseBody {
        request_id: Some(request.payload.request_id),
        body: response_body,
    });
    if let Ok(framed) = encode_response(&response) {
        let _ = stream.write_all(&framed).and_then(|()| stream.flush());
    }
}
