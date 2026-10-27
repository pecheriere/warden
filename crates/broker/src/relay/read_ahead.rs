//! Reading an agent's connection ahead of the SSH library, so that the
//! agent leaving is seen even while the library's event loop is held up
//! (a relayed session waiting on a target that does not read its input).
//!
//! What is read ahead is held in chunks whose bytes are counted against a
//! fixed budget: [`PRE_LOGIN_BYTES`] until the agent has logged in, then
//! [`LOGGED_IN_BYTES`]. A chunk's room is given back as the library reads
//! it, and its memory freed once read.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncReadExt as _, Join, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;

/// The SSH window the relay grants an agent's session channel (russh's
/// default, stated here because [`LOGGED_IN_BYTES`] depends on it).
pub(crate) const AGENT_WINDOW_BYTES: u32 = 2 * 1024 * 1024;

/// Most bytes read ahead for a logged-in agent. The SSH library grants the
/// agent window only as it handles the agent's channel data, so once it
/// stops (its event loop held up) the agent can send at most one window of
/// channel data, plus framing, before the close that ends its connection:
/// twice the window holds that, so the close is seen. Messages outside the
/// channel have no window; an agent that sends past this only fills the
/// read-ahead, and its session is ended by the stall watchdog.
const LOGGED_IN_BYTES: usize = 4 * 1024 * 1024;

/// Most bytes read ahead before the agent has logged in: the library reads
/// a connection in that phase continuously, so this only bounds what an
/// unauthenticated peer can make the relay hold.
const PRE_LOGIN_BYTES: usize = 64 * 1024;

// Logging in raises the budget.
const _: () = assert!(PRE_LOGIN_BYTES < LOGGED_IN_BYTES);

/// Most bytes taken from the socket in one read.
const READ_BYTES: usize = 16 * 1024;

/// What each chunk counts for at least, so that its bookkeeping (its queue
/// slot and allocation) is counted too and many small reads keep heap use
/// within a small factor of the budget.
const CHUNK_MIN_BYTES: usize = 128;

/// An agent's connection as the SSH library uses it: its socket read
/// ahead, its writes going straight out.
pub(crate) type AgentStream = Join<AheadReader, OwnedWriteHalf>;

/// Reads an agent's socket ahead of the SSH library; stops when dropped.
#[derive(Debug)]
pub(crate) struct ReadAhead(JoinHandle<()>);

impl Drop for ReadAhead {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Resolves once the agent has closed its connection (or it failed), as
/// the read-ahead saw it, whatever state the SSH library is in.
#[derive(Debug, Clone)]
pub(crate) struct AgentGone(watch::Receiver<bool>);

impl AgentGone {
    /// One told by `gone`, for tests of what waits on it.
    #[cfg(test)]
    pub(crate) fn new(gone: watch::Receiver<bool>) -> Self {
        Self(gone)
    }

    pub(crate) async fn wait(&mut self) {
        // The sender is dropped only once the close is recorded, or with
        // the connection: nothing to wait for then.
        if self.0.wait_for(|gone| *gone).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Raises the read-ahead's budget to [`LOGGED_IN_BYTES`] once the agent
/// has logged in.
#[derive(Debug)]
pub(crate) struct LoggedIn(Option<Arc<Semaphore>>);

impl LoggedIn {
    /// The agent logged in; only the first call has an effect.
    pub(crate) fn raise(&mut self) {
        if let Some(room) = self.0.take() {
            room.add_permits(LOGGED_IN_BYTES - PRE_LOGIN_BYTES);
        }
    }
}

/// Bytes read ahead, holding their room in the budget until read.
#[derive(Debug)]
struct Chunk {
    data: Vec<u8>,
    /// How much of `data` the library has read.
    read: usize,
    room: OwnedSemaphorePermit,
}

impl Chunk {
    fn unread(&self) -> &[u8] {
        &self.data[self.read..]
    }
}

/// The read side of an [`AgentStream`]: what the read-ahead took from the
/// socket, in order, then the end of the stream.
#[derive(Debug)]
pub(crate) struct AheadReader {
    chunks: mpsc::UnboundedReceiver<Chunk>,
    current: Option<Chunk>,
}

impl AsyncRead for AheadReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.current.is_none() {
            match ready!(this.chunks.poll_recv(cx)) {
                Some(chunk) => this.current = Some(chunk),
                // The read-ahead is over and everything was read.
                None => return Poll::Ready(Ok(())),
            }
        }
        let Some(chunk) = &mut this.current else {
            return Poll::Ready(Ok(()));
        };
        let taken = chunk.unread().len().min(buf.remaining());
        buf.put_slice(&chunk.unread()[..taken]);
        chunk.read += taken;
        if chunk.unread().is_empty() {
            // Its room goes back with it.
            this.current = None;
        } else {
            // Room for what is read goes back now; the rest still counts
            // for at least a chunk.
            let keep = chunk.unread().len().max(CHUNK_MIN_BYTES);
            let free = chunk.room.num_permits().saturating_sub(keep);
            drop(chunk.room.split(free));
        }
        Poll::Ready(Ok(()))
    }
}

/// Read `socket` ahead of the SSH library (see the module documentation):
/// the stream for the library, whether the agent has gone, the handle
/// raising the budget at login, and the read-ahead's lifetime.
pub(crate) fn read_ahead(socket: TcpStream) -> (AgentStream, AgentGone, LoggedIn, ReadAhead) {
    read_ahead_within(socket, PRE_LOGIN_BYTES)
}

fn read_ahead_within(
    socket: TcpStream,
    budget: usize,
) -> (AgentStream, AgentGone, LoggedIn, ReadAhead) {
    let (from_agent, to_agent) = socket.into_split();
    let room = Arc::new(Semaphore::new(budget));
    let (tx, chunks) = mpsc::unbounded_channel();
    let (gone, gone_rx) = watch::channel(false);
    let reading = Arc::clone(&room);
    let task = tokio::spawn(async move {
        pump(from_agent, reading, tx).await;
        // The agent closed the connection, it failed or was cut, or the
        // library is gone: each is the end of the agent here. The library
        // reads what is left, then the end of the stream.
        gone.send_replace(true);
    });
    let reader = AheadReader {
        chunks,
        current: None,
    };
    (
        tokio::io::join(reader, to_agent),
        AgentGone(gone_rx),
        LoggedIn(Some(room)),
        ReadAhead(task),
    )
}

/// Move bytes from the socket into chunks for the reader while the budget
/// has room, until the socket or the reader is done.
async fn pump(
    mut from_agent: OwnedReadHalf,
    room: Arc<Semaphore>,
    chunks: mpsc::UnboundedSender<Chunk>,
) {
    let Ok(chunk_min) = u32::try_from(CHUNK_MIN_BYTES) else {
        return;
    };
    let mut buf = vec![0_u8; READ_BYTES];
    loop {
        // Room for at least a chunk, and for as much of a read as is free.
        let Ok(mut held) = Arc::clone(&room).acquire_many_owned(chunk_min).await else {
            return;
        };
        let more = room.available_permits().min(READ_BYTES - CHUNK_MIN_BYTES);
        if let Ok(more) = u32::try_from(more)
            && more > 0
            && let Ok(extra) = Arc::clone(&room).try_acquire_many_owned(more)
        {
            held.merge(extra);
        }
        let want = held.num_permits();
        let read = match from_agent.read(&mut buf[..want]).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        // Give back what the read did not use; a chunk keeps its minimum.
        drop(held.split(want - read.max(CHUNK_MIN_BYTES)));
        let chunk = Chunk {
            data: buf[..read].to_vec(),
            read: 0,
            room: held,
        };
        if chunks.send(chunk).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::{Semaphore, mpsc};

    use super::{
        AGENT_WINDOW_BYTES, AheadReader, CHUNK_MIN_BYTES, Chunk, LOGGED_IN_BYTES, PRE_LOGIN_BYTES,
        read_ahead, read_ahead_within,
    };

    #[test]
    fn logged_in_budget_holds_a_window_and_its_framing() {
        let window = usize::try_from(AGENT_WINDOW_BYTES).unwrap();
        assert!(LOGGED_IN_BYTES >= 2 * window);
    }

    async fn pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let agent = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        (agent, socket)
    }

    fn pattern(len: u32) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[tokio::test]
    async fn sees_the_agent_leave_while_nothing_is_read() {
        let (mut agent, socket) = pair().await;
        let (mut stream, mut gone, mut logged_in, _reading) = read_ahead(socket);
        logged_in.raise();
        // A window's worth of input, then the agent leaves; nothing reads
        // the stream meanwhile (the SSH library held up).
        let sent = pattern(2 * 1024 * 1024);
        agent.write_all(&sent).await.unwrap();
        drop(agent);
        tokio::time::timeout(Duration::from_secs(5), gone.wait())
            .await
            .expect("the close was seen");
        // The library still gets every byte, in order, then the end.
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert!(got == sent, "{} bytes of {}", got.len(), sent.len());
        // Writes still go out.
        stream.write_all(b"bye").await.unwrap();
    }

    /// Take chunks off `stream` (without reading them, so they keep their
    /// room) until the read-ahead is out of room: the chunks taken and the
    /// room still free account for the whole `budget` (the pump holds none
    /// for a read), and less than a chunk's minimum is free, so the pump
    /// waits for room. The agent always has more to send.
    async fn take_until_held(
        stream: &mut super::AgentStream,
        chunks: &mut Vec<Chunk>,
        budget: usize,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            while let Ok(chunk) = stream.reader_mut().chunks.try_recv() {
                chunks.push(chunk);
            }
            if let Some(first) = chunks.first() {
                let free = first.room.semaphore().available_permits();
                let held: usize = chunks.iter().map(|c| c.room.num_permits()).sum();
                assert!(
                    held + free <= budget,
                    "{held} held, {free} free of {budget}"
                );
                if held + free == budget && free < CHUNK_MIN_BYTES {
                    return;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the read-ahead did not fill its budget"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The chunks hold the whole budget (all but less than a chunk's
    /// minimum, which the read-ahead waits for), never more, and at most
    /// as many bytes as that.
    fn assert_full(chunks: &[Chunk], budget: usize) {
        let held: usize = chunks.iter().map(|c| c.room.num_permits()).sum();
        let data: usize = chunks.iter().map(|c| c.data.len()).sum();
        assert!(
            held <= budget && held + CHUNK_MIN_BYTES > budget,
            "{held} of {budget}"
        );
        assert!(data > 0 && data <= held, "{data} bytes held");
    }

    #[tokio::test]
    async fn bounded_before_and_after_login() {
        let (mut agent, socket) = pair().await;
        let (mut stream, mut gone, mut logged_in, _reading) = read_ahead(socket);
        // Far more than either budget; the writer is held up by TCP.
        let sent = pattern(16 * 1024 * 1024);
        let writing = {
            let sent = sent.clone();
            tokio::spawn(async move {
                agent.write_all(&sent).await.unwrap();
                agent
            })
        };
        let mut chunks = Vec::new();
        take_until_held(&mut stream, &mut chunks, PRE_LOGIN_BYTES).await;
        assert_full(&chunks, PRE_LOGIN_BYTES);
        logged_in.raise();
        // Only once.
        logged_in.raise();
        take_until_held(&mut stream, &mut chunks, LOGGED_IN_BYTES).await;
        assert_full(&chunks, LOGGED_IN_BYTES);
        // Once given back, the room is used again, and every byte arrives
        // in order.
        let mut got: Vec<u8> = chunks.iter().flat_map(|c| c.data.clone()).collect();
        drop(chunks);
        let (read, ()) = tokio::join!(stream.read_to_end(&mut got), async {
            let agent = writing.await.unwrap();
            drop(agent);
        });
        read.unwrap();
        assert!(got == sent, "{} bytes of {}", got.len(), sent.len());
        gone.wait().await;
    }

    #[tokio::test]
    async fn room_is_given_back_as_the_library_reads() {
        let room = Arc::new(Semaphore::new(1000));
        let (tx, chunks) = mpsc::unbounded_channel();
        let mut reader = AheadReader {
            chunks,
            current: None,
        };
        let chunk = |len: usize, charge: usize| Chunk {
            data: vec![7_u8; len],
            read: 0,
            room: Arc::clone(&room)
                .try_acquire_many_owned(u32::try_from(charge).unwrap())
                .unwrap(),
        };
        tx.send(chunk(300, 300)).unwrap();
        tx.send(chunk(10, CHUNK_MIN_BYTES)).unwrap();
        assert_eq!(room.available_permits(), 1000 - 300 - CHUNK_MIN_BYTES);
        let mut buf = [0_u8; 100];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(room.available_permits(), 1000 - 200 - CHUNK_MIN_BYTES);
        let mut buf = [0_u8; 200];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(room.available_permits(), 1000 - CHUNK_MIN_BYTES);
        // A small chunk counts for its minimum until it is read whole.
        let mut buf = [0_u8; 5];
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(room.available_permits(), 1000 - CHUNK_MIN_BYTES);
        reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(room.available_permits(), 1000);
        drop(tx);
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn small_budget_still_reads_everything() {
        let (mut agent, socket) = pair().await;
        let (mut stream, _gone, _logged_in, _reading) = read_ahead_within(socket, CHUNK_MIN_BYTES);
        let sent = pattern(100_000);
        agent.write_all(&sent).await.unwrap();
        drop(agent);
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert!(got == sent, "{} bytes of {}", got.len(), sent.len());
    }
}
