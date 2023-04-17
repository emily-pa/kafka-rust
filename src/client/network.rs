//! Network related functionality for `KafkaClient`.
//!
//! This module is crate private and not exposed to the public except
//! through re-exports of individual items from within
//! `kafka::client`.

use crate::{
    codecs::ToByte,
    error::Result,
    protocol::sasl_authenticate::SaslAuthenticateRequest,
    security::{KafkaStream, SaslConfig, TlsConfig},
};
use std::{
    collections::HashMap,
    fmt,
    io::{Read, Write},
    mem,
    net::Shutdown,
    time::{Duration, Instant},
};

// --------------------------------------------------------------------

struct Pooled<T> {
    last_checkout: Instant,
    item: T,
}

impl<T> Pooled<T> {
    fn new(last_checkout: Instant, item: T) -> Self {
        Pooled {
            last_checkout,
            item,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Pooled<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pooled {{ last_checkout: {:?}, item: {:?} }}",
            self.last_checkout, self.item
        )
    }
}

#[derive(Debug)]
pub struct Config {
    rw_timeout: Option<Duration>,
    idle_timeout: Duration,
    verify_hostname: bool,
    sasl_config: SaslConfig,
    security_config: TlsConfig,
}

impl Config {
    fn new_conn(&self, id: u32, host: &str) -> Result<KafkaConnection> {
        KafkaConnection::new(
            id,
            host,
            self.rw_timeout,
            self.verify_hostname,
            self.security_config.clone(),
        )
        .map(|mut c| {
            log::debug!("Established: {:?}", c);

            let auth_req = SaslAuthenticateRequest::new(0, "test", self.sasl_config.clone());

            let mut buf = Vec::new();
            if auth_req.encode(&mut buf).is_ok() {
                println!("{buf:?}");
                c.send(&buf).ok();
            }

            let res = c.read_exact_alloc(1024).unwrap_or_default();
            println!("{res:?}");

            c
        })
    }
}

#[derive(Debug)]
struct State {
    num_conns: u32,
}

impl State {
    fn new() -> State {
        State { num_conns: 0 }
    }

    fn next_conn_id(&mut self) -> u32 {
        let c = self.num_conns;
        self.num_conns = self.num_conns.wrapping_add(1);
        c
    }
}

#[derive(Debug)]
pub struct Connections {
    conns: HashMap<String, Pooled<KafkaConnection>>,
    state: State,
    config: Config,
}

impl Connections {
    pub fn new(
        rw_timeout: Option<Duration>,
        idle_timeout: Duration,
        verify_hostname: bool,
        sasl_config: SaslConfig,
        security_config: TlsConfig,
    ) -> Connections {
        Connections {
            conns: HashMap::new(),
            state: State::new(),
            config: Config {
                rw_timeout,
                idle_timeout,
                verify_hostname,
                sasl_config,
                security_config,
            },
        }
    }

    pub fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.config.idle_timeout = idle_timeout;
    }

    pub fn idle_timeout(&self) -> Duration {
        self.config.idle_timeout
    }

    pub fn get_conn(&mut self, host: &str, now: Instant) -> Result<&mut KafkaConnection> {
        if let Some(conn) = self.conns.get_mut(host) {
            if now.duration_since(conn.last_checkout) >= self.config.idle_timeout {
                log::debug!("Idle timeout reached: {:?}", conn.item);
                let new_conn = self.config.new_conn(self.state.next_conn_id(), host)?;
                let _ = conn.item.shutdown();
                conn.item = new_conn;
            }
            conn.last_checkout = now;
            let kconn: &mut KafkaConnection = &mut conn.item;
            // ~ decouple the lifetimes to make the borrowck happy;
            // this is safe since we're immediately returning the
            // reference and the rest of the code in this method is
            // not affected
            return Ok(unsafe { mem::transmute(kconn) });
        }
        let cid = self.state.next_conn_id();
        self.conns.insert(
            host.to_owned(),
            Pooled::new(now, self.config.new_conn(cid, host)?),
        );
        Ok(&mut self.conns.get_mut(host).unwrap().item)
    }

    pub fn get_conn_any(&mut self, now: Instant) -> Option<&mut KafkaConnection> {
        for (host, conn) in &mut self.conns {
            if now.duration_since(conn.last_checkout) >= self.config.idle_timeout {
                log::debug!("Idle timeout reached: {:?}", conn.item);
                let new_conn_id = self.state.next_conn_id();
                let new_conn = match self.config.new_conn(new_conn_id, host.as_str()) {
                    Ok(new_conn) => {
                        let _ = conn.item.shutdown();
                        new_conn
                    }
                    Err(e) => {
                        log::warn!("Failed to establish connection to {}: {:?}", host, e);
                        continue;
                    }
                };
                conn.item = new_conn;
            }
            conn.last_checkout = now;
            let kconn: &mut KafkaConnection = &mut conn.item;
            return Some(kconn);
        }
        None
    }
}

// --------------------------------------------------------------------

/// A TCP stream to a remote Kafka broker.
pub struct KafkaConnection {
    // a surrogate identifier to distinguish between
    // connections to the same host in debug messages
    id: u32,
    // "host:port"
    host: String,
    // the (wrapped) tcp stream
    stream: KafkaStream,
}

impl fmt::Debug for KafkaConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KafkaConnection {{ id: {}, secured: {}, host: \"{}\" }}",
            self.id,
            self.stream.is_secured(),
            self.host
        )
    }
}

impl KafkaConnection {
    pub fn send(&mut self, msg: &[u8]) -> Result<usize> {
        let r = self.stream.write(msg).map_err(From::from);
        log::trace!("Sent {} bytes to: {:?} => {:?}", msg.len(), self, r);
        r
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let r = (self.stream).read_exact(buf).map_err(From::from);
        log::trace!("Read {} bytes from: {:?} => {:?}", buf.len(), self, r);
        r
    }

    pub fn read_exact_alloc(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0; size];
        self.read_exact(buffer.as_mut_slice())?;
        Ok(buffer)
    }

    fn shutdown(&mut self) -> Result<()> {
        let r = self.stream.shutdown(Shutdown::Both);
        log::debug!("Shut down: {:?} => {:?}", self, r);
        r.map_err(From::from)
    }

    fn from_stream(
        stream: KafkaStream,
        id: u32,
        host: &str,
        rw_timeout: Option<Duration>,
    ) -> Result<KafkaConnection> {
        stream.set_read_timeout(rw_timeout)?;
        stream.set_write_timeout(rw_timeout)?;
        Ok(KafkaConnection {
            id,
            host: host.to_owned(),
            stream,
        })
    }

    fn new(
        id: u32,
        host: &str,
        rw_timeout: Option<Duration>,
        verify_hostname: bool,
        security_config: TlsConfig,
    ) -> Result<KafkaConnection> {
        let stream = KafkaStream::new(host, verify_hostname, security_config)?;
        KafkaConnection::from_stream(stream, id, host, rw_timeout)
    }
}
