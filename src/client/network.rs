//! Network related functionality for `KafkaClient`.
//!
//! This module is crate private and not exposed to the public except
//! through re-exports of individual items from within
//! `kafka::client`.

use crate::error::Result;
use std::{
    collections::HashMap,
    fmt, io,
    io::{Read, Write},
    mem,
    net::{Shutdown, TcpStream},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

// --------------------------------------------------------------------

pub struct NoCertificateVerification {}

#[cfg(feature = "security-rustls")]
impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Security relevant configuration options for `KafkaClient`.
// This will be expanded in the future. See #51.
#[derive(Debug, Clone)]
pub enum SecurityConfig {
    None,
    #[cfg(feature = "security-openssl")]
    Openssl(openssl::ssl::SslConnector),
    #[cfg(feature = "security-rustls")]
    Rustls(rustls::ClientConfig),
}

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
    security_config: SecurityConfig,
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
        .map(|c| {
            debug!("Established: {:?}", c);
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
        security_config: SecurityConfig,
    ) -> Connections {
        Connections {
            conns: HashMap::new(),
            state: State::new(),
            config: Config {
                rw_timeout,
                idle_timeout,
                verify_hostname,
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
                debug!("Idle timeout reached: {:?}", conn.item);
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
                debug!("Idle timeout reached: {:?}", conn.item);
                let new_conn_id = self.state.next_conn_id();
                let new_conn = match self.config.new_conn(new_conn_id, host.as_str()) {
                    Ok(new_conn) => {
                        let _ = conn.item.shutdown();
                        new_conn
                    }
                    Err(e) => {
                        warn!("Failed to establish connection to {}: {:?}", host, e);
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

trait IsSecured {
    fn is_secured(&self) -> bool;
}

pub enum KafkaStream {
    Plain(TcpStream),
    #[cfg(feature = "security-openssl")]
    Openssl(openssl::ssl::SslStream<TcpStream>),
    #[cfg(feature = "security-rustls")]
    Rustls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
}

impl IsSecured for KafkaStream {
    fn is_secured(&self) -> bool {
        !matches!(self, KafkaStream::Plain(_))
    }
}

impl KafkaStream {
    fn get_ref(&self) -> &TcpStream {
        match *self {
            KafkaStream::Plain(ref s) => s,
            #[cfg(feature = "security-openssl")]
            KafkaStream::Openssl(ref s) => s.get_ref(),
            #[cfg(feature = "security-rustls")]
            KafkaStream::Rustls(ref s) => s.get_ref(),
        }
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.get_ref().set_read_timeout(dur)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.get_ref().set_write_timeout(dur)
    }

    pub fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        self.get_ref().shutdown(how)
    }
}

impl Read for KafkaStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            KafkaStream::Plain(ref mut s) => s.read(buf),
            #[cfg(feature = "security-openssl")]
            KafkaStream::Openssl(ref mut s) => s.read(buf),
            #[cfg(feature = "security-rustls")]
            KafkaStream::Rustls(ref mut s) => s.read(buf),
        }
    }
}

impl Write for KafkaStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            KafkaStream::Plain(ref mut s) => s.write(buf),
            #[cfg(feature = "security-openssl")]
            KafkaStream::Openssl(ref mut s) => s.write(buf),
            #[cfg(feature = "security-rustls")]
            KafkaStream::Rustls(ref mut s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            KafkaStream::Plain(ref mut s) => s.flush(),
            #[cfg(feature = "security-openssl")]
            KafkaStream::Openssl(ref mut s) => s.flush(),
            #[cfg(feature = "security-rustls")]
            KafkaStream::Rustls(ref mut s) => s.flush(),
        }
    }
}

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
        trace!("Sent {} bytes to: {:?} => {:?}", msg.len(), self, r);
        r
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        let r = (&mut self.stream).read_exact(buf).map_err(From::from);
        trace!("Read {} bytes from: {:?} => {:?}", buf.len(), self, r);
        r
    }

    pub fn read_exact_alloc(&mut self, size: u64) -> Result<Vec<u8>> {
        let mut buffer = vec![0; size as usize];
        self.read_exact(buffer.as_mut_slice())?;
        Ok(buffer)
    }

    fn shutdown(&mut self) -> Result<()> {
        let r = self.stream.shutdown(Shutdown::Both);
        debug!("Shut down: {:?} => {:?}", self, r);
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
        security_config: SecurityConfig,
    ) -> Result<KafkaConnection> {
        use crate::Error;

        let domain = match host.rfind(':') {
            None => host,
            Some(i) => &host[..i],
        };
        let stream = TcpStream::connect(host)?;
        let stream = match security_config {
            SecurityConfig::None => KafkaStream::Plain(stream),
            #[cfg(feature = "security-openssl")]
            SecurityConfig::Openssl(connector) => {
                if !verify_hostname {
                    connector
                        .configure()
                        .map_err(openssl::ssl::Error::from)?
                        .set_verify_hostname(false);
                }
                let connection = connector.connect(domain, stream).map_err(|err| match err {
                    openssl::ssl::HandshakeError::SetupFailure(err) => {
                        Error::from(openssl::ssl::Error::from(err))
                    }
                    openssl::ssl::HandshakeError::Failure(err) => Error::from(err.into_error()),
                    openssl::ssl::HandshakeError::WouldBlock(err) => Error::from(err.into_error()),
                })?;
                KafkaStream::Openssl(connection)
            }
            #[cfg(feature = "security-rustls")]
            SecurityConfig::Rustls(mut client_config) => {
                if !verify_hostname {
                    client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
                }
                let conn = rustls::ClientConnection::new(
                    client_config.into(),
                    domain.try_into().map_err(|err| Error::from(err))?,
                )
                .map_err(|err| Error::from(err))?;
                KafkaStream::Rustls(rustls::StreamOwned::new(conn, stream))
            }
        };
        KafkaConnection::from_stream(stream, id, host, rw_timeout)
    }
}
