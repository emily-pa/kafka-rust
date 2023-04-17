use crate::security::SaslConfig;
use crate::{security::TlsConfig, Error, Result};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
    time::{Duration, SystemTime},
};

struct NoCertificateVerification {}

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

pub enum KafkaStream {
    Plain(TcpStream),
    #[cfg(feature = "security-openssl")]
    Openssl(openssl::ssl::SslStream<TcpStream>),
    #[cfg(feature = "security-rustls")]
    Rustls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl KafkaStream {
    pub fn new(
        host: &str,
        verify_hostname: bool,
        sasl_config: SaslConfig,
        security_config: TlsConfig,
    ) -> Result<Self> {
        let stream = TcpStream::connect(host)?;
        let domain = match host.rfind(':') {
            None => host,
            Some(i) => &host[..i],
        };
        Ok(match security_config {
            TlsConfig::None => KafkaStream::Plain(stream),
            #[cfg(feature = "security-openssl")]
            TlsConfig::Openssl(connector) => {
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
            TlsConfig::Rustls(mut client_config) => {
                if !verify_hostname {
                    client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));
                }
                let conn = rustls::ClientConnection::new(
                    client_config.into(),
                    domain.try_into().map_err(Error::from)?,
                )
                .map_err(Error::from)?;
                KafkaStream::Rustls(Box::new(rustls::StreamOwned::new(conn, stream)))
            }
        })
    }

    pub fn is_secured(&self) -> bool {
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
