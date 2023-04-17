use crate::{codecs::ToByte, Result};
use sasl::{
    client::{mechanisms, Mechanism},
    common::{
        scram::{Sha1, Sha256},
        Credentials,
    },
};
use std::{
    fmt::{Debug, Formatter},
    io::Write,
};

#[derive(Clone)]
pub enum SaslConfig {
    None,
    Plain(Credentials),
    Anonymous(Credentials),
    ScramSha1(Credentials),
    ScramSha256(Credentials),
}

impl Debug for SaslConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SaslConfig::None => f.write_str("(SaslConfig: None)"),
            SaslConfig::Plain(_) => f.write_str("(SaslConfig: PLAIN)"),
            SaslConfig::Anonymous(_) => f.write_str("(SaslConfig: Anonymous)"),
            SaslConfig::ScramSha1(_) => f.write_str("(SaslConfig: SCRAM[SHA-1])"),
            SaslConfig::ScramSha256(_) => f.write_str("(SaslConfig: SCRAM[SHA-256])"),
        }
    }
}

impl ToByte for SaslConfig {
    fn encode<W: Write>(&self, buffer: &mut W) -> Result<()> {
        buffer
            .write(
                match self.clone() {
                    SaslConfig::None => "".as_bytes().to_vec(),
                    SaslConfig::Plain(creds) => {
                        mechanisms::Plain::from_credentials(creds)?.initial()
                    }
                    SaslConfig::Anonymous(creds) => {
                        mechanisms::Anonymous::from_credentials(creds)?.initial()
                    }
                    SaslConfig::ScramSha1(creds) => {
                        mechanisms::Scram::<Sha1>::from_credentials(creds)?.initial()
                    }
                    SaslConfig::ScramSha256(creds) => {
                        mechanisms::Scram::<Sha256>::from_credentials(creds)?.initial()
                    }
                }
                .as_slice(),
            )
            .ok();
        Ok(())
    }
}

/// Security relevant configuration options for `KafkaClient`.
// This will be expanded in the future. See #51.
#[derive(Debug, Clone)]
pub enum TlsConfig {
    None,
    #[cfg(feature = "security-openssl")]
    Openssl(openssl::ssl::SslConnector),
    #[cfg(feature = "security-rustls")]
    Rustls(rustls::ClientConfig),
}
