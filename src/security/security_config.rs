use sasl::common::Credentials;
use std::fmt::{Debug, Formatter};

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
