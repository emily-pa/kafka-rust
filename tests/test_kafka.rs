#[cfg(feature = "integration_tests")]
extern crate kafka;

#[cfg(feature = "integration_tests")]
extern crate rand;

#[cfg(feature = "integration_tests")]
#[macro_use]
extern crate log;

#[cfg(feature = "integration_tests")]
extern crate env_logger;

#[cfg(feature = "integration_tests")]
extern crate openssl;

#[cfg(feature = "integration_tests")]
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "integration_tests")]
mod integration {
    use kafka::client::{Compression, GroupOffsetStorage, KafkaClient, TlsConfig};
    use kafka::Error;
    use std::{collections::HashMap, sync::Arc};
    use x509_certificate::{
        CapturedX509Certificate, InMemorySigningKeyPair, KeyAlgorithm, Sign, X509CertificateBuilder,
    };

    mod client;
    mod consumer_producer;

    pub const LOCAL_KAFKA_BOOTSTRAP_HOST: &str = "localhost:9092";
    pub const TEST_TOPIC_NAME: &str = "kafka-rust-test";
    pub const TEST_TOPIC_NAME_2: &str = "kafka-rust-test2";
    pub const TEST_GROUP_NAME: &str = "kafka-rust-tester";
    pub const TEST_TOPIC_PARTITIONS: [i32; 2] = [0, 1];
    pub const KAFKA_CONSUMER_OFFSETS_TOPIC_NAME: &str = "__consumer_offsets";
    const RSA_KEY_SIZE: u32 = 4096;

    // env vars
    const KAFKA_CLIENT_SECURE: &str = "KAFKA_CLIENT_SECURE";
    const KAFKA_CLIENT_COMPRESSION: &str = "KAFKA_CLIENT_COMPRESSION";

    lazy_static! {
        static ref COMPRESSIONS: HashMap<&'static str, Compression> = {
            let mut m = HashMap::new();

            m.insert("", Compression::NONE);
            m.insert("none", Compression::NONE);
            m.insert("NONE", Compression::NONE);

            m.insert("snappy", Compression::SNAPPY);
            m.insert("SNAPPY", Compression::SNAPPY);

            m.insert("gzip", Compression::GZIP);
            m.insert("GZIP", Compression::GZIP);

            m
        };
    }

    /// Constructs a Kafka client for the integration tests, and loads
    /// its metadata so it is ready to use.
    pub(crate) fn new_ready_kafka_client() -> KafkaClient {
        let mut client = new_kafka_client();
        client.load_metadata_all().ok();
        client
    }

    /// Constructs a Kafka client for the integration tests.
    pub(crate) fn new_kafka_client() -> KafkaClient {
        let hosts = vec![LOCAL_KAFKA_BOOTSTRAP_HOST.to_owned()];

        let mut client = KafkaClient::new(
            hosts,
            false,
            new_security_config()
                .map(|exists| exists.expect("Could not load security configuration"))
                .unwrap_or(TlsConfig::None),
        );

        client.set_group_offset_storage(GroupOffsetStorage::Kafka);

        let compression = std::env::var(KAFKA_CLIENT_COMPRESSION).unwrap_or(String::from(""));
        let compression = COMPRESSIONS.get(&*compression).unwrap();

        client.set_compression(*compression);
        log::debug!("Constructing client: {:?}", client);

        client
    }

    /// Returns a new security config if the `KAFKA_CLIENT_SECURE`
    /// environment variable is set to a non-empty string.
    pub(crate) fn new_security_config() -> Option<Result<TlsConfig, kafka::Error>> {
        #[cfg(all(not(feature = "security-openssl"), not(feature = "security-rustls")))]
        {
            return None;
        }

        match std::env::var_os(KAFKA_CLIENT_SECURE) {
            Some(ref val) => {
                if val == "OPENSSL" {
                    Some(new_key_pair_openssl().and_then(get_security_config_openssl))
                } else if val == "RUSTLS" {
                    Some(get_security_config_rustls(new_key_pair_rustls()))
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }

    #[cfg(feature = "security-rustls")]
    pub(crate) fn get_security_config_rustls(
        (certificate, keypair): (CapturedX509Certificate, InMemorySigningKeyPair),
    ) -> Result<TlsConfig, kafka::Error> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(rustls::client::WebPkiVerifier::new(
                root_store, None,
            )))
            .with_single_cert(
                vec![rustls::Certificate(certificate.encode_der().unwrap())],
                rustls::PrivateKey(keypair.private_key_data().unwrap()),
            )
            .unwrap();
        Ok(TlsConfig::Rustls(client_config))
    }

    #[cfg(feature = "security-rustls")]
    pub(crate) fn new_key_pair_rustls() -> (CapturedX509Certificate, InMemorySigningKeyPair) {
        let (cert, key, _) = X509CertificateBuilder::new(KeyAlgorithm::Rsa)
            .create_with_random_keypair()
            .unwrap();
        (cert, key)
    }

    /// If the `KAFKA_CLIENT_SECURE` environment variable is set to OPENSSL, return a
    /// `TlsConfig`.
    #[cfg(feature = "security-openssl")]
    pub(crate) fn get_security_config_openssl(
        keypair: openssl::x509::X509,
    ) -> Result<TlsConfig, kafka::Error> {
        let mut builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();

        #[cfg(openssl110)]
        builder.set_cipher_list("DEFAULT@SECLEVEL=0").unwrap();

        #[cfg(not(openssl110))]
        builder.set_cipher_list("DEFAULT").unwrap();

        builder.set_certificate(&*keypair).unwrap();
        builder.set_verify(openssl::ssl::SslVerifyMode::NONE);

        let connector = builder.build();
        let security_config = TlsConfig::Openssl(connector);
        Ok(security_config)
    }

    #[cfg(feature = "security-openssl")]
    pub(crate) fn new_key_pair_openssl() -> Result<openssl::x509::X509, Error> {
        let rsa =
            openssl::rsa::Rsa::generate(RSA_KEY_SIZE).map_err(|err| Error::Openssl(err.into()))?;
        let pkey = openssl::pkey::PKey::from_rsa(rsa).map_err(|err| Error::Openssl(err.into()))?;
        let mut builder =
            openssl::x509::X509::builder().map_err(|err| Error::Openssl(err.into()))?;
        builder
            .set_pubkey(&*pkey)
            .map_err(|err| Error::Openssl(err.into()))?;
        Ok(builder.build())
    }
}
