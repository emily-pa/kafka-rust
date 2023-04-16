#[macro_use]
extern crate log;

fn main() {
    example::main();
}

#[cfg(feature = "security-rustls")]
mod example {
    use kafka::client::{FetchOffset, KafkaClient, SecurityConfig};
    use rustls::{client::WebPkiVerifier, RootCertStore};
    use std::sync::Arc;
    use std::{env, fs, io::BufReader, process};

    fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
        let certificate = fs::File::open(filename).expect("cannot open certificate file");
        let mut reader = BufReader::new(certificate);
        rustls_pemfile::certs(&mut reader)
            .expect("cannot parse certificate file")
            .iter()
            .map(|v| rustls::Certificate(v.clone()))
            .collect()
    }

    fn load_private_key(filename: &str) -> rustls::PrivateKey {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);

        loop {
            match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file")
            {
                Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
                Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
                Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
                None => break,
                _ => {}
            }
        }

        panic!(
            "No keys found in {:?} (encrypted keys not supported)",
            filename
        )
    }

    pub fn main() {
        env_logger::init();

        // ~ parse the command line arguments
        let cfg = match Config::from_cmdline() {
            Ok(cfg) => cfg,
            Err(e) => {
                println!("{}", e);
                process::exit(1);
            }
        };

        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let config_builder = rustls::ClientConfig::builder().with_safe_defaults();
        let rustls_config = {
            if let Some(ca_cert) = cfg.ca_cert {
                info!("loading ca-file={}", ca_cert);
                let with_cert = config_builder.with_custom_certificate_verifier(Arc::new(
                    WebPkiVerifier::new(root_store, None),
                ));

                if let (Some(ccert), Some(ckey)) = (cfg.client_cert, cfg.client_key) {
                    info!("loading cert-file={}, key-file={}", ccert, ckey);
                    with_cert
                        .with_single_cert(load_certs(&ccert), load_private_key(&ckey))
                        .expect("Could not add cert")
                } else {
                    with_cert.with_no_client_auth()
                }
            } else {
                let without_cert = config_builder.with_root_certificates(root_store);

                if let (Some(ccert), Some(ckey)) = (cfg.client_cert, cfg.client_key) {
                    info!("loading cert-file={}, key-file={}", ccert, ckey);
                    without_cert
                        .with_single_cert(load_certs(&ccert), load_private_key(&ckey))
                        .expect("Could not add cert")
                } else {
                    without_cert.with_no_client_auth()
                }
            }
        };

        // ~ instantiate KafkaClient with the previous OpenSSL setup
        let mut client = KafkaClient::new(
            cfg.brokers,
            cfg.verify_hostname,
            SecurityConfig::Rustls(rustls_config),
        );

        // ~ communicate with the brokers
        match client.load_metadata_all() {
            Err(e) => {
                println!("{:?}", e);
                drop(client);
                process::exit(1);
            }
            Ok(_) => {
                // ~ at this point we have successfully loaded
                // metadata via a secured connection to one of the
                // specified brokers

                if client.topics().len() == 0 {
                    println!("No topics available!");
                } else {
                    // ~ now let's communicate with all the brokers in
                    // the cluster our topics are spread over

                    let topics: Vec<String> = client.topics().names().map(Into::into).collect();
                    match client.fetch_offsets(topics.as_slice(), FetchOffset::Latest) {
                        Err(e) => {
                            println!("{:?}", e);
                            drop(client);
                            process::exit(1);
                        }
                        Ok(toffsets) => {
                            println!("Topic offsets:");
                            for (topic, mut offs) in toffsets {
                                offs.sort_by_key(|x| x.partition);
                                println!("{}", topic);
                                for off in offs {
                                    println!("\t{}: {:?}", off.partition, off.offset);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    struct Config {
        brokers: Vec<String>,
        client_cert: Option<String>,
        client_key: Option<String>,
        ca_cert: Option<String>,
        verify_hostname: bool,
    }

    impl Config {
        fn from_cmdline() -> Result<Config, String> {
            let mut opts = getopts::Options::new();
            opts.optflag("h", "help", "Print this help screen");
            opts.optopt(
                "",
                "brokers",
                "Specify kafka brokers (comma separated)",
                "HOSTS",
            );
            opts.optopt("", "ca-cert", "Specify the trusted CA certificates", "FILE");
            opts.optopt("", "client-cert", "Specify the client certificate", "FILE");
            opts.optopt(
                "",
                "client-key",
                "Specify key for the client certificate",
                "FILE",
            );
            opts.optflag(
                "",
                "no-hostname-verification",
                "Do not perform server hostname verification (insecure!)",
            );

            let args: Vec<_> = env::args().collect();
            let m = match opts.parse(&args[1..]) {
                Ok(m) => m,
                Err(e) => return Err(format!("{}", e)),
            };

            if m.opt_present("help") {
                let brief = format!("{} [options]", args[0]);
                return Err(opts.usage(&brief));
            };

            let brokers = m
                .opt_str("brokers")
                .map(|s| {
                    s.split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_else(|| vec!["localhost:9092".into()]);
            if brokers.is_empty() {
                return Err("Invalid --brokers specified!".to_owned());
            }

            Ok(Config {
                brokers,
                client_cert: m.opt_str("client-cert"),
                client_key: m.opt_str("client-key"),
                ca_cert: m.opt_str("ca-cert"),
                verify_hostname: !m.opt_present("no-hostname-verification"),
            })
        }
    }
}

#[cfg(not(feature = "security-rustls"))]
mod example {
    use std::process;

    pub fn main() {
        println!("example relevant only with the \"security-rustls\" feature enabled!");
        process::exit(1);
    }
}
