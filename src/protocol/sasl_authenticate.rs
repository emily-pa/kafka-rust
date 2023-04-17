use crate::codecs::ToByte;
use crate::protocol::{HeaderRequest, API_KEY_SASL_HANDSHAKE, API_VERSION};
use crate::security::SaslConfig;
use crate::Result;
use std::io::Write;

pub struct SaslAuthenticateRequest<'a> {
    pub header: HeaderRequest<'a>,
    pub auth: SaslConfig,
}

impl<'a> SaslAuthenticateRequest<'a> {
    pub fn new(
        correlation_id: i32,
        client_id: &'a str,
        auth: SaslConfig,
    ) -> SaslAuthenticateRequest<'a> {
        SaslAuthenticateRequest {
            header: HeaderRequest::new(
                API_KEY_SASL_HANDSHAKE,
                API_VERSION,
                correlation_id,
                client_id,
            ),
            auth,
        }
    }
}

impl<'a> ToByte for SaslAuthenticateRequest<'a> {
    fn encode<W: Write>(&self, buffer: &mut W) -> Result<()> {
        try_multi!(self.header.encode(buffer), self.auth.encode(buffer))
    }
}
