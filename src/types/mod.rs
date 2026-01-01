// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! EST message types and parsing utilities.
//!
//! This module provides types for EST request and response messages,
//! including PKCS#7/CMS structures, CSR attributes, and CMC messages.

mod cmc;
pub mod csr_attrs;
mod pkcs7;

pub use cmc::{CmcRequest, CmcResponse, CmcStatus};
pub use csr_attrs::CsrAttributes;
pub use pkcs7::{parse_certs_only, CaCertificates};

use x509_cert::Certificate;

/// Response from a simple enrollment or re-enrollment request.
#[derive(Debug, Clone)]
pub enum EnrollmentResponse {
    /// Certificate was issued immediately.
    Issued {
        /// The issued certificate.
        certificate: Box<Certificate>,
    },

    /// Enrollment is pending manual approval.
    ///
    /// The client should wait and retry after the specified duration.
    Pending {
        /// Number of seconds to wait before retrying.
        retry_after: u64,
    },
}

impl EnrollmentResponse {
    /// Create a new issued response.
    pub fn issued(certificate: Certificate) -> Self {
        Self::Issued {
            certificate: Box::new(certificate),
        }
    }

    /// Create a new pending response.
    pub fn pending(retry_after: u64) -> Self {
        Self::Pending { retry_after }
    }

    /// Returns the certificate if the enrollment was successful.
    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            Self::Issued { certificate } => Some(certificate),
            Self::Pending { .. } => None,
        }
    }

    /// Returns true if the enrollment is pending.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// Returns the retry-after value if pending.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Pending { retry_after } => Some(*retry_after),
            Self::Issued { .. } => None,
        }
    }
}

/// Response from a server key generation request.
#[derive(Debug, Clone)]
pub struct ServerKeygenResponse {
    /// The issued certificate.
    pub certificate: Certificate,

    /// The server-generated private key (DER-encoded PKCS#8).
    ///
    /// This may be encrypted if the server chose to encrypt it.
    pub private_key: Vec<u8>,

    /// Whether the private key is encrypted.
    pub key_encrypted: bool,
}

impl ServerKeygenResponse {
    /// Create a new server keygen response.
    pub fn new(certificate: Certificate, private_key: Vec<u8>, key_encrypted: bool) -> Self {
        Self {
            certificate,
            private_key,
            key_encrypted,
        }
    }
}

/// Content types used in EST protocol.
pub mod content_types {
    /// PKCS#10 CSR content type.
    pub const PKCS10: &str = "application/pkcs10";

    /// PKCS#7/CMS content type.
    pub const PKCS7_MIME: &str = "application/pkcs7-mime";

    /// PKCS#7 certs-only content type with smime-type parameter.
    pub const PKCS7_CERTS_ONLY: &str = "application/pkcs7-mime; smime-type=certs-only";

    /// PKCS#8 private key content type.
    pub const PKCS8: &str = "application/pkcs8";

    /// CSR attributes content type.
    pub const CSR_ATTRS: &str = "application/csrattrs";

    /// CMC request content type.
    pub const CMC_REQUEST: &str = "application/pkcs7-mime; smime-type=CMC-request";

    /// CMC response content type.
    pub const CMC_RESPONSE: &str = "application/pkcs7-mime; smime-type=CMC-response";

    /// Multipart mixed content type (for server keygen).
    pub const MULTIPART_MIXED: &str = "multipart/mixed";
}

/// EST operation paths.
pub mod operations {
    /// CA certificates endpoint.
    pub const CACERTS: &str = "cacerts";

    /// Simple enrollment endpoint.
    pub const SIMPLE_ENROLL: &str = "simpleenroll";

    /// Simple re-enrollment endpoint.
    pub const SIMPLE_REENROLL: &str = "simplereenroll";

    /// CSR attributes endpoint.
    pub const CSR_ATTRS: &str = "csrattrs";

    /// Server-side key generation endpoint.
    pub const SERVER_KEYGEN: &str = "serverkeygen";

    /// Full CMC endpoint.
    pub const FULL_CMC: &str = "fullcmc";
}
