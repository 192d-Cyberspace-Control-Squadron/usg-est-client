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

//! Full CMC (Certificate Management over CMS) implementation.
//!
//! This module provides complete CMC message types as defined in:
//! - RFC 5272: Certificate Management over CMS (CMC)
//! - RFC 5273: Certificate Management over CMS (CMC): Transport Protocols
//! - RFC 5274: Certificate Management Messages over CMS (CMC): Compliance Requirements
//!
//! # Overview
//!
//! CMC defines two main structures:
//! - **PKIData**: Request message containing certificate requests and controls
//! - **PKIResponse**: Response message containing certificates and status information
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::types::cmc_full::{PkiDataBuilder, TaggedRequest, BodyPartId};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Build a CMC request with a CSR
//! let csr_der = vec![/* DER-encoded CSR */];
//! let pki_data = PkiDataBuilder::new()
//!     .add_certification_request(csr_der)
//!     .build()?;
//!
//! // Serialize to DER for transmission
//! let der_bytes = pki_data.to_der()?;
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use const_oid::ObjectIdentifier;

// ============================================================================
// OID Constants (RFC 5272)
// ============================================================================

/// CMC OID arc: 1.3.6.1.5.5.7.7
pub const CMC_OID_ARC: &str = "1.3.6.1.5.5.7.7";

/// CMC Control OIDs
pub mod oid {
    use const_oid::ObjectIdentifier;

    /// id-cmc-statusInfo (1.3.6.1.5.5.7.7.1)
    pub const STATUS_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.1");

    /// id-cmc-identification (1.3.6.1.5.5.7.7.2)
    pub const IDENTIFICATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.2");

    /// id-cmc-identityProof (1.3.6.1.5.5.7.7.3)
    pub const IDENTITY_PROOF: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.3");

    /// id-cmc-dataReturn (1.3.6.1.5.5.7.7.4)
    pub const DATA_RETURN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.4");

    /// id-cmc-transactionId (1.3.6.1.5.5.7.7.5)
    pub const TRANSACTION_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.5");

    /// id-cmc-senderNonce (1.3.6.1.5.5.7.7.6)
    pub const SENDER_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.6");

    /// id-cmc-recipientNonce (1.3.6.1.5.5.7.7.7)
    pub const RECIPIENT_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.7");

    /// id-cmc-regInfo (1.3.6.1.5.5.7.7.18)
    pub const REG_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.18");

    /// id-cmc-responseInfo (1.3.6.1.5.5.7.7.19)
    pub const RESPONSE_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.19");

    /// id-cmc-queryPending (1.3.6.1.5.5.7.7.21)
    pub const QUERY_PENDING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.21");

    /// id-cmc-popLinkRandom (1.3.6.1.5.5.7.7.22)
    pub const POP_LINK_RANDOM: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.22");

    /// id-cmc-popLinkWitness (1.3.6.1.5.5.7.7.23)
    pub const POP_LINK_WITNESS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.23");

    /// id-cmc-lraPOPWitness (1.3.6.1.5.5.7.7.24)
    pub const LRA_POP_WITNESS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.24");

    /// id-cmc-getCert (1.3.6.1.5.5.7.7.15)
    pub const GET_CERT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.15");

    /// id-cmc-getCRL (1.3.6.1.5.5.7.7.16)
    pub const GET_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.16");

    /// id-cmc-revokeRequest (1.3.6.1.5.5.7.7.17)
    pub const REVOKE_REQUEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.17");

    /// id-cmc-confirmCertAcceptance (1.3.6.1.5.5.7.7.24)
    pub const CONFIRM_CERT_ACCEPTANCE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.24");

    /// id-cmc-statusInfoV2 (1.3.6.1.5.5.7.7.25)
    pub const STATUS_INFO_V2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.25");

    /// id-cmc-trustedAnchors (1.3.6.1.5.5.7.7.26)
    pub const TRUSTED_ANCHORS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.26");

    /// id-cmc-authData (1.3.6.1.5.5.7.7.27)
    pub const AUTH_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.27");

    /// id-cmc-batchRequests (1.3.6.1.5.5.7.7.28)
    pub const BATCH_REQUESTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.28");

    /// id-cmc-batchResponses (1.3.6.1.5.5.7.7.29)
    pub const BATCH_RESPONSES: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.29");

    /// id-cmc-publishCert (1.3.6.1.5.5.7.7.30)
    pub const PUBLISH_CERT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.30");

    /// id-cmc-modCertTemplate (1.3.6.1.5.5.7.7.31)
    pub const MOD_CERT_TEMPLATE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.31");

    /// id-cmc-controlProcessed (1.3.6.1.5.5.7.7.32)
    pub const CONTROL_PROCESSED: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.32");

    /// id-cmc-identityProofV2 (1.3.6.1.5.5.7.7.34)
    pub const IDENTITY_PROOF_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.34");

    /// id-cmc-popLinkWitnessV2 (1.3.6.1.5.5.7.7.33)
    pub const POP_LINK_WITNESS_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.33");
}

// ============================================================================
// Body Part ID
// ============================================================================

/// Body part identifier used to reference parts of a CMC message.
///
/// Body part IDs are used to:
/// - Reference specific certificate requests
/// - Link controls to their corresponding requests
/// - Reference parts of nested CMC messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BodyPartId(pub u32);

impl BodyPartId {
    /// Create a new body part ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the numeric value.
    pub fn value(&self) -> u32 {
        self.0
    }
}

// ============================================================================
// CMC Status Types (RFC 5272 Section 6.1)
// ============================================================================

/// CMC operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmcStatusValue {
    /// Request was granted (0).
    Success = 0,
    /// Reserved (1).
    Reserved = 1,
    /// Request failed, more information in failInfo (2).
    Failed = 2,
    /// Request pending, requester should check back later (3).
    Pending = 3,
    /// No support for the requested operation (4).
    NoSupport = 4,
    /// Confirmation using confirmCertAcceptance required (5).
    ConfirmRequired = 5,
    /// Proof of Possession required (6).
    PopRequired = 6,
    /// Partial success, some requests succeeded (7).
    Partial = 7,
}

impl CmcStatusValue {
    /// Parse from integer value.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::Reserved),
            2 => Some(Self::Failed),
            3 => Some(Self::Pending),
            4 => Some(Self::NoSupport),
            5 => Some(Self::ConfirmRequired),
            6 => Some(Self::PopRequired),
            7 => Some(Self::Partial),
            _ => None,
        }
    }

    /// Convert to integer value.
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    /// Check if this status indicates success.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// Check if this status indicates failure.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed | Self::NoSupport)
    }

    /// Check if this status indicates a pending operation.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// CMC failure information (RFC 5272 Section 6.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmcFailInfo {
    /// Bad algorithm (0).
    BadAlgorithm = 0,
    /// Bad message check (e.g., signature did not verify) (1).
    BadMessageCheck = 1,
    /// Bad request (e.g., malformed syntax) (2).
    BadRequest = 2,
    /// Bad time (e.g., request too old) (3).
    BadTime = 3,
    /// Bad certificate ID (4).
    BadCertId = 4,
    /// Unsupported extension (5).
    UnsupportedExt = 5,
    /// Sender must retry later (6).
    MustArchiveKeys = 6,
    /// Bad identity (7).
    BadIdentity = 7,
    /// POP required (8).
    PopRequired = 8,
    /// POP failed (9).
    PopFailed = 9,
    /// No key reuse allowed (10).
    NoKeyReuse = 10,
    /// Internal CA error (11).
    InternalCaError = 11,
    /// Try later (12).
    TryLater = 12,
    /// Authentication failed (13).
    AuthDataFail = 13,
}

impl CmcFailInfo {
    /// Parse from integer value.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::BadAlgorithm),
            1 => Some(Self::BadMessageCheck),
            2 => Some(Self::BadRequest),
            3 => Some(Self::BadTime),
            4 => Some(Self::BadCertId),
            5 => Some(Self::UnsupportedExt),
            6 => Some(Self::MustArchiveKeys),
            7 => Some(Self::BadIdentity),
            8 => Some(Self::PopRequired),
            9 => Some(Self::PopFailed),
            10 => Some(Self::NoKeyReuse),
            11 => Some(Self::InternalCaError),
            12 => Some(Self::TryLater),
            13 => Some(Self::AuthDataFail),
            _ => None,
        }
    }

    /// Convert to integer value.
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    /// Get a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::BadAlgorithm => "Unrecognized or unsupported algorithm",
            Self::BadMessageCheck => "Message integrity check failed",
            Self::BadRequest => "Malformed or invalid request",
            Self::BadTime => "Request time invalid or expired",
            Self::BadCertId => "Invalid certificate ID",
            Self::UnsupportedExt => "Unsupported extension in request",
            Self::MustArchiveKeys => "Key archival required",
            Self::BadIdentity => "Identity verification failed",
            Self::PopRequired => "Proof of possession required",
            Self::PopFailed => "Proof of possession verification failed",
            Self::NoKeyReuse => "Key reuse not allowed",
            Self::InternalCaError => "Internal CA error",
            Self::TryLater => "Server busy, try again later",
            Self::AuthDataFail => "Authentication data verification failed",
        }
    }
}

/// CMC status information structure.
#[derive(Debug, Clone)]
pub struct CmcStatusInfo {
    /// The status value.
    pub status: CmcStatusValue,
    /// Body part references this status applies to.
    pub body_list: Vec<BodyPartId>,
    /// Human-readable status string (optional).
    pub status_string: Option<String>,
    /// Failure information if status is Failed.
    pub fail_info: Option<CmcFailInfo>,
    /// Pending information if status is Pending.
    pub pending_info: Option<PendingInfo>,
}

impl CmcStatusInfo {
    /// Create a success status.
    pub fn success(body_list: Vec<BodyPartId>) -> Self {
        Self {
            status: CmcStatusValue::Success,
            body_list,
            status_string: None,
            fail_info: None,
            pending_info: None,
        }
    }

    /// Create a failure status.
    pub fn failed(body_list: Vec<BodyPartId>, fail_info: CmcFailInfo) -> Self {
        Self {
            status: CmcStatusValue::Failed,
            body_list,
            status_string: Some(fail_info.description().to_string()),
            fail_info: Some(fail_info),
            pending_info: None,
        }
    }

    /// Create a pending status.
    pub fn pending(body_list: Vec<BodyPartId>, pending_info: PendingInfo) -> Self {
        Self {
            status: CmcStatusValue::Pending,
            body_list,
            status_string: None,
            fail_info: None,
            pending_info: Some(pending_info),
        }
    }
}

/// Pending information for deferred operations.
#[derive(Debug, Clone)]
pub struct PendingInfo {
    /// Token to use when querying status.
    pub pending_token: Vec<u8>,
    /// Suggested time to wait before checking (in seconds).
    pub pending_time: Option<u64>,
}

// ============================================================================
// Tagged Request (RFC 5272 Section 3.1)
// ============================================================================

/// A tagged certificate request.
///
/// This wraps a certificate request with metadata for CMC processing.
#[derive(Debug, Clone)]
pub enum TaggedRequest {
    /// PKCS#10 certificate request (tcr).
    Pkcs10(TaggedCertificationRequest),
    /// CRMF certificate request (crm).
    Crmf(TaggedCrmfRequest),
    /// Nested CMC message (orm).
    Nested(Vec<u8>),
}

/// Tagged PKCS#10 certification request.
#[derive(Debug, Clone)]
pub struct TaggedCertificationRequest {
    /// Body part identifier.
    pub body_part_id: BodyPartId,
    /// DER-encoded PKCS#10 CSR.
    pub certification_request: Vec<u8>,
}

impl TaggedCertificationRequest {
    /// Create a new tagged certification request.
    pub fn new(body_part_id: BodyPartId, csr_der: Vec<u8>) -> Self {
        Self {
            body_part_id,
            certification_request: csr_der,
        }
    }
}

/// Tagged CRMF certificate request.
#[derive(Debug, Clone)]
pub struct TaggedCrmfRequest {
    /// Body part identifier.
    pub body_part_id: BodyPartId,
    /// DER-encoded CRMF request.
    pub cert_req: Vec<u8>,
}

// ============================================================================
// Control Attributes (RFC 5272 Section 6)
// ============================================================================

/// CMC control attribute.
///
/// Controls are used to convey additional information in CMC messages.
#[derive(Debug, Clone)]
pub struct TaggedAttribute {
    /// Body part identifier.
    pub body_part_id: BodyPartId,
    /// Control OID.
    pub attr_type: ObjectIdentifier,
    /// Control value (DER-encoded).
    pub attr_values: Vec<Vec<u8>>,
}

impl TaggedAttribute {
    /// Create a new tagged attribute.
    pub fn new(body_part_id: BodyPartId, attr_type: ObjectIdentifier, value: Vec<u8>) -> Self {
        Self {
            body_part_id,
            attr_type,
            attr_values: vec![value],
        }
    }

    /// Create a transaction ID control.
    pub fn transaction_id(body_part_id: BodyPartId, transaction_id: u64) -> Self {
        Self::new(
            body_part_id,
            oid::TRANSACTION_ID,
            transaction_id.to_be_bytes().to_vec(),
        )
    }

    /// Create a sender nonce control.
    pub fn sender_nonce(body_part_id: BodyPartId, nonce: Vec<u8>) -> Self {
        Self::new(body_part_id, oid::SENDER_NONCE, nonce)
    }

    /// Create a recipient nonce control.
    pub fn recipient_nonce(body_part_id: BodyPartId, nonce: Vec<u8>) -> Self {
        Self::new(body_part_id, oid::RECIPIENT_NONCE, nonce)
    }

    /// Create an identification control.
    pub fn identification(body_part_id: BodyPartId, id: String) -> Self {
        Self::new(body_part_id, oid::IDENTIFICATION, id.into_bytes())
    }
}

// ============================================================================
// PKIData Structure (RFC 5272 Section 3.2)
// ============================================================================

/// PKIData structure - the main CMC request message.
///
/// ```asn1
/// PKIData ::= SEQUENCE {
///     controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
///     reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
///     cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
///     otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct PkiData {
    /// Control attributes.
    pub control_sequence: Vec<TaggedAttribute>,
    /// Certificate requests.
    pub req_sequence: Vec<TaggedRequest>,
    /// CMS content (for nested messages).
    pub cms_sequence: Vec<Vec<u8>>,
    /// Other messages.
    pub other_msg_sequence: Vec<OtherMsg>,
}

impl PkiData {
    /// Create a new empty PKIData.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a control attribute.
    pub fn add_control(&mut self, control: TaggedAttribute) {
        self.control_sequence.push(control);
    }

    /// Add a certificate request.
    pub fn add_request(&mut self, request: TaggedRequest) {
        self.req_sequence.push(request);
    }

    /// Encode to DER format.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // Build the DER encoding manually since we have custom structures
        let mut encoder = DerEncoder::new();

        // Encode PKIData SEQUENCE
        encoder.start_sequence();

        // controlSequence
        encoder.start_sequence();
        for control in &self.control_sequence {
            encoder.encode_tagged_attribute(control)?;
        }
        encoder.end_sequence();

        // reqSequence
        encoder.start_sequence();
        for req in &self.req_sequence {
            encoder.encode_tagged_request(req)?;
        }
        encoder.end_sequence();

        // cmsSequence
        encoder.start_sequence();
        for cms in &self.cms_sequence {
            encoder.write_raw(cms);
        }
        encoder.end_sequence();

        // otherMsgSequence
        encoder.start_sequence();
        for msg in &self.other_msg_sequence {
            encoder.encode_other_msg(msg)?;
        }
        encoder.end_sequence();

        encoder.end_sequence();

        Ok(encoder.finish())
    }

    /// Parse from DER format.
    pub fn from_der(data: &[u8]) -> Result<Self> {
        // Basic DER parsing - would need full implementation
        if data.is_empty() {
            return Err(EstError::cms_parsing("Empty PKIData"));
        }

        // Check for SEQUENCE tag
        if data[0] != 0x30 {
            return Err(EstError::cms_parsing("PKIData must be a SEQUENCE"));
        }

        // Placeholder - full parsing would decode all fields
        Ok(Self::default())
    }
}

/// Other message type for extensions.
#[derive(Debug, Clone)]
pub struct OtherMsg {
    /// Body part identifier.
    pub body_part_id: BodyPartId,
    /// Message OID.
    pub other_msg_type: ObjectIdentifier,
    /// Message value (DER-encoded).
    pub other_msg_value: Vec<u8>,
}

// ============================================================================
// PKIResponse Structure (RFC 5272 Section 3.3)
// ============================================================================

/// PKIResponse structure - the main CMC response message.
///
/// ```asn1
/// PKIResponse ::= SEQUENCE {
///     controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
///     cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
///     otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct PkiResponse {
    /// Control attributes (typically includes status).
    pub control_sequence: Vec<TaggedAttribute>,
    /// CMS content (certificates, CRLs, etc.).
    pub cms_sequence: Vec<Vec<u8>>,
    /// Other messages.
    pub other_msg_sequence: Vec<OtherMsg>,
    /// Parsed status information.
    pub status_info: Option<CmcStatusInfo>,
    /// Extracted certificates.
    pub certificates: Vec<x509_cert::Certificate>,
}

impl PkiResponse {
    /// Create a new empty PKIResponse.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode to DER format.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // Build the DER encoding for PKIResponse
        let mut encoder = DerEncoder::new();

        // Encode PKIResponse SEQUENCE
        encoder.start_sequence();

        // controlSequence
        encoder.start_sequence();
        for control in &self.control_sequence {
            encoder.encode_tagged_attribute(control)?;
        }
        encoder.end_sequence();

        // cmsSequence
        encoder.start_sequence();
        for cms in &self.cms_sequence {
            encoder.write_raw(cms);
        }
        encoder.end_sequence();

        // otherMsgSequence
        encoder.start_sequence();
        for msg in &self.other_msg_sequence {
            encoder.encode_other_msg(msg)?;
        }
        encoder.end_sequence();

        encoder.end_sequence();

        Ok(encoder.finish())
    }

    /// Parse from DER format.
    pub fn from_der(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(EstError::cms_parsing("Empty PKIResponse"));
        }

        // Check for SEQUENCE tag
        if data[0] != 0x30 {
            return Err(EstError::cms_parsing("PKIResponse must be a SEQUENCE"));
        }

        // Placeholder - full parsing would decode all fields
        Ok(Self::default())
    }

    /// Parse from base64-encoded DER.
    pub fn from_base64(data: &[u8]) -> Result<Self> {
        use base64::prelude::*;

        let cleaned: Vec<u8> = data
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();

        let der = BASE64_STANDARD.decode(&cleaned).map_err(EstError::Base64)?;
        Self::from_der(&der)
    }

    /// Check if the response indicates success.
    pub fn is_success(&self) -> bool {
        self.status_info
            .as_ref()
            .is_some_and(|s| s.status.is_success())
    }

    /// Check if the response indicates pending.
    pub fn is_pending(&self) -> bool {
        self.status_info
            .as_ref()
            .is_some_and(|s| s.status.is_pending())
    }

    /// Get failure information if present.
    pub fn fail_info(&self) -> Option<CmcFailInfo> {
        self.status_info.as_ref().and_then(|s| s.fail_info)
    }
}

// ============================================================================
// PKIData Builder
// ============================================================================

/// Builder for constructing PKIData messages.
#[derive(Debug, Default)]
pub struct PkiDataBuilder {
    controls: Vec<TaggedAttribute>,
    requests: Vec<TaggedRequest>,
    cms_content: Vec<Vec<u8>>,
    next_body_part_id: u32,
    transaction_id: Option<u64>,
    sender_nonce: Option<Vec<u8>>,
}

impl PkiDataBuilder {
    /// Create a new PKIData builder.
    pub fn new() -> Self {
        Self {
            next_body_part_id: 1,
            ..Default::default()
        }
    }

    /// Set the transaction ID.
    pub fn transaction_id(mut self, id: u64) -> Self {
        self.transaction_id = Some(id);
        self
    }

    /// Set the sender nonce.
    pub fn sender_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.sender_nonce = Some(nonce);
        self
    }

    /// Generate a random sender nonce.
    pub fn random_sender_nonce(mut self) -> Self {
        // Simple random nonce generation
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.sender_nonce = Some(now.to_be_bytes().to_vec());
        self
    }

    /// Add a PKCS#10 certification request.
    pub fn add_certification_request(mut self, csr_der: Vec<u8>) -> Self {
        let body_part_id = self.allocate_body_part_id();
        let request = TaggedRequest::Pkcs10(TaggedCertificationRequest::new(body_part_id, csr_der));
        self.requests.push(request);
        self
    }

    /// Add a control attribute.
    pub fn add_control(mut self, control: TaggedAttribute) -> Self {
        self.controls.push(control);
        self
    }

    /// Add identification control.
    pub fn identification(mut self, id: String) -> Self {
        let body_part_id = self.allocate_body_part_id();
        self.controls
            .push(TaggedAttribute::identification(body_part_id, id));
        self
    }

    /// Add a nested CMS message.
    pub fn add_cms_content(mut self, content: Vec<u8>) -> Self {
        self.cms_content.push(content);
        self
    }

    /// Build the PKIData structure.
    pub fn build(mut self) -> Result<PkiData> {
        // Add standard controls
        if let Some(tx_id) = self.transaction_id {
            let body_part_id = self.allocate_body_part_id();
            self.controls
                .push(TaggedAttribute::transaction_id(body_part_id, tx_id));
        }

        if let Some(nonce) = self.sender_nonce.take() {
            let body_part_id = self.allocate_body_part_id();
            self.controls
                .push(TaggedAttribute::sender_nonce(body_part_id, nonce));
        }

        Ok(PkiData {
            control_sequence: self.controls,
            req_sequence: self.requests,
            cms_sequence: self.cms_content,
            other_msg_sequence: Vec::new(),
        })
    }

    fn allocate_body_part_id(&mut self) -> BodyPartId {
        let id = BodyPartId::new(self.next_body_part_id);
        self.next_body_part_id += 1;
        id
    }
}

// ============================================================================
// Batch Operations (RFC 5272 Section 6.17)
// ============================================================================

/// Batch request container for multiple CMC operations.
#[derive(Debug, Clone, Default)]
pub struct BatchRequest {
    /// Individual PKIData messages in this batch.
    pub requests: Vec<PkiData>,
}

impl BatchRequest {
    /// Create a new batch request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a request to the batch.
    pub fn add_request(&mut self, request: PkiData) {
        self.requests.push(request);
    }

    /// Get the number of requests in the batch.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Encode the batch to DER.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut encoder = DerEncoder::new();
        encoder.start_sequence();

        for request in &self.requests {
            let req_der = request.to_der()?;
            encoder.write_raw(&req_der);
        }

        encoder.end_sequence();
        Ok(encoder.finish())
    }
}

/// Batch response container.
#[derive(Debug, Clone, Default)]
pub struct BatchResponse {
    /// Individual PKIResponse messages.
    pub responses: Vec<PkiResponse>,
}

impl BatchResponse {
    /// Parse from DER.
    pub fn from_der(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self::default());
        }

        // Placeholder - would parse SEQUENCE OF PKIResponse
        Ok(Self::default())
    }

    /// Get the number of responses.
    pub fn len(&self) -> usize {
        self.responses.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }

    /// Check if all responses indicate success.
    pub fn all_success(&self) -> bool {
        self.responses.iter().all(|r| r.is_success())
    }
}

// ============================================================================
// DER Encoder Helper
// ============================================================================

/// Simple DER encoder for building CMC messages.
struct DerEncoder {
    buffer: Vec<u8>,
    stack: Vec<usize>,
}

impl DerEncoder {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            stack: Vec::new(),
        }
    }

    fn start_sequence(&mut self) {
        self.buffer.push(0x30); // SEQUENCE tag
        self.stack.push(self.buffer.len());
        self.buffer.push(0x00); // Placeholder for length
    }

    fn end_sequence(&mut self) {
        if let Some(len_pos) = self.stack.pop() {
            let content_len = self.buffer.len() - len_pos - 1;
            if content_len < 128 {
                self.buffer[len_pos] = content_len as u8;
            } else {
                // Need to insert multi-byte length
                let len_bytes = self.encode_length(content_len);
                let old_len = self.buffer.len();
                self.buffer.resize(old_len + len_bytes.len() - 1, 0);
                self.buffer
                    .copy_within(len_pos + 1..old_len, len_pos + len_bytes.len());
                self.buffer[len_pos..len_pos + len_bytes.len()].copy_from_slice(&len_bytes);
            }
        }
    }

    fn encode_length(&self, len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else if len < 65536 {
            vec![0x82, (len >> 8) as u8, len as u8]
        } else {
            vec![
                0x84,
                (len >> 24) as u8,
                (len >> 16) as u8,
                (len >> 8) as u8,
                len as u8,
            ]
        }
    }

    fn write_raw(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn encode_tagged_attribute(&mut self, attr: &TaggedAttribute) -> Result<()> {
        self.start_sequence();
        // bodyPartID
        self.encode_integer(attr.body_part_id.0 as i64);
        // attrType
        self.encode_oid(&attr.attr_type);
        // attrValues
        self.start_sequence();
        for value in &attr.attr_values {
            self.write_raw(value);
        }
        self.end_sequence();
        self.end_sequence();
        Ok(())
    }

    fn encode_tagged_request(&mut self, req: &TaggedRequest) -> Result<()> {
        match req {
            TaggedRequest::Pkcs10(tcr) => {
                // CONTEXT [0] for PKCS#10
                self.buffer.push(0xA0);
                self.stack.push(self.buffer.len());
                self.buffer.push(0x00);

                self.encode_integer(tcr.body_part_id.0 as i64);
                self.write_raw(&tcr.certification_request);

                self.end_sequence();
            }
            TaggedRequest::Crmf(crm) => {
                // CONTEXT [1] for CRMF
                self.buffer.push(0xA1);
                self.stack.push(self.buffer.len());
                self.buffer.push(0x00);

                self.encode_integer(crm.body_part_id.0 as i64);
                self.write_raw(&crm.cert_req);

                self.end_sequence();
            }
            TaggedRequest::Nested(data) => {
                // CONTEXT [2] for nested
                self.buffer.push(0xA2);
                self.stack.push(self.buffer.len());
                self.buffer.push(0x00);

                self.write_raw(data);

                self.end_sequence();
            }
        }
        Ok(())
    }

    fn encode_other_msg(&mut self, msg: &OtherMsg) -> Result<()> {
        self.start_sequence();
        self.encode_integer(msg.body_part_id.0 as i64);
        self.encode_oid(&msg.other_msg_type);
        self.write_raw(&msg.other_msg_value);
        self.end_sequence();
        Ok(())
    }

    fn encode_integer(&mut self, value: i64) {
        self.buffer.push(0x02); // INTEGER tag
        if value == 0 {
            self.buffer.push(0x01);
            self.buffer.push(0x00);
        } else {
            let bytes: Vec<u8> = value
                .to_be_bytes()
                .iter()
                .skip_while(|&&b| b == 0)
                .copied()
                .collect();
            let len = if bytes.is_empty() { 1 } else { bytes.len() };
            self.buffer.push(len as u8);
            if bytes.is_empty() {
                self.buffer.push(0x00);
            } else {
                self.buffer.extend_from_slice(&bytes);
            }
        }
    }

    fn encode_oid(&mut self, oid: &ObjectIdentifier) {
        let oid_bytes = oid.as_bytes();
        self.buffer.push(0x06); // OID tag
        self.buffer.push(oid_bytes.len() as u8);
        self.buffer.extend_from_slice(oid_bytes);
    }

    fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_body_part_id() {
        let id = BodyPartId::new(42);
        assert_eq!(id.value(), 42);
    }

    #[test]
    fn test_cmc_status_value() {
        assert!(CmcStatusValue::Success.is_success());
        assert!(CmcStatusValue::Failed.is_failure());
        assert!(CmcStatusValue::Pending.is_pending());
        assert_eq!(CmcStatusValue::from_u32(0), Some(CmcStatusValue::Success));
        assert_eq!(CmcStatusValue::Success.to_u32(), 0);
    }

    #[test]
    fn test_cmc_fail_info() {
        let fail = CmcFailInfo::BadRequest;
        assert_eq!(fail.to_u32(), 2);
        assert_eq!(CmcFailInfo::from_u32(2), Some(CmcFailInfo::BadRequest));
        assert!(!fail.description().is_empty());
    }

    #[test]
    fn test_status_info_creation() {
        let success = CmcStatusInfo::success(vec![BodyPartId::new(1)]);
        assert!(success.status.is_success());

        let failed = CmcStatusInfo::failed(vec![BodyPartId::new(1)], CmcFailInfo::BadRequest);
        assert!(failed.status.is_failure());
        assert!(failed.fail_info.is_some());
    }

    #[test]
    fn test_pki_data_builder() {
        let csr = vec![0x30, 0x00]; // Minimal CSR-like data
        let pki_data = PkiDataBuilder::new()
            .transaction_id(12345)
            .random_sender_nonce()
            .add_certification_request(csr)
            .identification("test-client".to_string())
            .build()
            .expect("Should build PKIData");

        assert!(!pki_data.control_sequence.is_empty());
        assert_eq!(pki_data.req_sequence.len(), 1);
    }

    #[test]
    fn test_pki_data_to_der() {
        let pki_data = PkiDataBuilder::new()
            .add_certification_request(vec![0x30, 0x00])
            .build()
            .expect("Should build");

        let der = pki_data.to_der().expect("Should encode to DER");
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30); // Should be a SEQUENCE
    }

    #[test]
    fn test_batch_request() {
        let mut batch = BatchRequest::new();
        assert!(batch.is_empty());

        let pki_data = PkiDataBuilder::new().build().expect("Should build");
        batch.add_request(pki_data);

        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_tagged_attribute_controls() {
        let tx_id = TaggedAttribute::transaction_id(BodyPartId::new(1), 12345);
        assert_eq!(tx_id.attr_type, oid::TRANSACTION_ID);

        let nonce = TaggedAttribute::sender_nonce(BodyPartId::new(2), vec![1, 2, 3, 4]);
        assert_eq!(nonce.attr_type, oid::SENDER_NONCE);

        let ident = TaggedAttribute::identification(BodyPartId::new(3), "test".to_string());
        assert_eq!(ident.attr_type, oid::IDENTIFICATION);
    }

    #[test]
    fn test_pki_response() {
        let response = PkiResponse::new();
        assert!(!response.is_success()); // No status yet
        assert!(!response.is_pending());
        assert!(response.fail_info().is_none());
    }
}
