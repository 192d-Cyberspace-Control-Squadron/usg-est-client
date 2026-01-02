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

//! CSR Attributes operation (GET /csrattrs).
//!
//! This module provides utilities for the CSR attributes operation
//! defined in RFC 7030 Section 4.5.

use const_oid::ObjectIdentifier;

use crate::types::CsrAttributes;

/// Check if the server requires a specific attribute.
pub fn requires_attribute(attrs: &CsrAttributes, oid: &ObjectIdentifier) -> bool {
    attrs.contains_oid(oid)
}

/// Check if the server requires challenge password.
pub fn requires_challenge_password(attrs: &CsrAttributes) -> bool {
    use crate::types::csr_attrs::oids::CHALLENGE_PASSWORD;
    attrs.contains_oid(&CHALLENGE_PASSWORD)
}

/// Check if the server requires specific extensions.
pub fn requires_extensions(attrs: &CsrAttributes) -> bool {
    use crate::types::csr_attrs::oids::EXTENSION_REQUEST;
    attrs.contains_oid(&EXTENSION_REQUEST)
}

/// Get a human-readable description of required attributes.
pub fn describe_requirements(attrs: &CsrAttributes) -> Vec<String> {
    use crate::types::csr_attrs::oids;

    let mut descriptions = Vec::new();

    for attr in &attrs.attributes {
        let desc = match attr.oid {
            oid if oid == oids::CHALLENGE_PASSWORD => "Challenge Password".to_string(),
            oid if oid == oids::EXTENSION_REQUEST => "Extension Request".to_string(),
            oid if oid == oids::SUBJECT_ALT_NAME => "Subject Alternative Name".to_string(),
            oid if oid == oids::KEY_USAGE => "Key Usage".to_string(),
            oid if oid == oids::EXTENDED_KEY_USAGE => "Extended Key Usage".to_string(),
            oid if oid == oids::BASIC_CONSTRAINTS => "Basic Constraints".to_string(),
            _ => format!("OID: {}", attr.oid),
        };
        descriptions.push(desc);
    }

    descriptions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::csr_attrs::{CsrAttribute, oids};

    #[test]
    fn test_requires_challenge_password() {
        let mut attrs = CsrAttributes::new();
        assert!(!requires_challenge_password(&attrs));

        attrs
            .attributes
            .push(CsrAttribute::new(oids::CHALLENGE_PASSWORD));
        assert!(requires_challenge_password(&attrs));
    }

    #[test]
    fn test_describe_requirements() {
        let mut attrs = CsrAttributes::new();
        attrs
            .attributes
            .push(CsrAttribute::new(oids::CHALLENGE_PASSWORD));
        attrs.attributes.push(CsrAttribute::new(oids::KEY_USAGE));

        let descriptions = describe_requirements(&attrs);
        assert_eq!(descriptions.len(), 2);
        assert!(descriptions.contains(&"Challenge Password".to_string()));
        assert!(descriptions.contains(&"Key Usage".to_string()));
    }
}
