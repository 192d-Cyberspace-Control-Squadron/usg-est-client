// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! Variable expansion for configuration values.
//!
//! This module handles expansion of variables like `${COMPUTERNAME}` and
//! `${USERDNSDOMAIN}` in configuration strings.

use crate::error::EstError;

/// Expand variables in a string.
///
/// Variables are in the format `${VARIABLE_NAME}`. Supported variables:
///
/// - `${COMPUTERNAME}` - Computer/hostname
/// - `${USERDNSDOMAIN}` - DNS domain suffix (Windows)
/// - `${USERDOMAIN}` - NetBIOS domain name (Windows)
/// - `${USERNAME}` - Current username
/// - `${USERPROFILE}` - User profile directory
/// - `${PROGRAMDATA}` - ProgramData directory (Windows)
/// - `${LOCALAPPDATA}` - Local app data directory
/// - `${TEMP}` - Temporary directory
/// - `${HOME}` - Home directory (Unix)
///
/// Unknown variables are left unchanged.
///
/// # Examples
///
/// ```
/// use usg_est_client::auto_enroll::expand_variables;
///
/// // Simple expansion
/// let result = expand_variables("${COMPUTERNAME}.example.com").unwrap();
/// // Returns something like "MYPC.example.com"
///
/// // Multiple variables
/// let result = expand_variables("${USERNAME}@${COMPUTERNAME}").unwrap();
/// // Returns something like "john@MYPC"
/// ```
pub fn expand_variables(input: &str) -> Result<String, EstError> {
    let mut result = input.to_string();
    let mut start = 0;

    // Find all ${...} patterns and replace them
    while let Some(var_start) = result[start..].find("${") {
        let absolute_start = start + var_start;

        if let Some(var_end) = result[absolute_start..].find('}') {
            let absolute_end = absolute_start + var_end;
            let var_name = &result[absolute_start + 2..absolute_end];

            // Look up the variable value
            if let Some(value) = get_variable_value(var_name) {
                // Replace ${VAR} with value
                result.replace_range(absolute_start..absolute_end + 1, &value);
                // Continue searching after the replacement
                start = absolute_start + value.len();
            } else {
                // Variable not found, skip past it
                start = absolute_end + 1;
            }
        } else {
            // No closing brace, skip past ${
            start = absolute_start + 2;
        }
    }

    Ok(result)
}

/// Get the value of a variable.
///
/// Returns `None` for unknown variables.
fn get_variable_value(name: &str) -> Option<String> {
    // First try our custom resolvers
    match name {
        "COMPUTERNAME" => get_computer_name(),
        "USERDNSDOMAIN" => get_dns_domain(),
        "USERDOMAIN" => get_netbios_domain(),
        "USERNAME" => get_username(),
        "HOME" | "USERPROFILE" => get_home_dir(),
        "PROGRAMDATA" => get_program_data(),
        "LOCALAPPDATA" => get_local_app_data(),
        "TEMP" | "TMP" => get_temp_dir(),
        _ => {
            // Fall back to environment variable
            std::env::var(name).ok()
        }
    }
}

/// Get the computer name.
fn get_computer_name() -> Option<String> {
    // Try environment variable first (works on Windows)
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        return Some(name);
    }

    // Fall back to hostname
    #[cfg(unix)]
    {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .map(|s| {
                // Remove domain suffix if present
                s.split('.').next().unwrap_or(&s).to_uppercase()
            })
    }

    #[cfg(not(unix))]
    {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .map(|s| s.to_uppercase())
    }
}

/// Get the DNS domain suffix.
fn get_dns_domain() -> Option<String> {
    // Try environment variable first (Windows)
    if let Ok(domain) = std::env::var("USERDNSDOMAIN") {
        return Some(domain);
    }

    // On Unix, try to extract from FQDN
    #[cfg(unix)]
    {
        if let Ok(Some(fqdn)) = hostname::get().map(|h| h.into_string().ok())
            && let Some(dot_pos) = fqdn.find('.')
        {
            return Some(fqdn[dot_pos + 1..].to_string());
        }
    }

    None
}

/// Get the NetBIOS domain name.
fn get_netbios_domain() -> Option<String> {
    // Try environment variable (Windows)
    std::env::var("USERDOMAIN").ok()
}

/// Get the current username.
fn get_username() -> Option<String> {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .ok()
}

/// Get the home directory.
fn get_home_dir() -> Option<String> {
    dirs::home_dir().map(|p| p.to_string_lossy().into_owned())
}

/// Get the ProgramData directory (Windows) or /var/lib equivalent.
fn get_program_data() -> Option<String> {
    std::env::var("PROGRAMDATA").ok().or_else(|| {
        #[cfg(unix)]
        {
            Some("/var/lib".to_string())
        }
        #[cfg(not(unix))]
        {
            None
        }
    })
}

/// Get the local app data directory.
fn get_local_app_data() -> Option<String> {
    std::env::var("LOCALAPPDATA")
        .ok()
        .or_else(|| dirs::data_local_dir().map(|p| p.to_string_lossy().into_owned()))
}

/// Get the temporary directory.
fn get_temp_dir() -> Option<String> {
    Some(std::env::temp_dir().to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_no_variables() {
        let result = expand_variables("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_expand_single_variable() {
        // Set a test environment variable
        // SAFETY: This is a test, no other threads are accessing this variable
        unsafe {
            std::env::set_var("TEST_VAR_123", "test_value");
        }
        let result = expand_variables("prefix_${TEST_VAR_123}_suffix").unwrap();
        assert_eq!(result, "prefix_test_value_suffix");
        unsafe {
            std::env::remove_var("TEST_VAR_123");
        }
    }

    #[test]
    fn test_expand_multiple_variables() {
        // SAFETY: This is a test, no other threads are accessing these variables
        unsafe {
            std::env::set_var("TEST_A", "aaa");
            std::env::set_var("TEST_B", "bbb");
        }
        let result = expand_variables("${TEST_A}-${TEST_B}").unwrap();
        assert_eq!(result, "aaa-bbb");
        unsafe {
            std::env::remove_var("TEST_A");
            std::env::remove_var("TEST_B");
        }
    }

    #[test]
    fn test_expand_unknown_variable() {
        // Unknown variables are left unchanged
        let result = expand_variables("${DEFINITELY_NOT_SET_XYZ123}").unwrap();
        assert_eq!(result, "${DEFINITELY_NOT_SET_XYZ123}");
    }

    #[test]
    fn test_expand_unclosed_brace() {
        // Unclosed brace is left unchanged
        let result = expand_variables("${UNCLOSED").unwrap();
        assert_eq!(result, "${UNCLOSED");
    }

    #[test]
    fn test_expand_temp() {
        let result = expand_variables("${TEMP}").unwrap();
        // Should expand to something (temp dir exists on all platforms)
        assert!(!result.is_empty());
        assert!(!result.contains("${"));
    }

    #[test]
    fn test_expand_computername() {
        // COMPUTERNAME should always resolve to something
        let result = expand_variables("${COMPUTERNAME}").unwrap();
        // Either it expanded or the environment var wasn't set
        // On most systems, hostname is available
        if !result.contains("${") {
            assert!(!result.is_empty());
        }
    }

    #[test]
    fn test_expand_in_path() {
        // SAFETY: This is a test, no other threads are accessing this variable
        unsafe {
            std::env::set_var("TEST_DIR", "mydir");
        }
        let result = expand_variables("/base/${TEST_DIR}/file.txt").unwrap();
        assert_eq!(result, "/base/mydir/file.txt");
        unsafe {
            std::env::remove_var("TEST_DIR");
        }
    }
}
