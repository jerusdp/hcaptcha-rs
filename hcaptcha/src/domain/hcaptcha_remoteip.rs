use crate::{Code, HcaptchaError};
use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
pub struct HcaptchaRemoteip(String);

impl fmt::Display for HcaptchaRemoteip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl HcaptchaRemoteip {
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Validate User IP.", skip(s), level = "debug")
    )]
    pub fn parse(s: String) -> Result<Self, HcaptchaError> {
        empty_ip_string(&s)?;
        invalid_ip_string(&s)?;

        Ok(HcaptchaRemoteip(s))
    }
}

#[cfg_attr(
    feature = "trace",
    tracing::instrument(name = "Return error on empty string.", skip(s), level = "debug")
)]
fn empty_ip_string(s: &str) -> Result<(), HcaptchaError> {
    if s.trim().is_empty() {
        let mut codes = HashSet::new();
        codes.insert(Code::MissingUserIp);

        #[cfg(feature = "trace")]
        tracing::debug!("UserIP string is missing");
        Err(HcaptchaError::Codes(codes))
    } else {
        Ok(())
    }
}

#[cfg_attr(
    feature = "trace",
    tracing::instrument(name = "Return error if not an ip string.", skip(s), level = "debug")
)]
fn invalid_ip_string(s: &str) -> Result<(), HcaptchaError> {
    let invalid_ip4 = Ipv4Addr::from_str(s).is_err();
    let invalid_ip6 = Ipv6Addr::from_str(s).is_err();
    if invalid_ip4 && invalid_ip6 {
        let mut codes = HashSet::new();
        codes.insert(Code::InvalidUserIp);

        #[cfg(feature = "trace")]
        tracing::debug!("UserIP string is invalid");
        Err(HcaptchaError::Codes(codes))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::HcaptchaRemoteip;
    use crate::Code;
    use crate::HcaptchaError;
    use claims::{assert_err, assert_ok};

    #[test]
    fn whitespace_only_ip_strings_are_rejected() {
        let ip_string = " ".to_string();
        assert_err!(HcaptchaRemoteip::parse(ip_string));
    }

    #[test]
    fn empty_string_is_rejected() {
        let ip_string = "".to_string();
        assert_err!(HcaptchaRemoteip::parse(ip_string));
    }

    #[test]
    fn error_set_contains_missing_ip_string_error() {
        let ip_string = "".to_string();
        if let Err(HcaptchaError::Codes(hs)) = HcaptchaRemoteip::parse(ip_string) {
            assert!(hs.contains(&Code::MissingUserIp));
        }
    }

    #[test]
    fn error_set_contains_invalid_ip_string_error() {
        let ip_string = "1922.20".to_string();
        let res = HcaptchaRemoteip::parse(ip_string);
        assert_err!(&res);

        if let Err(HcaptchaError::Codes(hs)) = res {
            println!("Error Codes: {:?}", &hs);
            assert!(hs.contains(&Code::InvalidUserIp));
        }
    }

    #[test]
    fn test_ip_string_key_is_valid_ip4() {
        let ip_string = mockd::internet::ipv4_address();
        assert_ok!(HcaptchaRemoteip::parse(ip_string));
    }

    #[test]
    fn test_ip_string_key_is_valid_ip6() {
        let ip_string = mockd::internet::ipv6_address();
        assert_ok!(HcaptchaRemoteip::parse(ip_string));
    }
}
