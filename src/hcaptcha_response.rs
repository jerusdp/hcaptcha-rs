//! Structure to capture the response from the hcaptcha api
//!
//! # Example
//!
//! ```no_run
//! #   use hcaptcha::{HcaptchaRequest, HcaptchaClient};
//! # #[tokio::main]
//! # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
//! # let request = HcaptchaRequest::new(
//! #    "0x123456789abcedf0123456789abcdef012345678",
//! #    "response"
//! # )?;
//! # let client = HcaptchaClient::new();
//!     let response = client.verify_client_response(request).await?;
//!
//!     if let Some(timestamp) = response.timestamp() {
//!         println!("Timestamp: {}", timestamp);
//!     };
//!     if let Some(hostname) = response.hostname() {
//!         println!("Timestamp: {}", hostname);
//!     };
//!     if let Some(credit) = response.credit() {
//!         println!("Timestamp: {}", credit);
//!     };
//!     // Only available with an Enterprise subscription to Hcaptcha
//!     if let Some(score) = response.score() {
//!         println!("Score: {}", score);
//!     };
//!     if let Some(score_reason) = response.score_reason() {
//!         println!("Score reasons: {:?}", score_reason);
//!     };
//!
//! # Ok(())
//! # }
//! ```
use crate::Code;
use crate::HcaptchaError;
use serde_derive::Deserialize;
use std::collections::HashSet;
use std::fmt;

type Score = f32;

/// Result from call to verify the client's response
#[allow(missing_doc_code_examples)]
#[derive(Debug, Default, Deserialize, Clone)]
pub struct HcaptchaResponse {
    /// verification status: true or false.
    ///
    /// Successful verification may have additional information.
    /// Unsuccessful verification will return a set of error codes.
    success: bool,
    /// timestamp of the captcha (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
    challenge_ts: Option<String>, //yyyy-MM-dd'T'HH:mm:ssZZ
    /// the hostname of the site where the captcha was solved
    hostname: Option<String>,
    /// optional: whether the response will be credited
    credit: Option<bool>,
    /// optional: any error codes
    #[serde(rename = "error-codes")]
    error_codes: Option<HashSet<Code>>,
    /// `enterprise` feature: a score denoting malicious activity.
    #[cfg_attr(docsrs, doc(cfg(feature = "enterprise")))]
    score: Option<Score>,
    /// `enterprise` feature: reason(s) for score. See [BotStop.com] for details
    ///
    /// [BotStop.com]: https://BotStop.com
    #[cfg_attr(docsrs, doc(cfg(feature = "enterprise")))]
    score_reason: Option<HashSet<String>>,
}

#[allow(missing_doc_code_examples)]
impl fmt::Display for HcaptchaResponse {
    #[allow(missing_doc_code_examples)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
        Status:         {}
        Timestamp:      {}
        Hostname:       {}
        Credit:         {}
        Error Codes:    {}
        Score:          {}
        Score Reason:   {}
        "#,
            self.success,
            match self.timestamp() {
                Some(v) => v,
                None => "".to_owned(),
            },
            match self.hostname() {
                Some(v) => v,
                None => "".to_owned(),
            },
            match self.credit() {
                Some(v) => format!("{}", v),
                None => "".to_owned(),
            },
            match self.error_codes() {
                Some(v) => format!("{:?}", v),
                None => "".to_owned(),
            },
            match self.score() {
                Some(v) => format!("{}", v),
                None => "".to_owned(),
            },
            match self.score_reason() {
                Some(v) => format!("{:?}", v),
                None => "".to_owned(),
            },
        )
    }
}

#[allow(missing_doc_code_examples)]
impl HcaptchaResponse {
    /// Check succcess of API call and return HcaptchaError
    /// with the error codes if not successful.
    pub(crate) fn check_error(&self) -> Result<(), HcaptchaError> {
        if !self.success() {
            match &self.error_codes {
                Some(codes) => Err(HcaptchaError::Codes(codes.clone())),
                None => {
                    let mut codes = HashSet::new();
                    codes.insert(Code::Unknown("No error codes returned".to_owned()));
                    Err(HcaptchaError::Codes(codes))
                }
            }
        } else {
            Ok(())
        }
    }

    /// Get the value of the success field
    ///
    /// # Example
    /// ```no_run
    /// #   use hcaptcha::{HcaptchaRequest, HcaptchaClient};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let request = HcaptchaRequest::new(
    /// #    "0x123456789abcedf0123456789abcdef012345678",
    /// #    "response"
    /// # )?;
    /// # let client = HcaptchaClient::new();
    ///     let response = client.verify_client_response(request).await?;
    ///     println!("Success returns true: {}", response.success());
    /// # Ok(())
    /// # }

    #[allow(dead_code)]
    pub fn success(&self) -> bool {
        self.success
    }

    /// Get the value of the hostname field
    ///
    /// # Example
    /// ```no_run
    /// #   use hcaptcha::{HcaptchaRequest, HcaptchaClient};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let request = HcaptchaRequest::new(
    /// #    "0x123456789abcedf0123456789abcdef012345678",
    /// #    "response"
    /// # )?;
    /// # let client = HcaptchaClient::new();
    ///     let response = client.verify_client_response(request).await?;
    ///
    ///     if let Some(hostname) = response.hostname() {
    ///         println!("Timestamp: {}", hostname);
    ///     };
    /// # Ok(())
    /// # }

    #[allow(dead_code)]
    pub fn hostname(&self) -> Option<String> {
        self.hostname.clone()
    }

    /// Get the value of the timestamp field
    ///
    /// # Example
    /// ```no_run
    /// #   use hcaptcha::{HcaptchaRequest, HcaptchaClient};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let request = HcaptchaRequest::new(
    /// #    "0x123456789abcedf0123456789abcdef012345678",
    /// #    "response"
    /// # )?;
    /// # let client = HcaptchaClient::new();
    ///     let response = client.verify_client_response(request).await?;
    ///
    ///     if let Some(timestamp) = response.timestamp() {
    ///         println!("Timestamp: {}", timestamp);
    ///     };
    /// # Ok(())
    /// # }
    #[allow(dead_code)]
    pub fn timestamp(&self) -> Option<String> {
        self.challenge_ts.clone()
    }

    /// Get the value of the credit field
    ///
    /// # Example
    /// ```no_run
    /// #   use hcaptcha::{HcaptchaRequest, HcaptchaClient};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let request = HcaptchaRequest::new(
    /// #    "0x123456789abcedf0123456789abcdef012345678",
    /// #    "response"
    /// # )?;
    /// # let client = HcaptchaClient::new();
    ///     let response = client.verify_client_response(request).await?;
    ///
    ///     if let Some(credit) = response.credit() {
    ///         println!("Timestamp: {}", credit);
    ///     };
    ///
    /// # Ok(())
    /// # }

    #[allow(dead_code)]
    pub fn credit(&self) -> Option<bool> {
        self.credit
    }

    /// Get the value of the error_codes field
    #[allow(dead_code)]
    pub(crate) fn error_codes(&self) -> Option<HashSet<Code>> {
        self.error_codes.clone()
    }

    /// Get the value of the score field
    ///
    /// # Example
    /// ```no_run
    /// #   use hcaptcha::{HcaptchaRequest, HcaptchaClient};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let request = HcaptchaRequest::new(
    /// #    "0x123456789abcedf0123456789abcdef012345678",
    /// #    "response"
    /// # )?;
    /// # let client = HcaptchaClient::new();
    ///     let response = client.verify_client_response(request).await?;
    ///
    ///     if let Some(score) = response.score() {
    ///         println!("Score: {}", score);
    ///     };
    ///
    /// # Ok(())
    /// # }

    #[cfg(feature = "enterprise")]
    #[cfg_attr(docsrs, doc(cfg(feature = "enterprise")))]
    #[allow(dead_code)]
    pub fn score(&self) -> Option<Score> {
        self.score
    }

    /// Get the value of the score_reason field
    ///
    /// # Example
    /// ```no_run
    /// #   use hcaptcha::{HcaptchaRequest, HcaptchaClient};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let request = HcaptchaRequest::new(
    /// #    "0x123456789abcedf0123456789abcdef012345678",
    /// #    "response"
    /// # )?;
    /// # let client = HcaptchaClient::new();
    ///     let response = client.verify_client_response(request).await?;
    ///
    ///     if let Some(score_reason) = response.score_reason() {
    ///         println!("Score reasons: {:?}", score_reason);
    ///     };
    ///
    /// # Ok(())
    /// # }
    ///
    #[allow(dead_code)]
    #[cfg(feature = "enterprise")]
    #[cfg_attr(docsrs, doc(cfg(feature = "enterprise")))]
    pub fn score_reason(&self) -> Option<HashSet<String>> {
        self.score_reason.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::HcaptchaResponse;
    use serde_json::json;

    #[test]
    fn decoding_test() {
        use crate::Code::*;

        let response = json!({
            "success": true,
            "error-codes": ["missing-input-secret", "foo"],
            "hostname": "hostname"
        });
        let response: HcaptchaResponse = serde_json::from_value(response).unwrap();

        assert!(response.success);
        assert!(response.error_codes.is_some());

        let errors = response.error_codes.unwrap();
        assert!(errors.len() == 2);
        assert!(errors.contains(&MissingSecret));
        assert!(errors.contains(&Unknown("foo".to_string())));
    }

    fn test_response() -> HcaptchaResponse {
        let response = json!({
            "success": true,
            "challenge_ts": "2020-11-11T23:27:00Z",
            "hostname": "my-host.ie",
            "credit": false,
            "error-codes": ["missing-input-secret", "foo"],
            "score": null,
            "score_reason": [],
        });
        serde_json::from_value(response).unwrap()
    }

    #[test]
    fn success_test() {
        let response = test_response();

        assert_eq!(response.success(), true);
    }

    #[test]
    fn timestamp_test() {
        let response = test_response();

        assert_eq!(
            response.timestamp(),
            Some("2020-11-11T23:27:00Z".to_owned())
        );
    }

    #[test]
    fn hostname_test() {
        let response = test_response();

        assert_eq!(response.hostname(), Some("my-host.ie".to_owned()));
    }

    #[test]
    fn credit_test() {
        let response = test_response();

        assert_eq!(response.credit(), Some(false));
    }

    #[test]
    fn error_codes_test() {
        let response = test_response();

        assert!(response.error_codes().is_some());
        if let Some(hash_set) = response.error_codes() {
            assert_eq!(hash_set.len(), 2)
        }
    }

    #[test]
    fn score_test() {
        let response = test_response();

        assert!(response.score().is_none());
    }

    #[test]
    fn score_reason_test() {
        let response = test_response();
        println!("The response: {:?}", response);

        assert!(response.score_reason().is_some());
        if let Some(hash_set) = response.score_reason() {
            assert!(hash_set.is_empty())
        }
    }
}
