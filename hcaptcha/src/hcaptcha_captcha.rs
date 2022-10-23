//! Collect the required and optional parameters supplied by the client for the
//! hcaptcha api request.
//!
//! # Example
//! Create HcaptchaCaptcha struct from the body of JSON submitted as an event.
//! ```no_run
//!     use hcaptcha::HcaptchaCaptcha;
//! # #[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
//! # pub struct CustomEvent {
//! #   body: Option<String>,
//! # }
//! # #[tokio::main]
//! # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
//! # let e = CustomEvent {
//! #         body: Some("{\"response\":\"thisisthelonglistofcharactersthatformsaresponse\",\"remoteip\":\"10.10.20.10\"}".to_owned()),
// //! #         body: None,
//! # };
//!     // Create captcha struct from json string provided by client in
//!     // the body of the http post that submitted a form.
//!     let body_str = e.body.unwrap_or_else(|| "".to_owned());
//!     let captcha: HcaptchaCaptcha = serde_json::from_str(&body_str)?;
//!
//!  # Ok(())
//! # }
//! ```

use crate::domain::{HcaptchaClientResponse, HcaptchaRemoteip, HcaptchaSitekey};
use crate::HcaptchaError;

/// Capture the Hcaptcha data coming from the client.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct HcaptchaCaptcha {
    /// The response string collected by client from Hcaptcha.
    pub(crate) response: HcaptchaClientResponse,
    /// The remoteip of the client submitting the request.
    pub(crate) remoteip: Option<HcaptchaRemoteip>,
    /// The sitekey submitted to Hcaptcha by the client.
    pub(crate) sitekey: Option<HcaptchaSitekey>,
}

impl HcaptchaCaptcha {
    /// Create a new HcaptchaCaptcha from a response string slice.
    ///
    /// # Input
    ///
    /// response - The response token from the client
    ///
    /// # Output
    ///
    /// The HcaptchaCaptcha is returned if the input is valid.
    /// A [HcaptchaError] is returned if the validation fails.
    ///
    /// # Example
    /// Create HcaptchaCaptcha from response key.
    /// ```no_run
    ///     use hcaptcha::HcaptchaCaptcha;
    /// # #[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
    /// # struct CustomEvent {
    /// #   body: Option<String>,
    /// # }
    /// #
    /// # #[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
    /// # struct Form {
    /// #   name: Option<String>,
    /// #   email: Option<String>,
    /// #   phone: Option<String>,
    /// #   note: Option<String>,
    /// #   response: String,
    /// # }
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let e = CustomEvent {
    /// #         body: Some("{\"response\":\"thisisthelonglistofcharactersthatformsaresponse\",\"remoteip\":\"10.10.20.10\"}".to_owned()),
    // //! #         body: None,
    /// # };
    ///     // Get the body JSON string from the event.
    ///     let body_str = e.body.unwrap_or_else(|| "".to_owned());
    ///     // Get the form data from the body string.
    ///     let form: Form = serde_json::from_str(&body_str)?;
    ///
    ///     let captcha = HcaptchaCaptcha::new(&form.response)?;
    ///  # Ok(())
    /// # }
    ///
    /// ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(
            name = "Create new HcaptchaCaptcha from a response string.",
            level = "debug"
        )
    )]
    pub fn new(response: &str) -> Result<Self, HcaptchaError> {
        Ok(HcaptchaCaptcha {
            response: HcaptchaClientResponse::parse(response.to_owned())?,
            remoteip: None,
            sitekey: None,
        })
    }

    /// Update the remoteip field in HcaptchaCaptcha.
    ///
    /// # Input
    ///
    /// remoteip - The response token from the client
    ///
    /// # Output
    ///
    /// If the remoteip string is empty the field is set to None.
    /// If the remoteip string is a valid v4 or v6 ip address the field is
    /// set to Some(remoteip).
    /// If the remoteip string is invalid a [HcaptchaError] is returned.
    ///
    /// # Example
    ///
    /// ```no_run
    ///     use hcaptcha::HcaptchaCaptcha;
    /// # use claims::assert_some;
    /// # #[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
    /// # struct CustomEvent {
    /// #   body: Option<String>,
    /// # }
    /// #
    /// # #[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
    /// # struct Form {
    /// #   name: Option<String>,
    /// #   email: Option<String>,
    /// #   phone: Option<String>,
    /// #   note: Option<String>,
    /// #   response: String,
    /// # }
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let e = CustomEvent {
    /// #         body: Some("{\"response\":\"thisisthelonglistofcharactersthatformsaresponse\",\"remoteip\":\"10.10.20.10\"}".to_owned()),
    // //! #         body: None,
    /// # };
    /// #     // Get the body JSON string from the event.
    /// #    let body_str = e.body.unwrap_or_else(|| "".to_owned());
    /// #    // Get the form data from the body string.
    /// #    let form: Form = serde_json::from_str(&body_str)?;
    ///     let remoteip = get_remoteip_address();
    ///
    ///     let captcha = HcaptchaCaptcha::new(&form.response)?
    ///                     .set_remoteip(&remoteip)?;
    ///
    ///     assert_some!(captcha.remoteip());
    ///     if let Some(sk) = captcha.remoteip() {
    ///             assert_eq!(remoteip, sk.to_string());
    ///     };
    ///  # Ok(())
    /// # }
    /// # fn get_remoteip_address() -> String {
    /// #    mockd::internet::ipv4_address()
    /// # }
    /// ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Update remoteip field in HcaptchaCaptcha.", level = "debug")
    )]
    pub fn set_remoteip(&mut self, remoteip: &str) -> Result<Self, HcaptchaError> {
        if remoteip.is_empty() {
            self.remoteip = None;
        } else {
            self.remoteip = Some(HcaptchaRemoteip::parse(remoteip.to_owned())?);
        };

        Ok(self.clone())
    }

    /// Update the remoteip field in HcaptchaCaptcha.
    ///
    /// # Input
    ///
    /// sitekey - The response token from the client
    ///
    /// # Output
    ///
    /// If the sitekey string is empty the field is set to None.
    /// If the sitekey string is a valid uuid the field is set to Some(sitekey).
    /// If the sitekey string is invalid a [HcaptchaError] is returned.
    ///
    /// # Example
    ///
    /// ```no_run
    ///     use hcaptcha::HcaptchaCaptcha;
    /// # use claims::assert_some;
    /// # #[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
    /// # struct CustomEvent {
    /// #   body: Option<String>,
    /// # }
    /// #
    /// # #[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
    /// # struct Form {
    /// #   name: Option<String>,
    /// #   email: Option<String>,
    /// #   phone: Option<String>,
    /// #   note: Option<String>,
    /// #   response: String,
    /// # }
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    /// # let e = CustomEvent {
    /// #         body: Some("{\"response\":\"thisisthelonglistofcharactersthatformsaresponse\",\"remoteip\":\"10.10.20.10\"}".to_owned()),
    // //! #         body: None,
    /// # };
    ///     // Get the body JSON string from the event.
    ///     let body_str = e.body.unwrap_or_else(|| "".to_owned());
    ///     // Get the form data from the body string.
    ///     let form: Form = serde_json::from_str(&body_str)?;
    ///     let sitekey = get_sitekey();
    ///
    ///     let captcha = HcaptchaCaptcha::new(&form.response)?
    ///                     .set_sitekey(&sitekey)?;
    ///
    ///     assert_some!(captcha.sitekey());
    ///     if let Some(sk) = captcha.sitekey() {
    ///             assert_eq!(sitekey, sk.to_string());
    ///     };
    ///
    ///  # Ok(())
    /// # }
    /// # fn get_sitekey() -> String {
    /// #    mockd::unique::uuid_v4()
    /// # }
    /// ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Update sitekey field in HcaptchaCaptcha.", level = "debug")
    )]
    pub fn set_sitekey(&mut self, sitekey: &str) -> Result<Self, HcaptchaError> {
        if sitekey.is_empty() {
            self.sitekey = None;
        } else {
            self.sitekey = Some(HcaptchaSitekey::parse(sitekey.to_owned())?);
        };

        Ok(self.clone())
    }

    /// Return the value of the response field.
    ///
    /// # Output
    ///
    /// A string containing the value of the response field.
    ///
    /// # Example
    ///
    /// ```no_run
    ///     use hcaptcha::HcaptchaCaptcha;
    ///     let (response, captcha) = get_captcha();
    ///
    ///     assert_eq!(response, captcha.response().to_string());
    ///
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # fn random_response() -> String {
    /// #     let mut rng = thread_rng();
    /// #     iter::repeat(())
    /// #         .map(|()| rng.sample(Alphanumeric))
    /// #         .map(char::from)
    /// #         .take(100)
    /// #         .collect()
    /// # }
    /// #
    /// # fn get_captcha() -> (String, HcaptchaCaptcha) {
    /// #     let response = random_response();
    /// #     let captcha = HcaptchaCaptcha::new(&response)
    /// #         .unwrap()
    /// #         .set_remoteip(&mockd::internet::ipv4_address())
    /// #         .unwrap()
    /// #         .set_sitekey(&mockd::unique::uuid_v4())
    /// #         .unwrap();
    /// #     (response, captcha)
    /// # }
    /// # fn get_sitekey() -> String {
    /// #    mockd::unique::uuid_v4()
    /// # }
    /// ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Get response field.", level = "debug")
    )]
    pub fn response(self) -> HcaptchaClientResponse {
        self.response
    }

    /// Get the value of the remoteip field.
    ///
    /// # Output
    ///
    /// An [Option] enum containing the value of the remoteip in the [Some]
    /// variant or a [None] variant if the value is not set.
    ///
    /// # Example
    ///
    /// ```no_run
    ///     use hcaptcha::HcaptchaCaptcha;
    /// # use claims::assert_some;
    ///     let (remoteip, captcha) = get_captcha();
    ///     
    ///     let value = captcha.remoteip();
    ///     assert_some!(&value);
    ///
    ///     if let Some(v) = value {
    ///         assert_eq!(remoteip, v.to_string());
    ///     }
    ///
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # fn random_response() -> String {
    /// #     let mut rng = thread_rng();
    /// #     iter::repeat(())
    /// #         .map(|()| rng.sample(Alphanumeric))
    /// #         .map(char::from)
    /// #         .take(100)
    /// #         .collect()
    /// # }
    /// #
    /// # fn get_captcha() -> (String, HcaptchaCaptcha) {
    /// #     let remoteip = mockd::internet::ipv4_address();
    /// #     let captcha = HcaptchaCaptcha::new(&random_response())
    /// #         .unwrap()
    /// #         .set_remoteip(&remoteip)
    /// #         .unwrap()
    /// #         .set_sitekey(&mockd::unique::uuid_v4())
    /// #         .unwrap();
    /// #     (remoteip, captcha)
    /// # }
    /// ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Get remoteip field.", level = "debug")
    )]
    pub fn remoteip(&self) -> Option<HcaptchaRemoteip> {
        self.remoteip.clone()
    }

    /// Get the value of the sitekey field.
    ///
    /// # Output
    ///
    /// An [Option] enum containing the value of the sitekey in the [Some]
    /// variant or a [None] variant if the value is not set.
    ///
    /// # Example
    ///
    /// ```no_run
    ///     use hcaptcha::HcaptchaCaptcha;
    /// # use claims::assert_some;
    ///     let (sitekey, captcha) = get_captcha();
    ///
    ///     let value = captcha.sitekey();
    ///     assert_some!(&value);
    ///
    ///     if let Some(v) = value {
    ///         assert_eq!(sitekey, v.to_string());
    ///     };
    ///
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # fn random_response() -> String {
    /// #     let mut rng = thread_rng();
    /// #     iter::repeat(())
    /// #         .map(|()| rng.sample(Alphanumeric))
    /// #         .map(char::from)
    /// #         .take(100)
    /// #         .collect()
    /// # }
    /// #
    /// # fn get_captcha() -> (String, HcaptchaCaptcha) {
    /// #     let sitekey = mockd::unique::uuid_v4();
    /// #     let captcha = HcaptchaCaptcha::new(&random_response())
    /// #         .unwrap()
    /// #         .set_remoteip(&mockd::internet::ipv4_address())
    /// #         .unwrap()
    /// #         .set_sitekey(&sitekey)
    /// #         .unwrap();
    /// #     (sitekey, captcha)
    /// # }
    /// ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(name = "Get sitekey field.", level = "debug")
    )]
    pub fn sitekey(&self) -> Option<HcaptchaSitekey> {
        self.sitekey.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Code;
    use claims::{assert_err, assert_none, assert_ok, assert_some};
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::iter;

    fn random_response() -> String {
        let mut rng = thread_rng();
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(100)
            .collect()
    }

    fn dummy_captcha() -> HcaptchaCaptcha {
        HcaptchaCaptcha::new(&random_response())
            .unwrap()
            .set_remoteip(&mockd::internet::ipv4_address())
            .unwrap()
            .set_sitekey(&mockd::unique::uuid_v4())
            .unwrap()
    }

    #[test]
    fn response_cannot_be_empty_or_blank() {
        let empty = "";
        assert_err!(HcaptchaCaptcha::new(empty));
        let blank = "   ";
        assert_err!(HcaptchaCaptcha::new(blank));
    }

    #[test]
    fn fail_if_remoteip_not_valid_v4_or_v6_address() {
        let captcha = HcaptchaCaptcha::new("response_string")
            .unwrap()
            .set_remoteip(&mockd::words::word());
        assert_err!(&captcha);
        if let Err(HcaptchaError::Codes(hs)) = captcha {
            assert!(hs.contains(&Code::InvalidUserIp));
        }
    }
    #[test]
    fn remoteip_is_optional() {
        let captcha = HcaptchaCaptcha::new("response_string")
            .unwrap()
            .set_remoteip(&mockd::internet::ipv4_address())
            .unwrap();

        assert_some!(captcha.remoteip);
    }

    #[test]
    fn valid_user_id_is_accepted() {
        assert_ok!(HcaptchaCaptcha::new("response_string")
            .unwrap()
            .set_remoteip(&mockd::internet::ipv4_address()));
    }

    #[test]
    fn fail_if_sitekey_not_valid_uuid() {
        let captcha = HcaptchaCaptcha::new("response_string")
            .unwrap()
            .set_sitekey(&mockd::words::word());

        assert_err!(&captcha);
        if let Err(HcaptchaError::Codes(hs)) = captcha {
            assert!(hs.contains(&Code::InvalidSiteKey));
        }
    }
    #[test]
    fn sitekey_is_optional() {
        let captcha = HcaptchaCaptcha::new("response_string")
            .unwrap()
            .set_sitekey(&mockd::unique::uuid_v4())
            .unwrap();

        assert_some!(captcha.sitekey);
    }

    #[test]
    fn valid_sitekey_is_accepted() {
        let captcha = HcaptchaCaptcha::new("response_string")
            .unwrap()
            .set_sitekey(&mockd::unique::uuid_v4())
            .unwrap();

        assert_some!(captcha.sitekey());
    }

    #[test]
    fn update_sitekey_with_empty_string_yields_none() {
        let mut captcha = dummy_captcha();

        assert_some!(captcha.sitekey());
        captcha.set_sitekey("").unwrap();

        assert_none!(captcha.sitekey());
    }

    #[test]
    fn update_remoteip_with_empty_string_yields_none() {
        let mut captcha = dummy_captcha();

        assert_some!(captcha.remoteip());
        captcha.set_remoteip("").unwrap();

        assert_none!(captcha.remoteip());
    }
}
