//! Collect the required and optional parameters for the hcaptcha api request.
//!
//! # Example
//!
//! ```
//!     use hcaptcha::HcaptchaRequest;
//! # #[tokio::main]
//! # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
//!     let secret = get_your_secret();         // your secret key
//!     let captcha = get_captcha();            // user's response token
//!     let sitekey = get_your_sitekey();     // your site key
//!     let remoteip = get_remoteip_address();    // user's ip address
//!
//!     let request = HcaptchaRequest::new(&secret, captcha)?
//!         .set_sitekey(&sitekey)?
//!         .set_remoteip(&remoteip)?;
//! # Ok(())
//! # }
//! # fn get_your_secret() -> String {
//! #   "0x123456789abcde0f123456789abcdef012345678".to_string()
//! # }
//! # use hcaptcha::HcaptchaCaptcha;
//! # use rand::distributions::Alphanumeric;
//! # use rand::{thread_rng, Rng};
//! # use std::iter;
//! # fn random_response() -> String {
//! #    let mut rng = thread_rng();
//! #    iter::repeat(())
//! #        .map(|()| rng.sample(Alphanumeric))
//! #        .map(char::from)
//! #        .take(100)
//! #        .collect()
//! # }
//! # fn get_captcha() -> HcaptchaCaptcha {
//! #    HcaptchaCaptcha::new(&random_response())
//! #       .unwrap()
//! #       .set_remoteip(&mockd::internet::ipv4_address())
//! #       .unwrap()
//! #       .set_sitekey(&mockd::unique::uuid_v4())
//! #       .unwrap()
//! #       }
//! # fn get_remoteip_address() -> String {
//! #    "192.168.71.17".to_string()
//! # }
//! # use uuid::Uuid;
//! # fn get_your_sitekey() -> String {
//! #    Uuid::new_v4().to_string()
//! # }
//!
//! ```

use crate::domain::HcaptchaSecret;
use crate::HcaptchaCaptcha;
use crate::HcaptchaError;

/// Capture the required and optional data for a call to the hcaptcha API
#[cfg_attr(docsrs, allow(rustdoc::missing_doc_code_examples))]
#[derive(Debug, Default, serde::Serialize)]
pub struct HcaptchaRequest {
    /// [HcaptchaCaptcha] captures the response and, optionally, the remoteip
    /// and sitekey reported by the client.
    captcha: HcaptchaCaptcha,
    /// The secret_key related to the sitekey used to capture the response.
    secret: HcaptchaSecret,
}

#[cfg_attr(docsrs, allow(rustdoc::missing_doc_code_examples))]
impl HcaptchaRequest {
    /// Create a new HcaptchaRequest
    ///
    /// # Input
    ///
    /// The Hcaptcha API has two mandatory parameters:
    ///     `secret`:     The client's secret key for authentication
    ///     `captcha`:    [HcaptchaCaptcha] (including response token)
    ///
    /// # Output
    ///
    /// HcaptchaRequest is returned if the input strings are valid.
    /// [HcaptchaError] is returned if the validation fails.
    ///
    /// # Example
    ///
    /// ``` no_run
    ///     use hcaptcha::HcaptchaRequest;
    /// # fn main() -> Result<(), hcaptcha::HcaptchaError>{
    ///     let secret = get_your_secret();     // your secret key
    ///     let captcha = get_captcha();        // captcha with response token
    ///
    ///     let request = HcaptchaRequest::new(&secret, captcha)?;
    /// # Ok(())
    /// # }
    /// # fn get_your_secret() -> String {
    /// #   "0x123456789abcde0f123456789abcdef012345678".to_string()
    /// # }
    /// # use hcaptcha::HcaptchaCaptcha;
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # fn random_response() -> String {
    /// #    let mut rng = thread_rng();
    /// #    iter::repeat(())
    /// #        .map(|()| rng.sample(Alphanumeric))
    /// #        .map(char::from)
    /// #        .take(100)
    /// #        .collect()
    /// # }
    /// # fn get_captcha() -> HcaptchaCaptcha {
    /// #    HcaptchaCaptcha::new(&random_response())
    /// #       .unwrap()
    /// #       .set_remoteip(&mockd::internet::ipv4_address())
    /// #       .unwrap()
    /// #       .set_sitekey(&mockd::unique::uuid_v4())
    /// #       .unwrap()
    /// #       }
    ///  ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    /// The secret field will not be logged.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(
            name = "Create new HcaptchaRequest from HcaptchaCaptcha struct.",
            skip(secret),
            level = "debug"
        )
    )]
    pub fn new(secret: &str, captcha: HcaptchaCaptcha) -> Result<HcaptchaRequest, HcaptchaError> {
        Ok(HcaptchaRequest {
            captcha,
            secret: HcaptchaSecret::parse(secret.to_owned())?,
        })
    }

    /// Create a new HcaptchaRequest from only the response string
    ///
    /// # Input
    ///
    /// The Hcaptcha API has two mandatory parameters:
    ///     secret:     The client's secret key for authentication
    ///     response:    The response code to validate
    ///
    /// # Output
    ///
    /// HcaptchaRequest is returned if the inputs are valid.
    /// [HcaptchaError] is returned if the validation fails.
    ///
    /// # Example
    ///
    /// ``` no_run
    ///     use hcaptcha::HcaptchaRequest;
    /// # fn main() -> Result<(), hcaptcha::HcaptchaError>{
    ///     let secret = get_your_secret();     // your secret key
    ///     let response = get_response();    // Hcaptcha client response
    ///
    ///     let request = HcaptchaRequest::new_from_response(&secret, &response)?;
    /// # Ok(())
    /// # }
    /// # fn get_your_secret() -> String {
    /// #   "0x123456789abcde0f123456789abcdef012345678".to_string()
    /// # }
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # fn get_response() -> String {
    /// #    let mut rng = thread_rng();
    /// #    iter::repeat(())
    /// #        .map(|()| rng.sample(Alphanumeric))
    /// #        .map(char::from)
    /// #        .take(100)
    /// #        .collect()
    /// # }
    ///  ```
    /// # Logging
    ///
    /// If the tracing feature is enabled a debug level span is set for the
    /// method.
    /// The secret field will not be logged.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(
            name = "Create new HcaptchaRequest from response string.",
            skip(secret),
            level = "debug"
        )
    )]
    pub fn new_from_response(
        secret: &str,
        response: &str,
    ) -> Result<HcaptchaRequest, HcaptchaError> {
        let captcha = HcaptchaCaptcha::new(response)?;
        HcaptchaRequest::new(secret, captcha)
    }

    /// Specify the optional ip address value
    ///
    /// Update client IP address.
    ///
    /// # Example
    /// ``` no_run
    ///     use hcaptcha::HcaptchaRequest;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    ///     let secret = get_your_secret();         // your secret key
    ///     let response = get_response();          // user's response token
    ///     let remoteip = get_remoteip_address();    // user's ip address
    ///
    ///     let request = HcaptchaRequest::new_from_response(&secret, &response)?
    ///         .set_remoteip(&remoteip)?;
    /// # Ok(())
    /// # }
    /// # fn get_your_secret() -> String {
    /// #   "0x123456789abcde0f123456789abcdef012345678".to_string()
    /// # }
    /// # use hcaptcha::HcaptchaCaptcha;
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # fn get_response() -> String {
    /// #    let mut rng = thread_rng();
    /// #    iter::repeat(())
    /// #        .map(|()| rng.sample(Alphanumeric))
    /// #        .map(char::from)
    /// #        .take(100)
    /// #        .collect()
    /// # }
    /// # use std::net::{IpAddr, Ipv4Addr};
    /// # fn get_remoteip_address() -> String {
    /// #    "192.168.71.17".to_string()
    /// # }
    ///
    /// ```
    ///
    /// #Logging
    ///
    /// If the `trace` feature is enabled a debug level span is set for the
    /// method.
    /// The secret field is not logged.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(
            name = "Request verification from hcaptcha.",
            skip(self),
            fields(captcha = ?self.captcha),
            level = "debug"
        )
    )]
    pub fn set_remoteip(mut self, remoteip: &str) -> Result<Self, HcaptchaError> {
        self.captcha.set_remoteip(remoteip)?;
        Ok(self)
    }

    /// Specify the optional sitekey value
    ///
    /// Update the sitekey.
    ///
    /// # Example
    /// Create a new request and set the sitekey field in the request.
    /// ```
    ///     use hcaptcha::HcaptchaRequest;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    ///     let secret = get_your_secret();     // your secret key
    ///     let captcha = get_captcha();        // captcha
    ///     let sitekey = get_your_sitekey();   // your site key
    ///
    ///     let request = HcaptchaRequest::new(&secret, captcha)?
    ///         .set_sitekey(&sitekey);
    /// # Ok(())
    /// # }
    /// # fn get_your_secret() -> String {
    /// #   "0x123456789abcde0f123456789abcdef012345678".to_string()
    /// # }
    /// # use hcaptcha::HcaptchaCaptcha;
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # fn random_response() -> String {
    /// #    let mut rng = thread_rng();
    /// #    iter::repeat(())
    /// #        .map(|()| rng.sample(Alphanumeric))
    /// #        .map(char::from)
    /// #        .take(100)
    /// #        .collect()
    /// # }
    /// # fn get_captcha() -> HcaptchaCaptcha {
    /// #    HcaptchaCaptcha::new(&random_response())
    /// #       .unwrap()
    /// #       .set_remoteip(&mockd::internet::ipv4_address())
    /// #       .unwrap()
    /// #       .set_sitekey(&mockd::unique::uuid_v4())
    /// #       .unwrap()
    /// #       }
    /// # use uuid::Uuid;
    /// # fn get_your_sitekey() -> String {
    /// #    Uuid::new_v4().to_string()
    /// # }
    ///
    /// ```
    ///
    /// #Logging
    ///
    /// If the `trace` feature is enabled a debug level span is created for the
    /// method.
    /// The secret field is not logged.
    ///
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(
            name = "Request verification from hcaptcha.",
            skip(self),
            fields(captcha = ?self.captcha),
            level = "debug"
        )
    )]
    pub fn set_sitekey(mut self, sitekey: &str) -> Result<Self, HcaptchaError> {
        self.captcha.set_sitekey(sitekey)?;
        Ok(self)
    }

    #[allow(dead_code)]
    pub(crate) fn secret(&self) -> HcaptchaSecret {
        self.secret.clone()
    }

    #[allow(dead_code)]
    pub(crate) fn captcha(&self) -> HcaptchaCaptcha {
        self.captcha.clone()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::HcaptchaCaptcha;
    use claims::{assert_none, assert_ok};
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::iter;

    fn random_hex_string(len: usize) -> String {
        let mut rng = thread_rng();
        let chars: String = iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(len / 2)
            .collect();

        hex::encode(chars)
    }

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
    fn valid_new_from_captcha_struct() {
        let secret = format!("0x{}", random_hex_string(40));
        let captcha = dummy_captcha();

        assert_ok!(HcaptchaRequest::new(&secret, captcha));
    }

    #[test]
    fn valid_new_from_response() {
        let secret = format!("0x{}", random_hex_string(40));
        let response = random_response();

        let request = HcaptchaRequest::new_from_response(&secret, &response).unwrap();

        assert_eq!(&secret, &request.secret().to_string().as_str());

        let HcaptchaCaptcha {
            response: resp,
            remoteip: ip,
            sitekey: key,
        } = request.captcha;

        assert_eq!(response, resp.to_string());
        assert_none!(ip);
        assert_none!(key);
    }
}
