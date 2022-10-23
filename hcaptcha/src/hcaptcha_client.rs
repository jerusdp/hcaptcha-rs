//!
//! # Hcaptcha Client
//!
//! The Hcaptcha Client struct provides an http client to connect to
//! the Hcaptcha API.
//!
//! The url for the API is stored in the url field of the struct.
//! A default url is stored in the const VERIFY_URL.
//! The new_with method allows the specification of an alternative url.
//!
//! # Examples
//! Create client to connect to default API endpoint.
//! ```
//!     use hcaptcha::HcaptchaClient;
//!     let client = HcaptchaClient::new();
//! ```
//!
//! Create a client and submit for verification.
//!```no_run
//!     use hcaptcha::{HcaptchaCaptcha, HcaptchaClient, HcaptchaRequest};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
//! #   let secret = get_your_secret();
//! #   let captcha = dummy_captcha();
//! #   let request = HcaptchaRequest::new(&secret, captcha)?; // <- returns error
//!     let client = HcaptchaClient::new();
//!     let response = client.verify_client_response(request).await?;
//! # Ok(())
//! # }
//!
//! # fn get_your_secret() -> String {
//! #   "0x123456789abcde0f123456789abcdef012345678".to_string()
//! # }
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
//! # fn dummy_captcha() -> HcaptchaCaptcha {
//! #    HcaptchaCaptcha::new(&random_response())
//! #       .unwrap()
//! #       .set_remoteip(&mockd::internet::ipv4_address())
//! #       .unwrap()
//! #       .set_sitekey(&mockd::unique::uuid_v4())
//! #       .unwrap()
//! #       }
//!
//! ```

// const CYAN: &str = "\u{001b}[35m";
// const RESET: &str = "\u{001b}[0m";

use crate::HcaptchaError;
use crate::HcaptchaRequest;
use crate::HcaptchaResponse;
use reqwest::{Client, Url};

mod hcaptcha_form;

use hcaptcha_form::HcaptchaForm;

/// Endpoint url for the Hcaptcha siteverify API.
pub const VERIFY_URL: &str = "https://hcaptcha.com/siteverify";

/// Client to submit a request to a Hcaptcha validation endpoint.
#[cfg_attr(docsrs, allow(rustdoc::missing_doc_code_examples))]
#[derive(Debug)]
pub struct HcaptchaClient {
    /// HTTP Client to submit request to endpoint and read the response.
    client: Client,
    /// Url for the endpoint.
    url: Url,
}

#[cfg_attr(docsrs, allow(rustdoc::missing_doc_code_examples))]
impl Default for HcaptchaClient {
    fn default() -> HcaptchaClient {
        HcaptchaClient::new()
    }
}

#[cfg_attr(docsrs, allow(rustdoc::missing_doc_code_examples))]
impl HcaptchaClient {
    /// Create a new Hcaptcha Client to connect with the default Hcaptcha
    /// siteverify API endpoint specified in [VERIFY_URL].
    ///
    /// # Example
    /// Initialise client to connect to default API endpoint.
    /// ```
    ///     use hcaptcha::HcaptchaClient;
    ///     let client = HcaptchaClient::new();
    /// ```
    /// # Panic
    ///
    /// If the default API url constant is corrupted the function with
    /// will panic.
    #[allow(unknown_lints)]
    #[cfg_attr(docsrs, allow(rustdoc::bare_urls))]
    pub fn new() -> HcaptchaClient {
        HcaptchaClient {
            client: Client::new(),
            url: Url::parse(VERIFY_URL).expect("API url string corrupt"),
        }
    }

    /// Create a new Hcaptcha Client and specify the url for the API.
    ///
    /// Specify the url for the hcaptcha API.
    ///
    /// # Example
    /// Initialise client to connect to custom Hcaptcha API
    /// ```
    ///     use hcaptcha::HcaptchaClient;
    ///     use url::Url;
    ///
    ///     let url = "https://domain.com/siteverify";
    ///     let _client = HcaptchaClient::new_with(url);
    /// ```
    pub fn new_with(url: &str) -> Result<HcaptchaClient, url::ParseError> {
        Ok(HcaptchaClient {
            client: Client::new(),
            url: Url::parse(url)?,
        })
    }

    /// Set the url.
    ///
    /// Specify the url for the hcaptcha API. This method is useful
    /// during testing to provide a mock url.
    ///
    /// # Example
    /// Initialise client to connect to custom Hcaptcha API
    /// ```no_run
    /// # fn main() -> Result<(), hcaptcha::HcaptchaError> {
    ///     use hcaptcha::HcaptchaClient;
    ///     use url::Url;
    ///
    ///     let url = "https://domain.com/siteverify";
    ///     let client = HcaptchaClient::new()
    ///                        .set_url(url)?;
    /// #    Ok(())
    /// # }
    /// ```
    pub fn set_url(mut self, url: &str) -> Result<Self, HcaptchaError> {
        self.url = Url::parse(url)?;
        Ok(self)
    }

    /// Verify the client token with the Hcaptcha API.
    ///
    /// Call the Hcaptcha api providing a [HcaptchaRequest] struct.
    ///
    /// # Inputs
    ///
    /// HcaptchaRequest contains the required and optional fields
    /// for the Hcaptcha API. The required fields include the response
    /// code to validate and the secret key.
    ///
    /// # Outputs
    ///
    /// This method returns [HcaptchaResponse] if successful and [HcaptchaError] if
    /// unsuccessful.
    ///
    /// # Example
    ///
    ///
    ///  ```no_run
    ///     use hcaptcha::{HcaptchaClient, HcaptchaRequest};
    /// # use hcaptcha::HcaptchaCaptcha;
    /// # use rand::distributions::Alphanumeric;
    /// # use rand::{thread_rng, Rng};
    /// # use std::iter;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), hcaptcha::HcaptchaError> {
    ///     let secret = get_your_secret(); // your secret key
    ///     let captcha = get_captcha();  // user's token
    ///
    ///     let request = HcaptchaRequest::new(&secret, captcha)?;
    ///
    ///     let client = HcaptchaClient::new();
    ///
    ///     let response = client.verify_client_response(request).await?;
    ///
    /// # #[cfg(feature = "enterprise")]
    ///     let score = response.score();
    /// # #[cfg(feature = "enterprise")]
    ///     let score_reasons = response.score_reason();
    ///
    /// # Ok(())
    /// # }
    /// # fn get_your_secret() -> String {
    /// #   "0x123456789abcde0f123456789abcdef012345678".to_string()
    /// # }
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
    /// ```
    ///
    /// # Logging
    ///
    /// If the `trace` feature is enabled a debug level span is set for the
    /// method and an event logs the response.
    ///
    #[allow(dead_code)]
    #[cfg_attr(
        feature = "trace",
        tracing::instrument(
            name = "Request verification from hcaptcha.",
            skip(self),
            level = "debug"
        )
    )]
    pub async fn verify_client_response(
        self,
        request: HcaptchaRequest,
    ) -> Result<HcaptchaResponse, HcaptchaError> {
        let form: HcaptchaForm = request.into();
        #[cfg(feature = "trace")]
        tracing::debug!(
            "The form to submit to Hcaptcha API: {:?}",
            serde_urlencoded::to_string(&form).unwrap_or_else(|_| "form corrupted".to_owned())
        );
        let response = self
            .client
            .post(self.url.clone())
            .form(&form)
            .send()
            .await?
            .json::<HcaptchaResponse>()
            .await?;
        #[cfg(feature = "trace")]
        tracing::debug!("The response is: {:?}", response);
        response.check_error()?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Code;
    use chrono::{Duration, Utc};
    use claims::assert_ok;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use serde_json::json;
    use std::iter;
    #[cfg(feature = "trace")]
    use tracing_test::traced_test;
    use wiremock::matchers::{body_string, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // const RED: &str = "\t\u{001b}[31m";
    // const GREEN: &str = "\t\u{001b}[32m";
    // const CYAN: &str = "\t\u{001b}[36m";
    // const RESET: &str = "\t\u{001b}[0m";

    fn random_string(characters: usize) -> String {
        let mut rng = thread_rng();
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(characters)
            .collect()
    }

    #[tokio::test]
    #[cfg_attr(feature = "trace", traced_test)]
    async fn hcaptcha_mock() {
        let token = random_string(100);
        let secret = format!("0x{}", hex::encode(random_string(20)));
        let request = HcaptchaRequest::new_from_response(&secret, &token).unwrap();

        let expected_body = format!("response={}&secret={}", &token, &secret);

        let timestamp = Utc::now()
            .checked_sub_signed(Duration::minutes(10))
            .unwrap()
            .to_rfc3339();

        let response_template = ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "challenge_ts": timestamp,
            "hostname": "test-host",
        }));
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/siteverify"))
            .and(body_string(&expected_body))
            .respond_with(response_template)
            .mount(&mock_server)
            .await;
        let uri = format!("{}{}", mock_server.uri(), "/siteverify");

        let client = HcaptchaClient::new_with(&uri).unwrap();
        let response = client.verify_client_response(request).await;
        assert_ok!(&response);
        let response = response.unwrap();
        assert!(&response.success());
        assert_eq!(&response.timestamp().unwrap(), &timestamp);
        #[cfg(feature = "trace")]
        assert!(logs_contain("Hcaptcha API"));
        #[cfg(feature = "trace")]
        assert!(logs_contain("The response is"));
    }

    #[tokio::test]
    #[cfg_attr(feature = "trace", traced_test)]
    async fn hcaptcha_mock_with_remoteip() {
        let token = random_string(100);
        let secret = format!("0x{}", hex::encode(random_string(20)));
        let remoteip = mockd::internet::ipv4_address();
        let request = HcaptchaRequest::new_from_response(&secret, &token)
            .unwrap()
            .set_remoteip(&remoteip)
            .unwrap();

        let expected_body = format!(
            "response={}&remoteip={}&secret={}",
            &token, &remoteip, &secret
        );

        let timestamp = Utc::now()
            .checked_sub_signed(Duration::minutes(10))
            .unwrap()
            .to_rfc3339();

        let response_template = ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "challenge_ts": timestamp,
            "hostname": "test-host",
        }));
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/siteverify"))
            .and(body_string(&expected_body))
            .respond_with(response_template)
            .mount(&mock_server)
            .await;
        let uri = format!("{}{}", mock_server.uri(), "/siteverify");

        let client = HcaptchaClient::new_with(&uri).unwrap();
        let response = client.verify_client_response(request).await;
        assert_ok!(&response);
        let response = response.unwrap();
        assert!(&response.success());
        assert_eq!(&response.timestamp().unwrap(), &timestamp);
        #[cfg(feature = "trace")]
        assert!(logs_contain("Hcaptcha API"));
        #[cfg(feature = "trace")]
        assert!(logs_contain("The response is"));
    }

    #[tokio::test]
    #[cfg_attr(feature = "trace", traced_test)]
    async fn hcaptcha_mock_with_sitekey() {
        let token = random_string(100);
        let secret = format!("0x{}", hex::encode(random_string(20)));
        let sitekey = mockd::unique::uuid_v4();
        let request = HcaptchaRequest::new_from_response(&secret, &token)
            .unwrap()
            .set_sitekey(&sitekey)
            .unwrap();

        let expected_body = format!(
            "response={}&sitekey={}&secret={}",
            &token, &sitekey, &secret
        );

        let timestamp = Utc::now()
            .checked_sub_signed(Duration::minutes(10))
            .unwrap()
            .to_rfc3339();

        let response_template = ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "challenge_ts": timestamp,
            "hostname": "test-host",
        }));
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/siteverify"))
            .and(body_string(&expected_body))
            .respond_with(response_template)
            .mount(&mock_server)
            .await;
        let uri = format!("{}{}", mock_server.uri(), "/siteverify");

        let client = HcaptchaClient::new_with(&uri).unwrap();
        let response = client.verify_client_response(request).await;
        assert_ok!(&response);
        let response = response.unwrap();
        assert!(&response.success());
        assert_eq!(&response.timestamp().unwrap(), &timestamp);
        #[cfg(feature = "trace")]
        assert!(logs_contain("Hcaptcha API"));
        #[cfg(feature = "trace")]
        assert!(logs_contain("The response is"));
    }

    #[test]
    fn test_success_response() {
        let api_response = json!({
            "success": true,
            "challenge_ts": "2020-11-11T23:27:00Z",
            "hostname": "my-host.ie",
            "credit": true,
            "error-codes": [],
            "score": null,
            "score_reason": [],
        });
        let response: HcaptchaResponse = serde_json::from_value(api_response).unwrap();
        assert!(response.success());
        assert_eq!(
            response.timestamp(),
            Some("2020-11-11T23:27:00Z".to_owned())
        );
        assert_eq!(response.hostname(), Some("my-host.ie".to_owned()));
    }

    #[test]
    fn test_error_response() {
        let api_response = json!({
            "success": false,
            "challenge_ts": null,
            "hostname": null,
            "credit": null,
            "error-codes": ["missing-input-secret", "foo"],
            "score": null,
            "score_reason": [],
        });
        let response: HcaptchaResponse = serde_json::from_value(api_response).unwrap();
        assert!(!response.success());
        assert!(response.error_codes().is_some());
        if let Some(hash_set) = response.error_codes() {
            assert_eq!(hash_set.len(), 2);
            assert!(hash_set.contains(&Code::MissingSecret));
            assert!(hash_set.contains(&Code::Unknown("foo".to_owned())));
        }
    }
}
