//! Request module
//! Provides a struct to collect the data required for
//! the hcaptcha api request.

const VERIFY_URL: &str = "https://hcaptcha.com/siteverify";

use super::response::HcaptchaResponse;
use super::HcaptchaError;
#[cfg(feature = "logging")]
use log::debug;
use reqwest::{Client, Url};
use serde_derive::Serialize;
use std::net::IpAddr;
/// Type to capture the required and optional data for a call to the hcaptcha API
#[derive(Debug, Default, Serialize)]
pub struct HcaptchaRequest {
    /// The response from the client's call to API
    response: String,
    /// The secret_key for the site_key used by the client to call the API
    secret: String,
    /// The ip address of the client making the call (optional)
    user_ip: Option<String>,
    /// The site_key used by the client to make the call (optional, recommended)
    site_key: Option<String>,
}

impl HcaptchaRequest {
    /// Create a new HcaptchaRequest
    #[allow(dead_code)]
    pub fn new(secret: &str, response: &str) -> HcaptchaRequest {
        HcaptchaRequest {
            response: response.to_owned(),
            secret: secret.to_owned(),
            ..HcaptchaRequest::default()
        }
    }

    /// Specify the optional ip address value
    #[allow(dead_code)]
    pub fn set_user_ip(&mut self, user_ip: &IpAddr) -> &HcaptchaRequest {
        self.user_ip = Some(user_ip.to_string());
        self
    }

    /// Specify the optional site key value
    #[allow(dead_code)]
    pub fn set_site_key(&mut self, site_key: &str) -> &HcaptchaRequest {
        self.site_key = Some(site_key.to_owned());
        self
    }

    /// Call the api to verify the response code recieved from the client
    #[allow(dead_code)]
    pub async fn verify(&self) -> Result<HcaptchaResponse, HcaptchaError> {
        let url = Url::parse(VERIFY_URL).unwrap();
        let response = Client::new().post(url).form(&self).send().await?;
        let response = response.json::<HcaptchaResponse>().await?;
        #[cfg(feature = "logging")]
        debug!("The response is: {:?}", response);
        Ok(response)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Code::*;
    use crate::HcaptchaError::*;
    use std::collections::HashSet;
    #[allow(unused_imports)]
    // use tokio_compat_02::FutureExt;
    #[tokio::test]
    async fn test_invalid_secret_missing_response() {
        let response = HcaptchaRequest::new("", "").verify().await;

        match response {
            Ok(response) => {
                println!("{:?}", response);
                let response = match (response.success(), response.error_codes()) {
                    (true, _) => Ok(()),
                    (false, Some(errors)) => Err(HcaptchaError::Codes(errors)),
                    (false, _) => Err(HcaptchaError::Codes(HashSet::new())),
                };

                match response {
                    Ok(_) => panic!("unexpected response: Ok(())"),
                    Err(Codes(ref errors)) => {
                        println!("Errors found {:?}", errors);
                        assert!(errors.contains(&MissingSecret));
                        assert!(errors.contains(&MissingResponse));
                    }
                    Err(e) => panic!("unexpected error: {}", e),
                };
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[tokio::test]
    async fn test_invalid_secret_missing_response_with_ip() {
        use std::net::Ipv4Addr;

        let user_ip = IpAddr::V4(Ipv4Addr::new(18, 197, 23, 227));

        let response = HcaptchaRequest::new("", "")
            .set_user_ip(&user_ip)
            .verify()
            // .compat()
            .await;

        match response {
            Ok(response) => {
                println!("{:?}", response);
                let response = match (response.success(), response.error_codes()) {
                    (true, _) => Ok(()),
                    (false, Some(errors)) => Err(HcaptchaError::Codes(errors)),
                    (false, _) => Err(HcaptchaError::Codes(HashSet::new())),
                };

                match response {
                    Ok(_) => panic!("unexpected response: Ok(())"),
                    Err(Codes(ref errors)) => {
                        println!("Errors found {:?}", errors);
                        assert!(errors.contains(&MissingSecret));
                        assert!(errors.contains(&MissingResponse));
                    }
                    Err(e) => panic!("unexpected error: {}", e),
                };
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[tokio::test]
    async fn test_invalid_secret_missing_response_with_site_key() {
        let response = HcaptchaRequest::new("", "")
            .set_site_key("10000000-ffff-ffff-ffff-000000000001")
            .verify()
            // .compat()
            .await;

        match response {
            Ok(response) => {
                println!("{:?}", response);
                let response = match (response.success(), response.error_codes()) {
                    (true, _) => Ok(()),
                    (false, Some(errors)) => Err(HcaptchaError::Codes(errors)),
                    (false, _) => Err(HcaptchaError::Codes(HashSet::new())),
                };

                match response {
                    Ok(_) => panic!("unexpected response: Ok(())"),
                    Err(Codes(ref errors)) => {
                        println!("Errors found {:?}", errors);
                        assert!(errors.contains(&MissingSecret));
                        assert!(errors.contains(&MissingResponse));
                    }
                    Err(e) => panic!("unexpected error: {}", e),
                };
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}
