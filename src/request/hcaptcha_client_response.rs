use crate::{Code, HcaptchaError};
use std::collections::HashSet;

#[derive(Debug, Default, serde::Serialize)]
pub struct HcaptchaClientResponse(String);

impl HcaptchaClientResponse {
    pub fn parse(s: String) -> Result<HcaptchaClientResponse, HcaptchaError> {
        if s.trim().is_empty() {
            let mut codes = HashSet::new();
            codes.insert(Code::MissingResponse);

            Err(HcaptchaError::Codes(codes))
        } else {
            Ok(HcaptchaClientResponse(s))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HcaptchaClientResponse;
    use crate::Code;
    use crate::HcaptchaError;
    use claim::assert_err;

    #[test]
    fn whitespace_only_names_are_rejected() {
        let response = " ".to_string();
        assert_err!(HcaptchaClientResponse::parse(response));
    }

    #[test]
    fn empty_string_is_rejected() {
        let response = "".to_string();
        assert_err!(HcaptchaClientResponse::parse(response));
    }

    #[test]
    fn error_set_contains_missing_response_error() {
        let response = "".to_string();

        if let Err(HcaptchaError::Codes(hs)) = HcaptchaClientResponse::parse(response) {
            assert!(hs.contains(&Code::MissingResponse));
        }
    }
}
