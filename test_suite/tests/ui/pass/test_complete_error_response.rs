mod helper;

use hcaptcha::{Code, Hcaptcha};
use serde_json::json;
use wiremock::matchers::{body_string, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug, Hcaptcha)]
struct Test {
    #[captcha]
    hcaptcha: String,
    #[sitekey]
    sitekey: String,
    #[remoteip]
    ip: String,
}

#[tokio::main]
async fn main() {
    // Setup
    let token = helper::random_string(100);
    let remoteip = mockd::internet::ipv4_address();
    let sitekey = mockd::unique::uuid_v4();
    let secret = format!("0x{}", hex::encode(helper::random_string(20)));

    let expected_body = format!(
        "response={}&remoteip={}&sitekey={}&secret={}",
        &token, &remoteip, &sitekey, &secret
    );

    let response_template = ResponseTemplate::new(200).set_body_json(json!({
        "success": false,
        "challenge_ts": null,
        "hostname": null,
        "credit": null,
        "error-codes": ["missing-input-secret", "foo"],
        "score": null,
        "score_reason": [],
    }));

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string(&expected_body))
        .respond_with(response_template)
        .mount(&mock_server)
        .await;

    let uri = format!("{}{}", mock_server.uri(), "/siteverify");

    let form = Test {
        hcaptcha: token,
        sitekey,
        ip: remoteip,
    };
    let response = form.valid_response(&secret, Some(uri)).await;

    claims::assert_err!(&response);

    if let Err(response) = response {
        match response {
            hcaptcha::HcaptchaError::Codes(hash_set) => {
                assert_eq!(hash_set.len(), 2);
                assert!(hash_set.contains(&Code::MissingSecret));
                assert!(hash_set.contains(&Code::Unknown("foo".to_owned())));
            }
            _ => unreachable!(),
        }
    };
}
