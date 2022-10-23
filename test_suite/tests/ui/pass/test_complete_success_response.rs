mod helper;

use chrono::{Duration, Utc};
use claims::assert_ok;
use hcaptcha::Hcaptcha;
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

    let form = Test {
        hcaptcha: token,
        sitekey,
        ip: remoteip,
    };
    let response = form.valid_response(&secret, Some(uri)).await;

    assert_ok!(&response);
    let response = response.unwrap();
    assert!(&response.success());
    assert_eq!(&response.timestamp().unwrap(), &timestamp);
    #[cfg(feature = "trace")]
    assert!(logs_contain("Hcaptcha API"));
    #[cfg(feature = "trace")]
    assert!(logs_contain("The response is"));
}
