use kubewarden_policy_sdk::request::ValidationRequest;
use kubewarden_policy_sdk::response::ValidationResponse;
use kubewarden_policy_sdk::wapc_guest as kubewarden;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
struct Settings {
    #[serde(default)]
    allow_config_snippets: bool,
}

fn default_true() -> bool {
    true
}

#[kubewarden::validate(request_type = "Value")]
fn validate(payload: Value) -> ValidationResponse {
    let request: ValidationRequest = match serde_json::from_value(payload) {
        Ok(req) => req,
        Err(_) => return ValidationResponse::reject("Invalid payload format"),
    };

    let settings: Settings = match request.settings.get("") {
        Some(settings_json) => match serde_json::from_value(settings_json.clone()) {
            Ok(s) => s,
            Err(_) => return ValidationResponse::reject("Invalid settings format"),
        },
        None => Settings {
            allow_config_snippets: true,
        },
    };

    let obj = request.request.object;
    let kind = obj["kind"].as_str().unwrap_or("");
    let annotations = &obj["metadata"]["annotations"];

    if kind != "Ingress" {
        return ValidationResponse::accept();
    }

    let mut blocked_annotations = vec![];
    blocked_annotations.extend_from_slice(&[
        "nginx.ingress.kubernetes.io/auth-url",
        "nginx.ingress.kubernetes.io/auth-tls-match-cn",
        "nginx.ingress.kubernetes.io/mirror-target",
        "nginx.ingress.kubernetes.io/mirror-host",
    ]);

    if !settings.allow_config_snippets {
        blocked_annotations.extend_from_slice(&[
            "nginx.ingress.kubernetes.io/server-snippet",
            "nginx.ingress.kubernetes.io/configuration-snippet",
            "nginx.ingress.kubernetes.io/auth-snippet",
        ]);
    }

    if let Some(annotations_map) = annotations.as_object() {
        for key in annotations_map.keys() {
            if blocked_annotations.contains(&key.as_str()) {
                return ValidationResponse::reject(format!(
                    "Blocked dangerous ingress annotation: {}",
                    key
                ));
            }
        }
    }

    ValidationResponse::accept()
}

#[kubewarden::protocol_version("v1")]
pub fn protocol_version() -> String {
    "v1".to_string()
}
