use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::networking::v1 as apinetworking;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    let ingress = match serde_json::from_value::<apinetworking::Ingress>(
        validation_request.request.object,
    ) {
        Ok(ingress) => ingress,
        Err(_) => {
            // Not Ingress, so we donIngresst need to validate it
            return kubewarden::accept_request();
        }
    };

    let mut blocked_annotations = vec![];
    blocked_annotations.extend_from_slice(&[
        "nginx.ingress.kubernetes.io/auth-url",
        "nginx.ingress.kubernetes.io/auth-tls-match-cn",
        "nginx.ingress.kubernetes.io/mirror",
    ]);

    if !&validation_request.settings.allow_config_snippets {
        blocked_annotations.extend_from_slice(&[
            "nginx.ingress.kubernetes.io/server-snippet",
            "nginx.ingress.kubernetes.io/configuration-snippet",
            "nginx.ingress.kubernetes.io/auth-snippet",
        ]);
    }

    let annotations = ingress.metadata.annotations;

    if let Some(annotations_map) = annotations {
        for key in annotations_map.keys() {
            if blocked_annotations.contains(&key.as_str()) {
                return kubewarden::reject_request(
                    Some(format!("Blocked dangerous ingress annotation: {}", key)),
                    None, None, None
                );
            }
        }
    }

    return kubewarden::accept_request();
}
