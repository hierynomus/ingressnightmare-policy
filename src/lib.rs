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


#[derive(Debug, PartialEq)]
enum PolicyResponse {
    Accept,
    Reject(String),
}


fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    let ingress = match serde_json::from_value::<apinetworking::Ingress>(
        validation_request.request.object,
    ) {
        Ok(ingress) => ingress,
        Err(_) => {
            // Not Ingress, so we don't need to validate it
            return kubewarden::accept_request();
        }
    };

    let settings = &validation_request.settings;

    match uses_blocked_annotations(&ingress, settings) {
        PolicyResponse::Accept => kubewarden::accept_request(),
        PolicyResponse::Reject(message) => {
            kubewarden::reject_request(Some(message), None, None, None)
        }
    }
}

fn uses_blocked_annotations(
    ingress: &apinetworking::Ingress,
    settings: &Settings,
) -> PolicyResponse {

    let mut blocked_annotations = vec![];
    blocked_annotations.extend_from_slice(&[
        "nginx.ingress.kubernetes.io/auth-url",
        "nginx.ingress.kubernetes.io/auth-tls-match-cn",
        "nginx.ingress.kubernetes.io/mirror-host",
        "nginx.ingress.kubernetes.io/mirror-target",
    ]);

    if !settings.allow_config_snippets {
        blocked_annotations.extend_from_slice(&[
            "nginx.ingress.kubernetes.io/server-snippet",
            "nginx.ingress.kubernetes.io/configuration-snippet",
            "nginx.ingress.kubernetes.io/auth-snippet",
        ]);
    }

    let annotations = &ingress.metadata.annotations;

    if let Some(annotations_map) = annotations {
        for key in annotations_map.keys() {
            if blocked_annotations.contains(&key.as_str()) {
                return PolicyResponse::Reject(format!("Blocked dangerous ingress annotation: {}", key));
            }
        }
    }

    return PolicyResponse::Accept;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
    use std::collections::BTreeMap;
    use rstest::rstest;

    #[rstest]
    #[case::no_annotations(None)]
    #[case::empty_annotations(Some(BTreeMap::new()))]
    #[case::no_blocked_annotations(Some(BTreeMap::from([("nginx.ingress.kubernetes.io/rewrite-target".to_string(), "http://example.com".to_string())])))]
    fn test_validate_accept(
        #[case] annotations: Option<BTreeMap<String, String>>,
    ) {
        let ingress = apinetworking::Ingress {
            metadata: metav1::ObjectMeta {
                annotations,
                ..Default::default()
            },
            ..Default::default()
        };

        let settings = Settings {
            allow_config_snippets: false,
        };

        assert_eq!(uses_blocked_annotations(&ingress, &settings), PolicyResponse::Accept);
    }

    #[rstest]
    #[case::block_auth_url("nginx.ingress.kubernetes.io/auth-url")]
    #[case::block_auth_tls_match_cn("nginx.ingress.kubernetes.io/auth-tls-match-cn")]
    #[case::block_mirror_host("nginx.ingress.kubernetes.io/mirror-host")]
    #[case::block_mirror_target("nginx.ingress.kubernetes.io/mirror-target")]
    fn test_block_cve_annotation(
        #[case] annotation: &str,
    ) {
        let ingress = apinetworking::Ingress {
            metadata: metav1::ObjectMeta {
                annotations: Some(BTreeMap::from([(
                    annotation.to_string(),
                    "http://example.com\nmalicious".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };

        let settings = Settings {
            allow_config_snippets: true,
        };

        assert_eq!(uses_blocked_annotations(&ingress, &settings), PolicyResponse::Reject(format!("Blocked dangerous ingress annotation: {}", annotation)));
    }

    #[rstest]
    #[case::block_config_snippet(false, PolicyResponse::Reject("Blocked dangerous ingress annotation: nginx.ingress.kubernetes.io/server-snippet".to_string()))]
    #[case::allow_config_snippet(true, PolicyResponse::Accept)]
    fn test_config_snippet(
        #[case] allow_config_snippets: bool,
        #[case] expected: PolicyResponse,
    ) {
        let ingress = apinetworking::Ingress {
            metadata: metav1::ObjectMeta {
                annotations: Some(BTreeMap::from([(
                    "nginx.ingress.kubernetes.io/server-snippet".to_string(),
                    "location /debug { allow all; }".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };

        let settings = Settings {
            allow_config_snippets,
        };

        assert_eq!(uses_blocked_annotations(&ingress, &settings), expected);
    }
}
