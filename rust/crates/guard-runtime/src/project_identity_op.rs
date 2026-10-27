//! `ProjectIdentity` — resident op answering the portable Git project
//! identity of a workspace from `project_identity`.
//!
//! An input the resolver does not settle (`PortableIdentity::Unknown`) is
//! answered as no identity: the identity only widens which saved decisions a
//! workspace shares with its other clones, so leaving it out narrows a match
//! and never grants one.

use crate::package_authority_op::request_digest_with_limit;
use crate::project_identity::{portable_workspace, PortableIdentity};
use guard_contracts::{
    ProjectIdentityPayloadV1, ProjectIdentityQueryV1, ProjectIdentityRequestV1,
    ProjectIdentityResultV1, PROJECT_IDENTITY_MAX_BYTES, PROJECT_IDENTITY_REQUEST_SCHEMA,
    PROJECT_IDENTITY_RESULT_SCHEMA,
};

pub(crate) fn evaluate_project_identity_request(
    request: &ProjectIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any filesystem read; an
    // oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, PROJECT_IDENTITY_MAX_BYTES)
        .map_err(|_| "native_project_identity_too_large".to_owned())?;
    let (status, code, payload) = if request.schema == PROJECT_IDENTITY_REQUEST_SCHEMA {
        let ProjectIdentityQueryV1::Resolve { workspace } = &request.query;
        let identity = match portable_workspace(workspace) {
            PortableIdentity::Identity(identity) => Some(identity),
            PortableIdentity::Absent | PortableIdentity::Unknown => None,
        };
        (
            "ok",
            "ok",
            Some(ProjectIdentityPayloadV1::Resolve { identity }),
        )
    } else {
        ("error", "native_project_identity_schema_mismatch", None)
    };
    crate::encode_response(&ProjectIdentityResultV1 {
        schema: PROJECT_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(schema: &str, workspace: &str) -> ProjectIdentityResultV1 {
        let request = ProjectIdentityRequestV1 {
            schema: schema.to_owned(),
            request_id: "project-identity-1".to_owned(),
            query: ProjectIdentityQueryV1::Resolve {
                workspace: workspace.to_owned(),
            },
        };
        serde_json::from_slice(&evaluate_project_identity_request(&request).unwrap()).unwrap()
    }

    fn identity(result: &ProjectIdentityResultV1) -> Option<String> {
        match &result.payload {
            Some(ProjectIdentityPayloadV1::Resolve { identity }) => identity.clone(),
            None => panic!("no payload: {result:?}"),
        }
    }

    #[test]
    fn a_portable_identity_answers_itself() {
        let value = format!("git-project:v1:{}", "a".repeat(64));
        let result = run(PROJECT_IDENTITY_REQUEST_SCHEMA, &format!("  {value} "));
        assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
        assert_eq!(result.request_id, "project-identity-1");
        assert!(result.request_sha256.starts_with("sha256:"));
        assert_eq!(identity(&result), Some(value));
    }

    #[test]
    fn an_unsettled_or_blank_workspace_has_no_identity() {
        for workspace in ["", "   ", "relative/repository", "~/repository"] {
            let result = run(PROJECT_IDENTITY_REQUEST_SCHEMA, workspace);
            assert_eq!(result.status, "ok", "{workspace}");
            assert_eq!(identity(&result), None, "{workspace}");
        }
    }

    #[test]
    fn a_foreign_schema_is_refused_without_a_payload() {
        let result = run("guard-project-identity-request.v0", "/");
        assert_eq!(result.status, "error");
        assert_eq!(result.code, "native_project_identity_schema_mismatch");
        assert!(result.payload.is_none());
    }
}
