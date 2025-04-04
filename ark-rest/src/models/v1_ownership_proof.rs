/*
 * ark/v1/service.proto
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: version not set
 *
 * Generated by: https://openapi-generator.tech
 */

use crate::models;
use serde::Deserialize;
use serde::Serialize;

/// V1OwnershipProof : This message is used to prove to the server that the user controls the vtxo
/// without revealing the whole VTXO taproot tree.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct V1OwnershipProof {
    #[serde(rename = "controlBlock", skip_serializing_if = "Option::is_none")]
    pub control_block: Option<String>,
    #[serde(rename = "script", skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(rename = "signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl V1OwnershipProof {
    /// This message is used to prove to the server that the user controls the vtxo without
    /// revealing the whole VTXO taproot tree.
    pub fn new() -> V1OwnershipProof {
        V1OwnershipProof {
            control_block: None,
            script: None,
            signature: None,
        }
    }
}
