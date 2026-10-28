// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

/// @title IDeploymentRegistry
/// @notice Read interface of the deployment registry, used by FeeSplitter and offchain components.
interface IDeploymentRegistry {
    /// @notice Lifecycle of a deployment. Closed is terminal.
    enum DeploymentStatus {
        None,
        Active,
        Closed
    }

    /// @notice An attested deployment record. This is also the EIP-712 `Record` type, field for field.
    struct Record {
        bytes32 deploymentId;
        address customer;
        bytes32 stackHash;
        bytes32 imageId;
        bytes32 quoteHash;
        bytes32 eventLogHash;
        bytes32 configHash;
        address enclaveSigner;
        uint64 attestedAt;
    }

    /// @notice A stored deployment. Only hashes and addresses (P6).
    /// @param attestedAt attestedAt of the registration record.
    /// @param lastAttestedAt attestedAt of the most recent registration or heartbeat.
    /// @param method Attestation method used at registration.
    /// @param lastMethod Attestation method used by the most recent registration or heartbeat.
    struct Deployment {
        bytes32 deploymentId;
        address customer;
        uint64 attestedAt;
        uint8 method;
        uint8 lastMethod;
        DeploymentStatus status;
        bytes32 stackHash;
        bytes32 imageId;
        bytes32 quoteHash;
        bytes32 eventLogHash;
        bytes32 configHash;
        address enclaveSigner;
        uint64 lastAttestedAt;
        uint64 registeredAt;
        uint64 closedAt;
    }

    /// @notice Status and paying parties of a deployment (cheap view for FeeSplitter).
    /// @param deploymentId The deployment id.
    /// @return status The deployment status (None for unknown ids).
    /// @return customer The customer that approved the stack.
    /// @return enclaveSigner The enclave signer key bound in the record.
    function deploymentParties(bytes32 deploymentId)
        external
        view
        returns (DeploymentStatus status, address customer, address enclaveSigner);

    /// @notice True when the deployment exists and the approval of its (customer, stackHash) lists a release of
    ///         `appId`.
    /// @param deploymentId The deployment id.
    /// @param appId The app id.
    /// @return included Whether the app is part of the deployment's approved stack.
    function appInDeployment(bytes32 deploymentId, bytes32 appId) external view returns (bool included);
}
