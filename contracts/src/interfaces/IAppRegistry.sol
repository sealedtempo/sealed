// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

/// @title IAppRegistry
/// @notice Read interface of the app catalog, used by DeploymentRegistry, FeeSplitter and offchain components.
interface IAppRegistry {
    /// @notice Lifecycle of a release. Revoked is terminal.
    enum ReleaseStatus {
        None,
        Active,
        Deprecated,
        Revoked
    }

    /// @notice A catalog app.
    struct App {
        string slug;
        string name;
        string licenseSpdx;
        string metadataURI;
        address maintainer;
        uint16 maintainerShareBps;
        uint64 registeredAt;
    }

    /// @notice A published release of an app.
    struct Release {
        bytes32 appId;
        bytes32 bundleHash;
        bytes32 egressPolicyHash;
        bytes32 sbomHash;
        ReleaseStatus status;
        uint64 publishedAt;
        string version;
        string provenanceURI;
        string signatureURI;
    }

    /// @notice True for Active and Deprecated releases (D-013): deprecated releases keep working in stacks that
    ///         already use them.
    /// @param releaseId The release id.
    /// @return active Whether the release may keep running.
    function isActiveRelease(bytes32 releaseId) external view returns (bool active);

    /// @notice True only for Active releases (D-013). Gates new stack approvals.
    /// @param releaseId The release id.
    /// @return approvable Whether a new stack approval may include the release.
    function isApprovableRelease(bytes32 releaseId) external view returns (bool approvable);

    /// @notice The app a release belongs to, or bytes32(0) for an unknown release.
    /// @param releaseId The release id.
    /// @return appId The app id.
    function appOfRelease(bytes32 releaseId) external view returns (bytes32 appId);

    /// @notice Current payout settings of an app. Reverts for unknown apps.
    /// @param appId The app id.
    /// @return maintainer The current maintainer.
    /// @return maintainerShareBps The maintainer's share of fees in basis points.
    function payoutInfo(bytes32 appId) external view returns (address maintainer, uint16 maintainerShareBps);
}
