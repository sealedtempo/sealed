// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import {IAppRegistry} from "./interfaces/IAppRegistry.sol";
import {OwnableNoRenounce} from "./utils/OwnableNoRenounce.sol";

/// @title AppRegistry
/// @notice Catalog of apps and their releases. The owner registers apps; the release CI (REGISTRAR_ROLE, the ops
///         key) publishes releases; the owner deprecates and revokes them.
/// @dev Roles: REGISTRAR_ROLE is managed only through the owner's grantRegistrar / revokeRegistrar. DEFAULT_ADMIN_ROLE
///      is never granted, so AccessControl's own grantRole / revokeRole always revert. A registrar may still
///      renounceRole itself.
///      Release status (D-013): None -> Active -> Deprecated -> Revoked, or Active -> Revoked. Revoked is terminal.
///      isActiveRelease is true for Active and Deprecated; isApprovableRelease only for Active; latestRelease returns
///      the newest Active release.
contract AppRegistry is IAppRegistry, OwnableNoRenounce, AccessControl {
    /// @notice Contract version.
    string public constant VERSION = "1.0.0";

    /// @notice Role allowed to publish releases.
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    /// @notice Upper bound for an app's maintainer share (50%).
    uint16 public constant MAX_MAINTAINER_SHARE_BPS = 5000;

    mapping(bytes32 appId => App app) private _apps;
    mapping(bytes32 releaseId => Release release) private _releases;
    mapping(bytes32 appId => bytes32[] releaseIds) private _appReleases;
    mapping(bytes32 appId => mapping(bytes32 versionHash => bytes32 releaseId)) private _releaseByVersion;
    bytes32[] private _appIds;

    /// @notice Emitted when an app is registered.
    event AppRegistered(
        bytes32 indexed appId,
        address indexed maintainer,
        string slug,
        string name,
        string licenseSpdx,
        uint16 maintainerShareBps,
        string metadataURI
    );

    /// @notice Emitted when an app's maintainer changes.
    /// @param changedBy The caller (previous maintainer or owner).
    event MaintainerChanged(
        bytes32 indexed appId, address indexed previousMaintainer, address indexed newMaintainer, address changedBy
    );

    /// @notice Emitted when an app's maintainer share changes.
    event MaintainerShareChanged(bytes32 indexed appId, uint16 previousShareBps, uint16 newShareBps);

    /// @notice Emitted when an app's metadata URI changes.
    event MetadataURIChanged(bytes32 indexed appId, string metadataURI);

    /// @notice Emitted when a release is published.
    event ReleasePublished(
        bytes32 indexed releaseId,
        bytes32 indexed appId,
        address indexed publisher,
        string version,
        bytes32 bundleHash,
        bytes32 egressPolicyHash,
        bytes32 sbomHash,
        string provenanceURI,
        string signatureURI
    );

    /// @notice Emitted when an Active release is deprecated.
    event ReleaseDeprecated(bytes32 indexed releaseId, bytes32 indexed appId);

    /// @notice Emitted when a release is revoked (terminal).
    event ReleaseRevoked(bytes32 indexed releaseId, bytes32 indexed appId, ReleaseStatus previousStatus, string reason);

    /// @notice The zero address was given.
    error ZeroAddress();
    /// @notice A required string was empty.
    error EmptyField();
    /// @notice appId is not keccak256(bytes(slug)).
    error AppIdMismatch(bytes32 appId, bytes32 expected);
    /// @notice The app is already registered.
    error AppAlreadyRegistered(bytes32 appId);
    /// @notice The app is not registered.
    error AppNotFound(bytes32 appId);
    /// @notice maintainerShareBps is above MAX_MAINTAINER_SHARE_BPS.
    error MaintainerShareTooHigh(uint16 shareBps);
    /// @notice The caller is neither the app's maintainer nor the owner.
    error NotMaintainerOrOwner(address caller);
    /// @notice bundleHash was zero.
    error ZeroBundleHash();
    /// @notice A release with this id already exists.
    error ReleaseAlreadyExists(bytes32 releaseId);
    /// @notice The app already has a release with this version.
    error VersionAlreadyPublished(bytes32 appId, string version);
    /// @notice The release does not exist.
    error ReleaseNotFound(bytes32 releaseId);
    /// @notice The release's status does not allow this transition.
    error InvalidReleaseStatus(bytes32 releaseId, ReleaseStatus status);
    /// @notice The account already has REGISTRAR_ROLE.
    error AlreadyRegistrar(address account);
    /// @notice The account does not have REGISTRAR_ROLE.
    error NotRegistrar(address account);
    /// @notice Index past the end of a list.
    error IndexOutOfBounds(uint256 index, uint256 length);

    /// @param initialOwner The owner (OWNER).
    constructor(address initialOwner) OwnableNoRenounce(initialOwner) {}

    // ---------------------------------------------------------------------------------------------------------
    // Roles
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Grants REGISTRAR_ROLE. Owner only. Emits RoleGranted.
    /// @param account The registrar (ops key).
    function grantRegistrar(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (!_grantRole(REGISTRAR_ROLE, account)) revert AlreadyRegistrar(account);
    }

    /// @notice Revokes REGISTRAR_ROLE. Owner only. Emits RoleRevoked.
    /// @param account The registrar to remove.
    function revokeRegistrar(address account) external onlyOwner {
        if (!_revokeRole(REGISTRAR_ROLE, account)) revert NotRegistrar(account);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Apps
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Registers an app. Owner only.
    /// @param appId Must equal keccak256(bytes(slug)).
    /// @param slug Unique app slug (non-empty).
    /// @param name Display name (non-empty).
    /// @param licenseSpdx SPDX license expression.
    /// @param maintainer Receives the maintainer share of fees (non-zero).
    /// @param maintainerShareBps Maintainer share in basis points, at most 5000.
    /// @param metadataURI Catalog metadata location.
    function registerApp(
        bytes32 appId,
        string calldata slug,
        string calldata name,
        string calldata licenseSpdx,
        address maintainer,
        uint16 maintainerShareBps,
        string calldata metadataURI
    ) external onlyOwner {
        if (bytes(slug).length == 0 || bytes(name).length == 0) revert EmptyField();
        bytes32 expected = keccak256(bytes(slug));
        if (appId != expected) revert AppIdMismatch(appId, expected);
        if (_apps[appId].registeredAt != 0) revert AppAlreadyRegistered(appId);
        if (maintainer == address(0)) revert ZeroAddress();
        if (maintainerShareBps > MAX_MAINTAINER_SHARE_BPS) revert MaintainerShareTooHigh(maintainerShareBps);

        App storage app = _apps[appId];
        app.slug = slug;
        app.name = name;
        app.licenseSpdx = licenseSpdx;
        app.metadataURI = metadataURI;
        app.maintainer = maintainer;
        app.maintainerShareBps = maintainerShareBps;
        app.registeredAt = uint64(block.timestamp);
        _appIds.push(appId);

        emit AppRegistered(appId, maintainer, slug, name, licenseSpdx, maintainerShareBps, metadataURI);
    }

    /// @notice Changes an app's maintainer. Callable by the current maintainer or the owner.
    /// @dev Fees already credited to the previous maintainer in FeeSplitter stay withdrawable by that address.
    /// @param appId The app id.
    /// @param newMaintainer The new maintainer (non-zero).
    function setMaintainer(bytes32 appId, address newMaintainer) external {
        App storage app = _existingApp(appId);
        address previous = app.maintainer;
        if (msg.sender != previous && msg.sender != owner()) revert NotMaintainerOrOwner(msg.sender);
        if (newMaintainer == address(0)) revert ZeroAddress();
        app.maintainer = newMaintainer;
        emit MaintainerChanged(appId, previous, newMaintainer, msg.sender);
    }

    /// @notice Changes an app's maintainer share. Owner only.
    /// @param appId The app id.
    /// @param maintainerShareBps New share in basis points, at most 5000.
    function setMaintainerShare(bytes32 appId, uint16 maintainerShareBps) external onlyOwner {
        App storage app = _existingApp(appId);
        if (maintainerShareBps > MAX_MAINTAINER_SHARE_BPS) revert MaintainerShareTooHigh(maintainerShareBps);
        uint16 previous = app.maintainerShareBps;
        app.maintainerShareBps = maintainerShareBps;
        emit MaintainerShareChanged(appId, previous, maintainerShareBps);
    }

    /// @notice Changes an app's metadata URI. Owner only.
    /// @param appId The app id.
    /// @param metadataURI The new URI.
    function setMetadataURI(bytes32 appId, string calldata metadataURI) external onlyOwner {
        App storage app = _existingApp(appId);
        app.metadataURI = metadataURI;
        emit MetadataURIChanged(appId, metadataURI);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Releases
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Publishes an Active release. REGISTRAR_ROLE only.
    /// @param appId A registered app.
    /// @param version Release version (non-empty, unique per app).
    /// @param bundleHash sha256 of the deterministic release bundle (non-zero).
    /// @param egressPolicyHash sha256 of the canonical egress policy.
    /// @param sbomHash Hash over the bundle's SBOM files.
    /// @param provenanceURI Build provenance location.
    /// @param signatureURI Signature / transparency log location.
    /// @return releaseId keccak256(abi.encode(appId, version, bundleHash)).
    function publishRelease(
        bytes32 appId,
        string calldata version,
        bytes32 bundleHash,
        bytes32 egressPolicyHash,
        bytes32 sbomHash,
        string calldata provenanceURI,
        string calldata signatureURI
    ) external onlyRole(REGISTRAR_ROLE) returns (bytes32 releaseId) {
        releaseId = _reserveRelease(appId, version, bundleHash);

        Release storage release = _releases[releaseId];
        release.appId = appId;
        release.bundleHash = bundleHash;
        release.egressPolicyHash = egressPolicyHash;
        release.sbomHash = sbomHash;
        release.status = ReleaseStatus.Active;
        release.publishedAt = uint64(block.timestamp);
        release.version = version;
        release.provenanceURI = provenanceURI;
        release.signatureURI = signatureURI;

        emit ReleasePublished(
            releaseId, appId, msg.sender, version, bundleHash, egressPolicyHash, sbomHash, provenanceURI, signatureURI
        );
    }

    /// @notice Deprecates an Active release. Owner only. Deprecated releases keep working in stacks that already
    ///         use them but cannot be added to new approvals (D-013).
    /// @param releaseId The release id.
    function deprecateRelease(bytes32 releaseId) external onlyOwner {
        Release storage release = _releases[releaseId];
        if (release.status == ReleaseStatus.None) revert ReleaseNotFound(releaseId);
        if (release.status != ReleaseStatus.Active) revert InvalidReleaseStatus(releaseId, release.status);
        release.status = ReleaseStatus.Deprecated;
        emit ReleaseDeprecated(releaseId, release.appId);
    }

    /// @notice Revokes an Active or Deprecated release. Owner only. Terminal; every stack using it stops being
    ///         approved.
    /// @param releaseId The release id.
    /// @param reason Human-readable reason (emitted, not stored).
    function revokeRelease(bytes32 releaseId, string calldata reason) external onlyOwner {
        Release storage release = _releases[releaseId];
        ReleaseStatus previous = release.status;
        if (previous == ReleaseStatus.None) revert ReleaseNotFound(releaseId);
        if (previous == ReleaseStatus.Revoked) revert InvalidReleaseStatus(releaseId, previous);
        release.status = ReleaseStatus.Revoked;
        emit ReleaseRevoked(releaseId, release.appId, previous, reason);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Returns an app. Reverts with AppNotFound for unknown ids.
    /// @param appId The app id.
    /// @return The app.
    function getApp(bytes32 appId) external view returns (App memory) {
        return _existingApp(appId);
    }

    /// @notice Whether an app is registered.
    /// @param appId The app id.
    /// @return True when registered.
    function appExists(bytes32 appId) external view returns (bool) {
        return _apps[appId].registeredAt != 0;
    }

    /// @notice Number of registered apps.
    /// @return The count.
    function appCount() external view returns (uint256) {
        return _appIds.length;
    }

    /// @notice The i-th registered app id, in registration order.
    /// @param index Index below appCount().
    /// @return The app id.
    function appAt(uint256 index) external view returns (bytes32) {
        if (index >= _appIds.length) revert IndexOutOfBounds(index, _appIds.length);
        return _appIds[index];
    }

    /// @notice Returns a release. Reverts with ReleaseNotFound for unknown ids.
    /// @param releaseId The release id.
    /// @return The release.
    function getRelease(bytes32 releaseId) external view returns (Release memory) {
        Release storage release = _releases[releaseId];
        if (release.status == ReleaseStatus.None) revert ReleaseNotFound(releaseId);
        return release;
    }

    /// @notice Status of a release (None for unknown ids). Never reverts.
    /// @param releaseId The release id.
    /// @return The status.
    function releaseStatus(bytes32 releaseId) external view returns (ReleaseStatus) {
        return _releases[releaseId].status;
    }

    /// @inheritdoc IAppRegistry
    function isActiveRelease(bytes32 releaseId) external view returns (bool) {
        ReleaseStatus status = _releases[releaseId].status;
        return status == ReleaseStatus.Active || status == ReleaseStatus.Deprecated;
    }

    /// @inheritdoc IAppRegistry
    function isApprovableRelease(bytes32 releaseId) external view returns (bool) {
        return _releases[releaseId].status == ReleaseStatus.Active;
    }

    /// @inheritdoc IAppRegistry
    function appOfRelease(bytes32 releaseId) external view returns (bytes32) {
        return _releases[releaseId].appId;
    }

    /// @inheritdoc IAppRegistry
    function payoutInfo(bytes32 appId) external view returns (address maintainer, uint16 maintainerShareBps) {
        App storage app = _existingApp(appId);
        return (app.maintainer, app.maintainerShareBps);
    }

    /// @notice The newest Active release of an app, or bytes32(0) if it has none (Deprecated releases are skipped).
    /// @param appId The app id.
    /// @return The release id.
    function latestRelease(bytes32 appId) external view returns (bytes32) {
        bytes32[] storage ids = _appReleases[appId];
        for (uint256 i = ids.length; i > 0;) {
            unchecked {
                --i;
            }
            if (_releases[ids[i]].status == ReleaseStatus.Active) return ids[i];
        }
        return bytes32(0);
    }

    /// @notice Number of releases ever published for an app.
    /// @param appId The app id.
    /// @return The count.
    function releaseCount(bytes32 appId) external view returns (uint256) {
        return _appReleases[appId].length;
    }

    /// @notice The i-th release of an app, in publish order.
    /// @param appId The app id.
    /// @param index Index below releaseCount(appId).
    /// @return The release id.
    function releaseAt(bytes32 appId, uint256 index) external view returns (bytes32) {
        bytes32[] storage ids = _appReleases[appId];
        if (index >= ids.length) revert IndexOutOfBounds(index, ids.length);
        return ids[index];
    }

    /// @notice The release id an app published for a version, or bytes32(0).
    /// @param appId The app id.
    /// @param version The version string.
    /// @return The release id.
    function releaseByVersion(bytes32 appId, string calldata version) external view returns (bytes32) {
        return _releaseByVersion[appId][keccak256(bytes(version))];
    }

    /// @notice keccak256(abi.encode(appId, version, bundleHash)) (D-008).
    /// @param appId The app id.
    /// @param version The version string.
    /// @param bundleHash The bundle hash.
    /// @return The release id.
    function computeReleaseId(bytes32 appId, string calldata version, bytes32 bundleHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(appId, version, bundleHash));
    }

    /// @notice keccak256(bytes(slug)) (D-008).
    /// @param slug The app slug.
    /// @return The app id.
    function computeAppId(string calldata slug) external pure returns (bytes32) {
        return keccak256(bytes(slug));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------------------------------------

    /// @dev Validates a new release, records its version and appends it to the app's list. Returns its id.
    function _reserveRelease(bytes32 appId, string calldata version, bytes32 bundleHash)
        private
        returns (bytes32 releaseId)
    {
        _existingApp(appId);
        if (bytes(version).length == 0) revert EmptyField();
        if (bundleHash == bytes32(0)) revert ZeroBundleHash();
        releaseId = computeReleaseId(appId, version, bundleHash);
        if (_releases[releaseId].status != ReleaseStatus.None) revert ReleaseAlreadyExists(releaseId);
        bytes32 versionHash = keccak256(bytes(version));
        if (_releaseByVersion[appId][versionHash] != bytes32(0)) revert VersionAlreadyPublished(appId, version);
        _releaseByVersion[appId][versionHash] = releaseId;
        _appReleases[appId].push(releaseId);
    }

    function _existingApp(bytes32 appId) private view returns (App storage app) {
        app = _apps[appId];
        if (app.registeredAt == 0) revert AppNotFound(appId);
    }
}
