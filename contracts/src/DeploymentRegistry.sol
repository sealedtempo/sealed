// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {IAttestationVerifier, AttestationMethods} from "./IAttestationVerifier.sol";
import {IAppRegistry} from "./interfaces/IAppRegistry.sol";
import {IDeploymentRegistry} from "./interfaces/IDeploymentRegistry.sol";
import {IPlatformRegistry} from "./interfaces/IPlatformRegistry.sol";
import {OwnableNoRenounce} from "./utils/OwnableNoRenounce.sol";

/// @title DeploymentRegistry
/// @notice Customers approve stacks (a compose hash bound to a set of releases and a platform image). Attested
///         deployments of approved stacks are recorded here with an attestation checked by a pluggable verifier,
///         and kept alive by heartbeats.
/// @dev Stores hashes and addresses only (P6): never customer config, IPs, hostnames or domains.
///      EIP-712 domain: name "Sealed DeploymentRegistry", version "1", chainId, verifyingContract = this.
///      Attestation methods: 1 = ORACLE_SIG_V1 (set at deploy), 2 = ZK_DCAP_V1 (reserved, unset). New methods are
///      plugged in with setVerifier and need no other change.
///      Approval content (contract review): stackHash is the measured compose, which commits to the config's
///      releaseIds and imageId, so one (customer, stackHash) has exactly one release set and image. The first
///      approveStack fixes them; a re-approval must repeat them and may only change the expiry (and clear a
///      revocation). A revoked release therefore stays a kill switch for every deployment of the stack, and
///      appInDeployment always answers for the release set the deployment was registered with.
contract DeploymentRegistry is IDeploymentRegistry, OwnableNoRenounce, Pausable, EIP712 {
    /// @notice Contract version.
    string public constant VERSION = "1.0.0";

    /// @notice EIP-712 typehash of Record.
    bytes32 public constant RECORD_TYPEHASH = keccak256(
        "Record(bytes32 deploymentId,address customer,bytes32 stackHash,bytes32 imageId,bytes32 quoteHash,bytes32 eventLogHash,bytes32 configHash,address enclaveSigner,uint64 attestedAt)"
    );

    /// @notice EIP-712 typehash of Heartbeat.
    bytes32 public constant HEARTBEAT_TYPEHASH =
        keccak256("Heartbeat(bytes32 deploymentId,bytes32 quoteHash,uint64 attestedAt)");

    /// @notice Method id of the oracle signature verifier.
    uint8 public constant METHOD_ORACLE_SIG_V1 = AttestationMethods.ORACLE_SIG_V1;
    /// @notice Reserved method id of the ZK DCAP verifier.
    uint8 public constant METHOD_ZK_DCAP_V1 = AttestationMethods.ZK_DCAP_V1;

    /// @notice Maximum releases in one stack approval.
    uint256 public constant MAX_RELEASES_PER_STACK = 16;
    /// @notice How far in the future an attestedAt may be, to absorb clock skew.
    uint64 public constant MAX_FUTURE_SKEW = 5 minutes;
    /// @notice Default for maxAttestationAge.
    uint64 public constant DEFAULT_MAX_ATTESTATION_AGE = 1 days;
    /// @notice Upper bound accepted by setMaxAttestationAge.
    uint64 public constant MAX_ATTESTATION_AGE_LIMIT = 30 days;

    /// @notice The platform image registry.
    IPlatformRegistry public immutable platformRegistry;
    /// @notice The app catalog.
    IAppRegistry public immutable appRegistry;

    /// @notice Maximum age of an attestation at registration or heartbeat time.
    uint64 public maxAttestationAge;

    /// @notice Verifier per attestation method id (address(0) = unset).
    mapping(uint8 method => IAttestationVerifier verifier) public verifiers;

    struct StackApproval {
        bytes32 imageId;
        uint64 expiry;
        uint64 approvedAt;
        bool revoked;
        bytes32[] releaseIds;
    }

    mapping(address customer => mapping(bytes32 stackHash => StackApproval approval)) private _approvals;
    mapping(bytes32 deploymentId => Deployment deployment) private _deployments;

    /// @notice Number of deployments ever registered.
    uint256 public deploymentCount;

    /// @notice Emitted by approveStack, including re-approvals (which repeat the release set and image, set a new
    ///         expiry and clear a previous revocation).
    /// @param expiry 0 for no expiry, otherwise the unix time at which the approval stops being valid.
    event StackApproved(
        address indexed customer,
        bytes32 indexed stackHash,
        bytes32 indexed imageId,
        bytes32[] releaseIds,
        uint64 expiry
    );

    /// @notice Emitted by revokeStack.
    event StackRevoked(address indexed customer, bytes32 indexed stackHash);

    /// @notice Emitted by registerDeployment with the full record.
    /// @param submitter The account that submitted the transaction.
    event DeploymentRegistered(
        bytes32 indexed deploymentId,
        address indexed customer,
        bytes32 indexed stackHash,
        Record record,
        uint8 method,
        address submitter
    );

    /// @notice Emitted by heartbeat.
    event DeploymentHeartbeat(bytes32 indexed deploymentId, bytes32 quoteHash, uint64 attestedAt, uint8 method);

    /// @notice Emitted by closeDeployment.
    event DeploymentClosed(bytes32 indexed deploymentId, address indexed closedBy);

    /// @notice Emitted by setVerifier.
    event VerifierSet(uint8 indexed method, address indexed previousVerifier, address indexed newVerifier);

    /// @notice Emitted by setMaxAttestationAge and once by the constructor.
    event MaxAttestationAgeSet(uint64 previousMaxAge, uint64 newMaxAge);

    /// @notice A zero address was given.
    error ZeroAddress();
    /// @notice stackHash was zero.
    error ZeroStackHash();
    /// @notice Release count outside 1..MAX_RELEASES_PER_STACK.
    error InvalidReleaseCount(uint256 count);
    /// @notice The same release appears twice.
    error DuplicateRelease(bytes32 releaseId);
    /// @notice A first approval names a release that is not Active (isApprovableRelease), or a re-approval names one
    ///         that is no longer Active or Deprecated (isActiveRelease).
    error ReleaseNotApprovable(bytes32 releaseId);
    /// @notice A re-approval names a different release list than the existing approval of the stack.
    error ReleasesChanged(address customer, bytes32 stackHash);
    /// @notice The image is not approved.
    error ImageNotApproved(bytes32 imageId);
    /// @notice expiry is non-zero and not in the future.
    error InvalidExpiry(uint64 expiry);
    /// @notice No live approval exists for (customer, stackHash).
    error ApprovalNotFound(address customer, bytes32 stackHash);
    /// @notice The approval is already revoked.
    error ApprovalAlreadyRevoked(address customer, bytes32 stackHash);
    /// @notice deploymentId was zero.
    error ZeroDeploymentId();
    /// @notice The deployment id is already used.
    error DeploymentAlreadyRegistered(bytes32 deploymentId);
    /// @notice The deployment does not exist.
    error DeploymentNotFound(bytes32 deploymentId);
    /// @notice The deployment is not Active.
    error DeploymentNotActive(bytes32 deploymentId);
    /// @notice isStackApproved(customer, stackHash) is false.
    error StackNotApproved(address customer, bytes32 stackHash);
    /// @notice The record's (or a re-approval's) image differs from the approval's image.
    error ImageMismatch(bytes32 imageId, bytes32 approvedImageId);
    /// @notice The record was attested before the current approval of its stack (minus MAX_FUTURE_SKEW).
    error AttestedBeforeApproval(uint64 attestedAt, uint64 approvedAt);
    /// @notice A heartbeat repeats the deployment's current quoteHash.
    error QuoteReused(bytes32 quoteHash);
    /// @notice method is 0 (invalid).
    error InvalidMethod(uint8 method);
    /// @notice No verifier is set for the method.
    error VerifierNotSet(uint8 method);
    /// @notice The verifier rejected the evidence.
    error InvalidAttestation(uint8 method);
    /// @notice attestedAt is more than MAX_FUTURE_SKEW ahead of block time.
    error AttestationInFuture(uint64 attestedAt, uint256 blockTime);
    /// @notice attestedAt is older than maxAttestationAge.
    error AttestationTooOld(uint64 attestedAt, uint256 blockTime);
    /// @notice A heartbeat's attestedAt is not after the last one.
    error StaleHeartbeat(uint64 attestedAt, uint64 lastAttestedAt);
    /// @notice The caller is neither the deployment's customer nor the owner.
    error NotCustomerOrOwner(address caller);
    /// @notice maxAttestationAge outside 1..MAX_ATTESTATION_AGE_LIMIT.
    error InvalidMaxAttestationAge(uint64 maxAge);
    /// @notice The verifier address has no code.
    error VerifierNotContract(address verifier);

    /// @param initialOwner The owner (OWNER).
    /// @param platformRegistry_ The PlatformRegistry.
    /// @param appRegistry_ The AppRegistry.
    constructor(address initialOwner, IPlatformRegistry platformRegistry_, IAppRegistry appRegistry_)
        OwnableNoRenounce(initialOwner)
        EIP712("Sealed DeploymentRegistry", "1")
    {
        if (address(platformRegistry_) == address(0) || address(appRegistry_) == address(0)) revert ZeroAddress();
        platformRegistry = platformRegistry_;
        appRegistry = appRegistry_;
        maxAttestationAge = DEFAULT_MAX_ATTESTATION_AGE;
        emit MaxAttestationAgeSet(0, DEFAULT_MAX_ATTESTATION_AGE);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Stack approvals (customer)
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Approves a stack for the caller (the customer). The first approval of a stackHash fixes its release
    ///         list and image. Re-approving the same stackHash must name the same releases (same order) and image,
    ///         sets the new expiry and clears a revocation.
    /// @dev First approval: 1..16 distinct releases, each Active (isApprovableRelease). Re-approval: the stored list,
    ///      each release still Active or Deprecated (isActiveRelease, D-013), so a stack that uses a since-deprecated
    ///      release can still be extended or restored after revokeStack. Either way the image must be approved.
    /// @param stackHash The stack (compose) hash, non-zero.
    /// @param releaseIds 1..16 distinct releases.
    /// @param imageId An approved platform image.
    /// @param expiry 0 for no expiry, or a unix time in the future.
    function approveStack(bytes32 stackHash, bytes32[] calldata releaseIds, bytes32 imageId, uint64 expiry) external {
        if (stackHash == bytes32(0)) revert ZeroStackHash();
        uint256 count = releaseIds.length;
        if (count == 0 || count > MAX_RELEASES_PER_STACK) revert InvalidReleaseCount(count);
        // Expiry and freshness are coarse (minutes to days); validator timestamp drift is irrelevant here.
        // forge-lint: disable-next-line(block-timestamp)
        if (expiry != 0 && expiry <= block.timestamp) revert InvalidExpiry(expiry);
        if (!platformRegistry.isApprovedImage(imageId)) revert ImageNotApproved(imageId);

        StackApproval storage a = _approvals[msg.sender][stackHash];
        if (a.approvedAt == 0) {
            for (uint256 i; i < count; ++i) {
                bytes32 releaseId = releaseIds[i];
                for (uint256 j; j < i; ++j) {
                    if (releaseIds[j] == releaseId) revert DuplicateRelease(releaseId);
                }
                if (!appRegistry.isApprovableRelease(releaseId)) revert ReleaseNotApprovable(releaseId);
            }
            a.imageId = imageId;
            a.releaseIds = releaseIds;
        } else {
            if (imageId != a.imageId) revert ImageMismatch(imageId, a.imageId);
            bytes32[] storage stored = a.releaseIds;
            if (count != stored.length) revert ReleasesChanged(msg.sender, stackHash);
            for (uint256 i; i < count; ++i) {
                bytes32 releaseId = releaseIds[i];
                if (releaseId != stored[i]) revert ReleasesChanged(msg.sender, stackHash);
                if (!appRegistry.isActiveRelease(releaseId)) revert ReleaseNotApprovable(releaseId);
            }
        }
        a.expiry = expiry;
        a.approvedAt = uint64(block.timestamp);
        a.revoked = false;

        emit StackApproved(msg.sender, stackHash, imageId, releaseIds, expiry);
    }

    /// @notice Revokes the caller's approval of a stack. Registered deployments of the stack can no longer
    ///         heartbeat, and no new deployment of it can be registered. A later re-approval restores both for
    ///         every deployment of the stack that was not closed: use closeDeployment to stop one for good.
    /// @param stackHash The stack hash.
    function revokeStack(bytes32 stackHash) external {
        StackApproval storage a = _approvals[msg.sender][stackHash];
        if (a.approvedAt == 0) revert ApprovalNotFound(msg.sender, stackHash);
        if (a.revoked) revert ApprovalAlreadyRevoked(msg.sender, stackHash);
        a.revoked = true;
        emit StackRevoked(msg.sender, stackHash);
    }

    /// @notice True when the approval exists, is not revoked, has not expired, every release is still active
    ///         (Active or Deprecated) and the image is still approved.
    /// @param customer The customer.
    /// @param stackHash The stack hash.
    /// @return True when approved.
    function isStackApproved(address customer, bytes32 stackHash) public view returns (bool) {
        StackApproval storage a = _approvals[customer][stackHash];
        if (a.approvedAt == 0 || a.revoked) return false;
        // forge-lint: disable-next-line(block-timestamp)
        if (a.expiry != 0 && block.timestamp >= a.expiry) return false;
        if (!platformRegistry.isApprovedImage(a.imageId)) return false;
        bytes32[] storage ids = a.releaseIds;
        uint256 count = ids.length;
        for (uint256 i; i < count; ++i) {
            if (!appRegistry.isActiveRelease(ids[i])) return false;
        }
        return true;
    }

    /// @notice The stored approval of (customer, stackHash). All zero when none exists.
    /// @param customer The customer.
    /// @param stackHash The stack hash.
    /// @return releaseIds The approved releases.
    /// @return imageId The approved image.
    /// @return expiry 0 for no expiry, else the expiry time.
    /// @return revoked Whether the approval was revoked.
    /// @return approvedAt Time of the latest approveStack call (0 when none). Records attested more than
    ///         MAX_FUTURE_SKEW before it cannot be registered.
    function getStackApproval(address customer, bytes32 stackHash)
        external
        view
        returns (bytes32[] memory releaseIds, bytes32 imageId, uint64 expiry, bool revoked, uint64 approvedAt)
    {
        StackApproval storage a = _approvals[customer][stackHash];
        return (a.releaseIds, a.imageId, a.expiry, a.revoked, a.approvedAt);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Deployments
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Registers an attested deployment. Anyone may submit (the ops key does); the attestation is what
    ///         authorizes it. The record must be attested after the latest approveStack of its stack (with
    ///         MAX_FUTURE_SKEW of tolerance), so a record signed before a revoke and re-approval cannot be used.
    /// @param r The record. deploymentId = keccak256(abi.encode(customer, stackHash, salt)) is computed offchain.
    /// @param method Attestation method id (1 = oracle signature).
    /// @param evidence Method-specific evidence over recordDigest(r).
    function registerDeployment(Record calldata r, uint8 method, bytes calldata evidence) external whenNotPaused {
        bytes32 deploymentId = r.deploymentId;
        if (deploymentId == bytes32(0)) revert ZeroDeploymentId();
        if (_deployments[deploymentId].status != DeploymentStatus.None) {
            revert DeploymentAlreadyRegistered(deploymentId);
        }
        if (r.customer == address(0) || r.enclaveSigner == address(0)) revert ZeroAddress();
        if (!isStackApproved(r.customer, r.stackHash)) revert StackNotApproved(r.customer, r.stackHash);
        StackApproval storage a = _approvals[r.customer][r.stackHash];
        if (r.imageId != a.imageId) revert ImageMismatch(r.imageId, a.imageId);
        _checkFreshness(r.attestedAt);
        if (uint256(r.attestedAt) + MAX_FUTURE_SKEW < a.approvedAt) {
            revert AttestedBeforeApproval(r.attestedAt, a.approvedAt);
        }
        _verify(method, _recordDigest(r), evidence);

        Deployment storage d = _deployments[deploymentId];
        d.deploymentId = deploymentId;
        d.customer = r.customer;
        d.attestedAt = r.attestedAt;
        d.method = method;
        d.lastMethod = method;
        d.status = DeploymentStatus.Active;
        d.stackHash = r.stackHash;
        d.imageId = r.imageId;
        d.quoteHash = r.quoteHash;
        d.eventLogHash = r.eventLogHash;
        d.configHash = r.configHash;
        d.enclaveSigner = r.enclaveSigner;
        d.lastAttestedAt = r.attestedAt;
        d.registeredAt = uint64(block.timestamp);
        unchecked {
            ++deploymentCount;
        }

        emit DeploymentRegistered(deploymentId, r.customer, r.stackHash, r, method, msg.sender);
    }

    /// @notice Records a fresh attestation of an Active deployment. Anyone may submit.
    /// @dev Requires the stack to still be approved, a fresh attestedAt strictly after the previous one, a quoteHash
    ///      different from the current one, and valid evidence over heartbeatDigest(...). The approval's image and
    ///      releases cannot change after registration, so they need no check here.
    /// @param deploymentId The deployment id.
    /// @param quoteHash sha256 of the new TDX quote.
    /// @param attestedAt Time of the new attestation.
    /// @param method Attestation method id.
    /// @param evidence Method-specific evidence over heartbeatDigest(deploymentId, quoteHash, attestedAt).
    function heartbeat(
        bytes32 deploymentId,
        bytes32 quoteHash,
        uint64 attestedAt,
        uint8 method,
        bytes calldata evidence
    ) external whenNotPaused {
        Deployment storage d = _deployments[deploymentId];
        if (d.status != DeploymentStatus.Active) revert DeploymentNotActive(deploymentId);
        address customer = d.customer;
        bytes32 stackHash = d.stackHash;
        if (!isStackApproved(customer, stackHash)) revert StackNotApproved(customer, stackHash);
        if (attestedAt <= d.lastAttestedAt) revert StaleHeartbeat(attestedAt, d.lastAttestedAt);
        if (quoteHash == d.quoteHash) revert QuoteReused(quoteHash);
        _checkFreshness(attestedAt);
        _verify(method, heartbeatDigest(deploymentId, quoteHash, attestedAt), evidence);

        d.quoteHash = quoteHash;
        d.lastAttestedAt = attestedAt;
        d.lastMethod = method;

        emit DeploymentHeartbeat(deploymentId, quoteHash, attestedAt, method);
    }

    /// @notice Closes an Active deployment. Callable by its customer or the owner, also while paused. Terminal.
    /// @param deploymentId The deployment id.
    function closeDeployment(bytes32 deploymentId) external {
        Deployment storage d = _deployments[deploymentId];
        if (d.status == DeploymentStatus.None) revert DeploymentNotFound(deploymentId);
        if (msg.sender != d.customer && msg.sender != owner()) revert NotCustomerOrOwner(msg.sender);
        if (d.status != DeploymentStatus.Active) revert DeploymentNotActive(deploymentId);
        d.status = DeploymentStatus.Closed;
        d.closedAt = uint64(block.timestamp);
        emit DeploymentClosed(deploymentId, msg.sender);
    }

    /// @notice Returns a deployment. Reverts with DeploymentNotFound for unknown ids.
    /// @param deploymentId The deployment id.
    /// @return The deployment.
    function getDeployment(bytes32 deploymentId) external view returns (Deployment memory) {
        Deployment storage d = _deployments[deploymentId];
        if (d.status == DeploymentStatus.None) revert DeploymentNotFound(deploymentId);
        return d;
    }

    /// @inheritdoc IDeploymentRegistry
    function deploymentParties(bytes32 deploymentId)
        external
        view
        returns (DeploymentStatus status, address customer, address enclaveSigner)
    {
        Deployment storage d = _deployments[deploymentId];
        return (d.status, d.customer, d.enclaveSigner);
    }

    /// @inheritdoc IDeploymentRegistry
    function appInDeployment(bytes32 deploymentId, bytes32 appId) external view returns (bool) {
        Deployment storage d = _deployments[deploymentId];
        if (d.status == DeploymentStatus.None || appId == bytes32(0)) return false;
        bytes32[] storage ids = _approvals[d.customer][d.stackHash].releaseIds;
        uint256 count = ids.length;
        for (uint256 i; i < count; ++i) {
            if (appRegistry.appOfRelease(ids[i]) == appId) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------------------------------------------------
    // EIP-712
    // ---------------------------------------------------------------------------------------------------------

    /// @notice EIP-712 digest of a Record, as passed to IAttestationVerifier.verify.
    /// @param r The record.
    /// @return The digest.
    function recordDigest(Record calldata r) external view returns (bytes32) {
        return _recordDigest(r);
    }

    /// @notice EIP-712 digest of a Heartbeat, as passed to IAttestationVerifier.verify.
    /// @param deploymentId The deployment id.
    /// @param quoteHash The new quote hash.
    /// @param attestedAt The new attestation time.
    /// @return The digest.
    function heartbeatDigest(bytes32 deploymentId, bytes32 quoteHash, uint64 attestedAt) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(HEARTBEAT_TYPEHASH, deploymentId, quoteHash, attestedAt)));
    }

    /// @notice The EIP-712 domain separator of this contract on this chain.
    /// @return The domain separator.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ---------------------------------------------------------------------------------------------------------
    // Admin
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Sets or unsets (address(0)) the verifier for an attestation method. Owner only. Method 0 is invalid.
    /// @param method The method id (1..255).
    /// @param verifier An IAttestationVerifier contract, or address(0) to unset.
    function setVerifier(uint8 method, address verifier) external onlyOwner {
        if (method == 0) revert InvalidMethod(method);
        if (verifier != address(0) && verifier.code.length == 0) revert VerifierNotContract(verifier);
        address previous = address(verifiers[method]);
        verifiers[method] = IAttestationVerifier(verifier);
        emit VerifierSet(method, previous, verifier);
    }

    /// @notice Sets the maximum attestation age (1 second .. 30 days). Owner only.
    /// @param maxAge The new maximum age in seconds.
    function setMaxAttestationAge(uint64 maxAge) external onlyOwner {
        if (maxAge == 0 || maxAge > MAX_ATTESTATION_AGE_LIMIT) revert InvalidMaxAttestationAge(maxAge);
        uint64 previous = maxAttestationAge;
        maxAttestationAge = maxAge;
        emit MaxAttestationAgeSet(previous, maxAge);
    }

    /// @notice Pauses registerDeployment and heartbeat. Owner only.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses. Owner only.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ---------------------------------------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------------------------------------

    function _recordDigest(Record calldata r) private view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECORD_TYPEHASH,
                    r.deploymentId,
                    r.customer,
                    r.stackHash,
                    r.imageId,
                    r.quoteHash,
                    r.eventLogHash,
                    r.configHash,
                    r.enclaveSigner,
                    r.attestedAt
                )
            )
        );
    }

    function _checkFreshness(uint64 attestedAt) private view {
        // forge-lint: disable-next-line(block-timestamp)
        if (uint256(attestedAt) > block.timestamp + MAX_FUTURE_SKEW) {
            revert AttestationInFuture(attestedAt, block.timestamp);
        }
        // forge-lint: disable-next-line(block-timestamp)
        if (uint256(attestedAt) + maxAttestationAge < block.timestamp) {
            revert AttestationTooOld(attestedAt, block.timestamp);
        }
    }

    function _verify(uint8 method, bytes32 digest, bytes calldata evidence) private view {
        if (method == 0) revert InvalidMethod(method);
        IAttestationVerifier verifier = verifiers[method];
        if (address(verifier) == address(0)) revert VerifierNotSet(method);
        if (!verifier.verify(digest, evidence)) revert InvalidAttestation(method);
    }
}
