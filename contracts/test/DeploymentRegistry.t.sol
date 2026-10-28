// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {AppRegistry} from "../src/AppRegistry.sol";
import {DeploymentRegistry} from "../src/DeploymentRegistry.sol";
import {PlatformRegistry} from "../src/PlatformRegistry.sol";
import {IAppRegistry} from "../src/interfaces/IAppRegistry.sol";
import {IDeploymentRegistry} from "../src/interfaces/IDeploymentRegistry.sol";
import {IPlatformRegistry} from "../src/interfaces/IPlatformRegistry.sol";
import {OwnableNoRenounce} from "../src/utils/OwnableNoRenounce.sol";
import {MockVerifier, RevertingVerifier} from "./mocks/MockVerifier.sol";
import {SealedTest} from "./utils/SealedTest.sol";

contract DeploymentRegistryTest is SealedTest {
    event StackApproved(
        address indexed customer,
        bytes32 indexed stackHash,
        bytes32 indexed imageId,
        bytes32[] releaseIds,
        uint64 expiry
    );
    event StackRevoked(address indexed customer, bytes32 indexed stackHash);
    event DeploymentRegistered(
        bytes32 indexed deploymentId,
        address indexed customer,
        bytes32 indexed stackHash,
        IDeploymentRegistry.Record record,
        uint8 method,
        address submitter
    );
    event DeploymentHeartbeat(bytes32 indexed deploymentId, bytes32 quoteHash, uint64 attestedAt, uint8 method);
    event DeploymentClosed(bytes32 indexed deploymentId, address indexed closedBy);
    event VerifierSet(uint8 indexed method, address indexed previousVerifier, address indexed newVerifier);
    event MaxAttestationAgeSet(uint64 previousMaxAge, uint64 newMaxAge);

    bytes32 internal constant SALT = bytes32(uint256(1));

    function _one(bytes32 id) internal pure returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = id;
    }

    function _manyReleases(uint256 n) internal returns (bytes32[] memory ids) {
        ids = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            ids[i] = _publish(appA, string.concat("v", vm.toString(i + 10)));
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Constructor and metadata
    // ------------------------------------------------------------------------------------------------------

    function test_metadata() public view {
        assertEq(registry.VERSION(), "1.0.0");
        assertEq(registry.METHOD_ORACLE_SIG_V1(), 1);
        assertEq(registry.METHOD_ZK_DCAP_V1(), 2);
        assertEq(registry.MAX_RELEASES_PER_STACK(), 16);
        assertEq(registry.MAX_FUTURE_SKEW(), 5 minutes);
        assertEq(registry.maxAttestationAge(), 1 days);
        assertEq(address(registry.platformRegistry()), address(platform));
        assertEq(address(registry.appRegistry()), address(apps));
        assertEq(address(registry.verifiers(1)), address(oracleVerifier));
        assertEq(address(registry.verifiers(2)), address(0));
        assertEq(registry.owner(), owner);
        assertFalse(registry.paused());
        assertEq(registry.deploymentCount(), 0);
    }

    function test_constructor_emitsMaxAge() public {
        vm.expectEmit();
        emit MaxAttestationAgeSet(0, 1 days);
        new DeploymentRegistry(owner, platform, apps);
    }

    function test_constructor_revertsOnZeroPlatform() public {
        vm.expectRevert(DeploymentRegistry.ZeroAddress.selector);
        new DeploymentRegistry(owner, IPlatformRegistry(address(0)), apps);
    }

    function test_constructor_revertsOnZeroApps() public {
        vm.expectRevert(DeploymentRegistry.ZeroAddress.selector);
        new DeploymentRegistry(owner, platform, IAppRegistry(address(0)));
    }

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new DeploymentRegistry(address(0), platform, apps);
    }

    function test_renounceOwnership_disabled() public {
        vm.prank(owner);
        vm.expectRevert(OwnableNoRenounce.RenounceOwnershipDisabled.selector);
        registry.renounceOwnership();
    }

    // ------------------------------------------------------------------------------------------------------
    // approveStack
    // ------------------------------------------------------------------------------------------------------

    function test_approveStack() public {
        bytes32[] memory ids = _releases2();
        uint64 expiry = uint64(block.timestamp + 30 days);
        vm.expectEmit(address(registry));
        emit StackApproved(customer, stackHash, imageId, ids, expiry);
        _approve(customer, stackHash, ids, imageId, expiry);

        (bytes32[] memory got, bytes32 img, uint64 exp, bool revoked, uint64 approvedAt) =
            registry.getStackApproval(customer, stackHash);
        assertEq(got.length, 2);
        assertEq(got[0], releaseA);
        assertEq(got[1], releaseB);
        assertEq(img, imageId);
        assertEq(exp, expiry);
        assertFalse(revoked);
        assertEq(approvedAt, block.timestamp);
        assertTrue(registry.isStackApproved(customer, stackHash));
        assertFalse(registry.isStackApproved(stranger, stackHash), "approvals are per customer");
    }

    function test_approveStack_noExpiry() public {
        _approveDefault();
        vm.warp(block.timestamp + 3650 days);
        assertTrue(registry.isStackApproved(customer, stackHash));
    }

    function test_approveStack_sixteenReleases() public {
        bytes32[] memory ids = _manyReleases(16);
        _approve(customer, stackHash, ids, imageId, 0);
        assertTrue(registry.isStackApproved(customer, stackHash));
    }

    function test_approveStack_revertsOnSeventeenReleases() public {
        bytes32[] memory ids = _manyReleases(17);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidReleaseCount.selector, 17));
        registry.approveStack(stackHash, ids, imageId, 0);
    }

    function test_approveStack_revertsOnNoReleases() public {
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidReleaseCount.selector, 0));
        registry.approveStack(stackHash, new bytes32[](0), imageId, 0);
    }

    function test_approveStack_revertsOnZeroStackHash() public {
        vm.prank(customer);
        vm.expectRevert(DeploymentRegistry.ZeroStackHash.selector);
        registry.approveStack(bytes32(0), _releases2(), imageId, 0);
    }

    function test_approveStack_revertsOnDuplicateRelease() public {
        bytes32[] memory ids = new bytes32[](3);
        ids[0] = releaseA;
        ids[1] = releaseB;
        ids[2] = releaseA;
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DuplicateRelease.selector, releaseA));
        registry.approveStack(stackHash, ids, imageId, 0);
    }

    function test_approveStack_revertsOnUnknownRelease() public {
        bytes32 unknown = keccak256("nope");
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ReleaseNotApprovable.selector, unknown));
        registry.approveStack(stackHash, _one(unknown), imageId, 0);
    }

    function test_approveStack_revertsOnDeprecatedRelease() public {
        vm.prank(owner);
        apps.deprecateRelease(releaseB);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ReleaseNotApprovable.selector, releaseB));
        registry.approveStack(stackHash, _releases2(), imageId, 0);
    }

    function test_approveStack_revertsOnRevokedRelease() public {
        vm.prank(owner);
        apps.revokeRelease(releaseA, "x");
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ReleaseNotApprovable.selector, releaseA));
        registry.approveStack(stackHash, _releases2(), imageId, 0);
    }

    function test_approveStack_revertsOnUnknownImage() public {
        bytes32 unknown = keccak256("img");
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ImageNotApproved.selector, unknown));
        registry.approveStack(stackHash, _releases2(), unknown, 0);
    }

    function test_approveStack_revertsOnDebugImage() public {
        bytes32 debugImage = _addImage("sealed-os-debug", "1.0.0", true);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ImageNotApproved.selector, debugImage));
        registry.approveStack(stackHash, _releases2(), debugImage, 0);
    }

    function test_approveStack_revertsOnDeprecatedImage() public {
        vm.prank(owner);
        platform.deprecateImage(imageId);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ImageNotApproved.selector, imageId));
        registry.approveStack(stackHash, _releases2(), imageId, 0);
    }

    function test_approveStack_revertsOnPastOrPresentExpiry() public {
        vm.startPrank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidExpiry.selector, uint64(block.timestamp)));
        registry.approveStack(stackHash, _releases2(), imageId, uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidExpiry.selector, uint64(block.timestamp - 1)));
        registry.approveStack(stackHash, _releases2(), imageId, uint64(block.timestamp - 1));
        vm.stopPrank();
    }

    function test_approveStack_reapprovalOverwritesAndUnrevokes() public {
        _approveDefault();
        vm.prank(customer);
        registry.revokeStack(stackHash);
        assertFalse(registry.isStackApproved(customer, stackHash));

        bytes32 imageB = _addImage("sealed-os", "1.1.0", false);
        uint64 expiry = uint64(block.timestamp + 1 days);
        vm.warp(block.timestamp + 10);
        vm.expectEmit(address(registry));
        emit StackApproved(customer, stackHash, imageB, _one(releaseB), expiry);
        _approve(customer, stackHash, _one(releaseB), imageB, expiry);

        (bytes32[] memory got, bytes32 img, uint64 exp, bool revoked, uint64 approvedAt) =
            registry.getStackApproval(customer, stackHash);
        assertEq(got.length, 1);
        assertEq(got[0], releaseB);
        assertEq(img, imageB);
        assertEq(exp, expiry);
        assertFalse(revoked);
        assertEq(approvedAt, block.timestamp);
        assertTrue(registry.isStackApproved(customer, stackHash));
    }

    function test_getStackApproval_emptyWhenNone() public view {
        (bytes32[] memory got, bytes32 img, uint64 exp, bool revoked, uint64 approvedAt) =
            registry.getStackApproval(customer, stackHash);
        assertEq(got.length, 0);
        assertEq(img, bytes32(0));
        assertEq(exp, 0);
        assertFalse(revoked);
        assertEq(approvedAt, 0);
    }

    // ------------------------------------------------------------------------------------------------------
    // revokeStack and isStackApproved
    // ------------------------------------------------------------------------------------------------------

    function test_revokeStack() public {
        _approveDefault();
        vm.expectEmit(address(registry));
        emit StackRevoked(customer, stackHash);
        vm.prank(customer);
        registry.revokeStack(stackHash);
        assertFalse(registry.isStackApproved(customer, stackHash));
        (,,, bool revoked,) = registry.getStackApproval(customer, stackHash);
        assertTrue(revoked);
    }

    function test_revokeStack_revertsWhenNotFound() public {
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ApprovalNotFound.selector, customer, stackHash));
        registry.revokeStack(stackHash);
    }

    function test_revokeStack_onlyOwnApproval() public {
        _approveDefault();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ApprovalNotFound.selector, stranger, stackHash));
        registry.revokeStack(stackHash);
        assertTrue(registry.isStackApproved(customer, stackHash));
    }

    function test_revokeStack_revertsWhenAlreadyRevoked() public {
        _approveDefault();
        vm.startPrank(customer);
        registry.revokeStack(stackHash);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ApprovalAlreadyRevoked.selector, customer, stackHash));
        registry.revokeStack(stackHash);
        vm.stopPrank();
    }

    function test_isStackApproved_unknownIsFalse() public view {
        assertFalse(registry.isStackApproved(customer, stackHash));
    }

    function test_isStackApproved_falseAtAndAfterExpiry() public {
        uint64 expiry = uint64(block.timestamp + 100);
        _approve(customer, stackHash, _releases2(), imageId, expiry);
        vm.warp(expiry - 1);
        assertTrue(registry.isStackApproved(customer, stackHash));
        vm.warp(expiry);
        assertFalse(registry.isStackApproved(customer, stackHash));
        vm.warp(expiry + 1000);
        assertFalse(registry.isStackApproved(customer, stackHash));
    }

    function test_isStackApproved_falseAfterReleaseRevoked() public {
        _approveDefault();
        vm.prank(owner);
        apps.revokeRelease(releaseB, "CVE");
        assertFalse(registry.isStackApproved(customer, stackHash));
    }

    function test_isStackApproved_trueAfterReleaseDeprecated() public {
        _approveDefault();
        vm.prank(owner);
        apps.deprecateRelease(releaseB);
        assertTrue(registry.isStackApproved(customer, stackHash), "D-013: deprecated keeps working");
    }

    function test_isStackApproved_falseAfterImageRevoked() public {
        _approveDefault();
        vm.prank(owner);
        platform.revokeImage(imageId, "CVE");
        assertFalse(registry.isStackApproved(customer, stackHash));
    }

    function test_isStackApproved_falseAfterImageDeprecated() public {
        _approveDefault();
        vm.prank(owner);
        platform.deprecateImage(imageId);
        assertFalse(registry.isStackApproved(customer, stackHash), "images follow the spec literally");
    }

    // ------------------------------------------------------------------------------------------------------
    // registerDeployment
    // ------------------------------------------------------------------------------------------------------

    function test_registerDeployment() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);

        vm.expectEmit(address(registry));
        emit DeploymentRegistered(r.deploymentId, customer, stackHash, r, 1, stranger);
        vm.prank(stranger); // anyone may submit
        registry.registerDeployment(r, 1, evidence);

        IDeploymentRegistry.Deployment memory d = registry.getDeployment(r.deploymentId);
        assertEq(d.deploymentId, r.deploymentId);
        assertEq(d.customer, customer);
        assertEq(d.stackHash, stackHash);
        assertEq(d.imageId, imageId);
        assertEq(d.quoteHash, r.quoteHash);
        assertEq(d.eventLogHash, r.eventLogHash);
        assertEq(d.configHash, r.configHash);
        assertEq(d.enclaveSigner, enclaveSigner);
        assertEq(d.attestedAt, r.attestedAt);
        assertEq(d.lastAttestedAt, r.attestedAt);
        assertEq(d.registeredAt, block.timestamp);
        assertEq(d.closedAt, 0);
        assertEq(d.method, 1);
        assertEq(d.lastMethod, 1);
        assertEq(uint8(d.status), uint8(IDeploymentRegistry.DeploymentStatus.Active));
        assertEq(registry.deploymentCount(), 1);

        (IDeploymentRegistry.DeploymentStatus status, address c, address signer) =
            registry.deploymentParties(r.deploymentId);
        assertEq(uint8(status), uint8(IDeploymentRegistry.DeploymentStatus.Active));
        assertEq(c, customer);
        assertEq(signer, enclaveSigner);
    }

    function test_registerDeployment_revertsWhenPaused() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.prank(owner);
        registry.pause();
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnZeroId() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.deploymentId = bytes32(0);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(DeploymentRegistry.ZeroDeploymentId.selector);
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnDuplicate() public {
        bytes32 id = _deployDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentAlreadyRegistered.selector, id));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnClosedIdReuse() public {
        bytes32 id = _deployDefault();
        vm.prank(customer);
        registry.closeDeployment(id);
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentAlreadyRegistered.selector, id));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnZeroCustomer() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.customer = address(0);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(DeploymentRegistry.ZeroAddress.selector);
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnZeroEnclaveSigner() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.enclaveSigner = address(0);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(DeploymentRegistry.ZeroAddress.selector);
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsWhenStackNotApproved() public {
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsForOtherCustomersApproval() public {
        _approve(stranger, stackHash, _releases2(), imageId, 0);
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsWhenApprovalRevoked() public {
        _approveDefault();
        vm.prank(customer);
        registry.revokeStack(stackHash);
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnImageMismatch() public {
        _approveDefault();
        bytes32 other = _addImage("sealed-os", "9.9.9", false);
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.imageId = other;
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ImageMismatch.selector, other, imageId));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_acceptsMaxFutureSkew() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.attestedAt = uint64(block.timestamp + 5 minutes);
        _register(r);
        assertEq(registry.getDeployment(r.deploymentId).attestedAt, r.attestedAt);
    }

    function test_registerDeployment_revertsBeyondFutureSkew() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.attestedAt = uint64(block.timestamp + 5 minutes + 1);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(
            abi.encodeWithSelector(DeploymentRegistry.AttestationInFuture.selector, r.attestedAt, block.timestamp)
        );
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_acceptsExactlyMaxAge() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.attestedAt = uint64(block.timestamp - 1 days);
        _register(r);
    }

    function test_registerDeployment_revertsWhenTooOld() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.attestedAt = uint64(block.timestamp - 1 days - 1);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(
            abi.encodeWithSelector(DeploymentRegistry.AttestationTooOld.selector, r.attestedAt, block.timestamp)
        );
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnMethodZero() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidMethod.selector, 0));
        registry.registerDeployment(r, 0, evidence);
    }

    function test_registerDeployment_revertsWhenVerifierNotSet() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.VerifierNotSet.selector, 7));
        registry.registerDeployment(r, 7, evidence);
    }

    function test_registerDeployment_revertsOnSignatureByNonOracle() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _sign(customerKey, registry.recordDigest(r));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnTamperedRecord() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        r.configHash = keccak256("tampered config");
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsOnTamperedEnclaveSigner() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        r.enclaveSigner = stranger;
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_rejectsHeartbeatSignatureAsRecord() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _heartbeatEvidence(r.deploymentId, r.quoteHash, r.attestedAt);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_registerDeployment_revertsWhenVerifierReverts() public {
        _approveDefault();
        RevertingVerifier bad = new RevertingVerifier();
        vm.prank(owner);
        registry.setVerifier(9, address(bad));
        IDeploymentRegistry.Record memory r = _record(SALT);
        vm.expectRevert(RevertingVerifier.Boom.selector);
        registry.registerDeployment(r, 9, "");
    }

    function test_registerDeployment_multipleDeploymentsOfOneStack() public {
        _approveDefault();
        _register(_record(bytes32(uint256(1))));
        _register(_record(bytes32(uint256(2))));
        assertEq(registry.deploymentCount(), 2);
    }

    // ------------------------------------------------------------------------------------------------------
    // heartbeat
    // ------------------------------------------------------------------------------------------------------

    function _beat(bytes32 id, bytes32 quoteHash, uint64 attestedAt) internal {
        bytes memory evidence = _heartbeatEvidence(id, quoteHash, attestedAt);
        registry.heartbeat(id, quoteHash, attestedAt, 1, evidence);
    }

    function test_heartbeat() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 1 hours);
        bytes32 q = keccak256("quote-2");
        uint64 t = uint64(block.timestamp);
        bytes memory evidence = _heartbeatEvidence(id, q, t);
        vm.expectEmit(address(registry));
        emit DeploymentHeartbeat(id, q, t, 1);
        vm.prank(stranger);
        registry.heartbeat(id, q, t, 1, evidence);

        IDeploymentRegistry.Deployment memory d = registry.getDeployment(id);
        assertEq(d.quoteHash, q);
        assertEq(d.lastAttestedAt, t);
        assertEq(d.attestedAt, START_TIME, "registration attestedAt is kept");
        assertEq(d.lastMethod, 1);
    }

    function test_heartbeat_revertsWhenPaused() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), uint64(block.timestamp));
        vm.prank(owner);
        registry.pause();
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 1, evidence);
    }

    function test_heartbeat_revertsWhenUnknown() public {
        bytes32 id = keccak256("unknown");
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentNotActive.selector, id));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 1, "");
    }

    function test_heartbeat_revertsWhenClosed() public {
        bytes32 id = _deployDefault();
        vm.prank(customer);
        registry.closeDeployment(id);
        vm.warp(block.timestamp + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentNotActive.selector, id));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 1, evidence);
    }

    function test_heartbeat_revertsWhenStackRevoked() public {
        bytes32 id = _deployDefault();
        vm.prank(customer);
        registry.revokeStack(stackHash);
        vm.warp(block.timestamp + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 1, evidence);
    }

    function test_heartbeat_revertsWhenReleaseRevoked() public {
        bytes32 id = _deployDefault();
        vm.prank(owner);
        apps.revokeRelease(releaseA, "CVE");
        vm.warp(block.timestamp + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 1, evidence);
    }

    function test_heartbeat_worksWhenReleaseDeprecated() public {
        bytes32 id = _deployDefault();
        vm.prank(owner);
        apps.deprecateRelease(releaseA);
        vm.warp(block.timestamp + 1);
        _beat(id, keccak256("q"), uint64(block.timestamp));
    }

    function test_heartbeat_revertsWhenImageRevoked() public {
        bytes32 id = _deployDefault();
        vm.prank(owner);
        platform.revokeImage(imageId, "CVE");
        vm.warp(block.timestamp + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 1, evidence);
    }

    function test_heartbeat_revertsWhenApprovalExpired() public {
        _approve(customer, stackHash, _releases2(), imageId, uint64(block.timestamp + 1 hours));
        IDeploymentRegistry.Record memory r = _record(SALT);
        _register(r);
        vm.warp(block.timestamp + 1 hours);
        bytes memory evidence = _heartbeatEvidence(r.deploymentId, bytes32(0), uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(r.deploymentId, bytes32(0), uint64(block.timestamp), 1, evidence);
    }

    function test_heartbeat_revertsWhenApprovalNowNamesOtherImage() public {
        bytes32 id = _deployDefault();
        bytes32 imageB = _addImage("sealed-os", "1.1.0", false);
        _approve(customer, stackHash, _releases2(), imageB, 0);
        vm.prank(owner);
        platform.revokeImage(imageId, "CVE");
        vm.warp(block.timestamp + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ImageMismatch.selector, imageId, imageB));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 1, evidence);
    }

    function test_heartbeat_revertsWhenNotAfterLast() public {
        bytes32 id = _deployDefault();
        uint64 last = uint64(block.timestamp);
        bytes memory same = _heartbeatEvidence(id, bytes32(0), last);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StaleHeartbeat.selector, last, last));
        registry.heartbeat(id, bytes32(0), last, 1, same);
        bytes memory older = _heartbeatEvidence(id, bytes32(0), last - 1);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StaleHeartbeat.selector, last - 1, last));
        registry.heartbeat(id, bytes32(0), last - 1, 1, older);
    }

    function test_heartbeat_replayRejected() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 60);
        uint64 t = uint64(block.timestamp);
        bytes memory evidence = _heartbeatEvidence(id, keccak256("q"), t);
        registry.heartbeat(id, keccak256("q"), t, 1, evidence);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StaleHeartbeat.selector, t, t));
        registry.heartbeat(id, keccak256("q"), t, 1, evidence);
    }

    function test_heartbeat_revertsBeyondFutureSkew() public {
        bytes32 id = _deployDefault();
        uint64 t = uint64(block.timestamp + 5 minutes + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), t);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.AttestationInFuture.selector, t, block.timestamp));
        registry.heartbeat(id, bytes32(0), t, 1, evidence);
    }

    function test_heartbeat_revertsWhenTooOld() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 3 days);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 t = uint64(START_TIME + 1);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), t);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.AttestationTooOld.selector, t, block.timestamp));
        registry.heartbeat(id, bytes32(0), t, 1, evidence);
    }

    function test_heartbeat_revertsOnBadSignature() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 1);
        uint64 t = uint64(block.timestamp);
        bytes memory evidence = _sign(enclaveSignerKey, registry.heartbeatDigest(id, bytes32(0), t));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.heartbeat(id, bytes32(0), t, 1, evidence);
    }

    function test_heartbeat_revertsOnSignatureForOtherQuote() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 1);
        uint64 t = uint64(block.timestamp);
        bytes memory evidence = _heartbeatEvidence(id, keccak256("q1"), t);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.heartbeat(id, keccak256("q2"), t, 1, evidence);
    }

    function test_heartbeat_revertsWhenVerifierNotSet() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 1);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.VerifierNotSet.selector, 3));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 3, "");
    }

    function test_heartbeat_revertsOnMethodZero() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 1);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidMethod.selector, 0));
        registry.heartbeat(id, bytes32(0), uint64(block.timestamp), 0, "");
    }

    function test_heartbeat_respectsMaxAttestationAgeChange() public {
        bytes32 id = _deployDefault();
        vm.prank(owner);
        registry.setMaxAttestationAge(10 minutes);
        vm.warp(block.timestamp + 1 hours);
        uint64 t = uint64(block.timestamp - 11 minutes);
        bytes memory evidence = _heartbeatEvidence(id, bytes32(0), t);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.AttestationTooOld.selector, t, block.timestamp));
        registry.heartbeat(id, bytes32(0), t, 1, evidence);
        _beat(id, bytes32(0), uint64(block.timestamp - 10 minutes));
    }

    // ------------------------------------------------------------------------------------------------------
    // closeDeployment
    // ------------------------------------------------------------------------------------------------------

    function test_closeDeployment_byCustomer() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 5);
        vm.expectEmit(address(registry));
        emit DeploymentClosed(id, customer);
        vm.prank(customer);
        registry.closeDeployment(id);
        IDeploymentRegistry.Deployment memory d = registry.getDeployment(id);
        assertEq(uint8(d.status), uint8(IDeploymentRegistry.DeploymentStatus.Closed));
        assertEq(d.closedAt, block.timestamp);
    }

    function test_closeDeployment_byOwner() public {
        bytes32 id = _deployDefault();
        vm.expectEmit(address(registry));
        emit DeploymentClosed(id, owner);
        vm.prank(owner);
        registry.closeDeployment(id);
    }

    function test_closeDeployment_worksWhilePaused() public {
        bytes32 id = _deployDefault();
        vm.prank(owner);
        registry.pause();
        vm.prank(customer);
        registry.closeDeployment(id);
        assertEq(uint8(registry.getDeployment(id).status), uint8(IDeploymentRegistry.DeploymentStatus.Closed));
    }

    function test_closeDeployment_revertsForStranger() public {
        bytes32 id = _deployDefault();
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.NotCustomerOrOwner.selector, enclaveSigner));
        registry.closeDeployment(id);
    }

    function test_closeDeployment_revertsWhenUnknown() public {
        bytes32 id = keccak256("unknown");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentNotFound.selector, id));
        registry.closeDeployment(id);
    }

    function test_closeDeployment_isTerminal() public {
        bytes32 id = _deployDefault();
        vm.startPrank(customer);
        registry.closeDeployment(id);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentNotActive.selector, id));
        registry.closeDeployment(id);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------------------------------------------
    // appInDeployment / getDeployment
    // ------------------------------------------------------------------------------------------------------

    function test_appInDeployment() public {
        bytes32 id = _deployDefault();
        assertTrue(registry.appInDeployment(id, appA));
        assertTrue(registry.appInDeployment(id, appB));
        bytes32 appC = _registerApp("scraper", 0);
        assertFalse(registry.appInDeployment(id, appC));
        assertFalse(registry.appInDeployment(id, bytes32(0)));
        assertFalse(registry.appInDeployment(keccak256("unknown"), appA));
    }

    function test_appInDeployment_trueAfterClose() public {
        bytes32 id = _deployDefault();
        vm.prank(customer);
        registry.closeDeployment(id);
        assertTrue(registry.appInDeployment(id, appA), "deployment still exists");
    }

    function test_appInDeployment_followsReapproval() public {
        bytes32 id = _deployDefault();
        _approve(customer, stackHash, _one(releaseA), imageId, 0);
        assertTrue(registry.appInDeployment(id, appA));
        assertFalse(registry.appInDeployment(id, appB));
    }

    function test_getDeployment_revertsWhenUnknown() public {
        bytes32 id = keccak256("unknown");
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentNotFound.selector, id));
        registry.getDeployment(id);
    }

    function test_deploymentParties_unknown() public view {
        (IDeploymentRegistry.DeploymentStatus status, address c, address s) =
            registry.deploymentParties(keccak256("unknown"));
        assertEq(uint8(status), 0);
        assertEq(c, address(0));
        assertEq(s, address(0));
    }

    // ------------------------------------------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------------------------------------------

    function test_setVerifier() public {
        MockVerifier mock = new MockVerifier();
        vm.expectEmit(address(registry));
        emit VerifierSet(5, address(0), address(mock));
        vm.prank(owner);
        registry.setVerifier(5, address(mock));
        assertEq(address(registry.verifiers(5)), address(mock));

        vm.expectEmit(address(registry));
        emit VerifierSet(5, address(mock), address(0));
        vm.prank(owner);
        registry.setVerifier(5, address(0));
        assertEq(address(registry.verifiers(5)), address(0));
    }

    function test_setVerifier_replaceMethodOne() public {
        MockVerifier mock = new MockVerifier();
        vm.expectEmit(address(registry));
        emit VerifierSet(1, address(oracleVerifier), address(mock));
        vm.prank(owner);
        registry.setVerifier(1, address(mock));
        _approveDefault();
        registry.registerDeployment(_record(SALT), 1, "anything");
    }

    function test_setVerifier_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        registry.setVerifier(2, address(oracleVerifier));
    }

    function test_setVerifier_revertsOnMethodZero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidMethod.selector, 0));
        registry.setVerifier(0, address(oracleVerifier));
    }

    function test_setVerifier_revertsOnEoa() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.VerifierNotContract.selector, stranger));
        registry.setVerifier(2, stranger);
    }

    function test_unsetVerifierBlocksMethod() public {
        _approveDefault();
        vm.prank(owner);
        registry.setVerifier(1, address(0));
        IDeploymentRegistry.Record memory r = _record(SALT);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.VerifierNotSet.selector, 1));
        registry.registerDeployment(r, 1, evidence);
    }

    function test_setMaxAttestationAge() public {
        vm.expectEmit(address(registry));
        emit MaxAttestationAgeSet(1 days, 2 hours);
        vm.prank(owner);
        registry.setMaxAttestationAge(2 hours);
        assertEq(registry.maxAttestationAge(), 2 hours);
        vm.prank(owner);
        registry.setMaxAttestationAge(30 days);
        assertEq(registry.maxAttestationAge(), 30 days);
    }

    function test_setMaxAttestationAge_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidMaxAttestationAge.selector, 0));
        registry.setMaxAttestationAge(0);
    }

    function test_setMaxAttestationAge_revertsAboveLimit() public {
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(DeploymentRegistry.InvalidMaxAttestationAge.selector, uint64(30 days + 1))
        );
        registry.setMaxAttestationAge(30 days + 1);
    }

    function test_setMaxAttestationAge_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        registry.setMaxAttestationAge(1 hours);
    }

    function test_setMaxAttestationAge_appliesToRegistration() public {
        _approveDefault();
        vm.prank(owner);
        registry.setMaxAttestationAge(1 hours);
        IDeploymentRegistry.Record memory r = _record(SALT);
        r.attestedAt = uint64(block.timestamp - 1 hours - 1);
        bytes memory evidence = _oracleEvidence(r);
        vm.expectRevert(
            abi.encodeWithSelector(DeploymentRegistry.AttestationTooOld.selector, r.attestedAt, block.timestamp)
        );
        registry.registerDeployment(r, 1, evidence);
    }

    function test_pauseUnpause() public {
        vm.startPrank(owner);
        vm.expectEmit(address(registry));
        emit Pausable.Paused(owner);
        registry.pause();
        assertTrue(registry.paused());
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.pause();
        vm.expectEmit(address(registry));
        emit Pausable.Unpaused(owner);
        registry.unpause();
        assertFalse(registry.paused());
        vm.expectRevert(Pausable.ExpectedPause.selector);
        registry.unpause();
        vm.stopPrank();
    }

    function test_pause_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        registry.pause();
    }

    function test_unpause_revertsForNonOwner() public {
        vm.prank(owner);
        registry.pause();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        registry.unpause();
    }

    function test_pauseDoesNotBlockApprovals() public {
        vm.prank(owner);
        registry.pause();
        _approveDefault();
        vm.prank(customer);
        registry.revokeStack(stackHash);
    }

    // ------------------------------------------------------------------------------------------------------
    // Fuzz
    // ------------------------------------------------------------------------------------------------------

    function testFuzz_freshnessWindow(uint64 offset, bool future) public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(SALT);
        offset = uint64(bound(offset, 0, 3 days));
        r.attestedAt = future ? uint64(block.timestamp + offset) : uint64(block.timestamp - offset);
        bytes memory evidence = _oracleEvidence(r);
        if (future && offset > 5 minutes) {
            vm.expectRevert(
                abi.encodeWithSelector(DeploymentRegistry.AttestationInFuture.selector, r.attestedAt, block.timestamp)
            );
        } else if (!future && offset > 1 days) {
            vm.expectRevert(
                abi.encodeWithSelector(DeploymentRegistry.AttestationTooOld.selector, r.attestedAt, block.timestamp)
            );
        }
        registry.registerDeployment(r, 1, evidence);
    }

    function testFuzz_approveStack_releaseCount(uint8 n) public {
        n = uint8(bound(n, 0, 20));
        bytes32[] memory ids = _manyReleases(n);
        vm.prank(customer);
        if (n == 0 || n > 16) {
            vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidReleaseCount.selector, uint256(n)));
        }
        registry.approveStack(stackHash, ids, imageId, 0);
    }
}
