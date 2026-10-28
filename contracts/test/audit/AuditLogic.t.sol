// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {SealedTest} from "../utils/SealedTest.sol";

/// @notice Contract review, logic lens (logic-F1 .. logic-F10). Each test replays the auditor's PoC. Fixed findings
///         assert the fix; acknowledged findings pin the documented behavior so a change is noticed.
///         Record: sealed-platform/docs/notes/contract-review.md.
contract AuditLogicTest is SealedTest {
    function _singleton(bytes32 id) internal pure returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = id;
    }

    function _registerFor(address who, bytes32 stack, bytes32 salt, address signer) internal returns (bytes32 id) {
        IDeploymentRegistry.Record memory r = IDeploymentRegistry.Record({
            deploymentId: _deploymentId(who, stack, salt),
            customer: who,
            stackHash: stack,
            imageId: imageId,
            quoteHash: keccak256(abi.encode("q", salt)),
            eventLogHash: keccak256(abi.encode("e", salt)),
            configHash: keccak256(abi.encode("c", salt)),
            enclaveSigner: signer,
            attestedAt: uint64(block.timestamp)
        });
        _register(r);
        id = r.deploymentId;
    }

    /// logic-F1 (fixed): another deployment's payer can no longer consume the victim's (usageHash, appId).
    function test_F1_usageHashSquatting_crossDeployment() public {
        bytes32 victimDep = _deployDefault();
        address attacker = makeAddr("attacker");
        bytes32 attackerStack = keccak256("attacker-stack");
        _approve(attacker, attackerStack, _singleton(releaseA), imageId, 0);
        bytes32 attackerDep = _registerFor(attacker, attackerStack, bytes32(uint256(9)), makeAddr("attackerSigner"));

        _fund(enclaveSigner, 10_000_000);
        _fund(attacker, 1);

        bytes32 usageHash = keccak256("victim usage report digest (contains victimDep)");
        vm.prank(attacker);
        splitter.payFees(attackerDep, appA, address(token), 1, usageHash);

        vm.prank(enclaveSigner);
        splitter.payFees(victimDep, appA, address(token), 4_000_000, usageHash);
        assertEq(splitter.usagePaid(victimDep, usageHash, appA), 4_000_000);
        assertEq(splitter.usagePaid(attackerDep, usageHash, appA), 1);
    }

    /// logic-F1 (b) / funds-F-02 (fixed with topUpFees and the agent's settlement rule): a deployment's own payer
    /// can still open a leg first with a smaller amount. The amount is recorded onchain, settlement treats the leg as
    /// unpaid until usagePaid reaches the report's fee, and topUpFees pulls the shortfall on the same leg.
    function test_F1b_customerUnderpaysUsage() public {
        bytes32 dep = _deployDefault();
        _fund(customer, 1);
        _fund(enclaveSigner, 10_000_000);
        bytes32 usageHash = keccak256("enclave-signed report with fee 4_000_000 for appA");
        vm.prank(customer);
        splitter.payFees(dep, appA, address(token), 1, usageHash);
        assertEq(splitter.usagePaid(dep, usageHash, appA), 1, "shortfall visible onchain");
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageAlreadyPaid.selector, dep, usageHash, appA));
        splitter.payFees(dep, appA, address(token), 4_000_000, usageHash);
        vm.prank(enclaveSigner);
        splitter.topUpFees(dep, appA, address(token), 4_000_000, usageHash);
        assertEq(splitter.usagePaid(dep, usageHash, appA), 4_000_000, "shortfall collected on the same leg");
        assertEq(splitter.totalCredited(address(token)), 4_000_000);
    }

    /// logic-F3 (acknowledged, spec: "deployment Active"): fees for an Active deployment stay payable after its
    /// release, stack or image is revoked, so past usage can be settled. The owner stops a malicious maintainer's
    /// income with setMaintainerShare(app, 0) or setMaintainer, and a deployment with closeDeployment.
    function test_F2_feesPayableAfterReleaseAndStackRevoked() public {
        bytes32 dep = _deployDefault();
        _fund(customer, 100_000_000);

        vm.prank(owner);
        apps.revokeRelease(releaseA, "malicious bundle");
        assertFalse(registry.isStackApproved(customer, stackHash));
        assertTrue(registry.appInDeployment(dep, appA));
        vm.prank(customer);
        splitter.payFees(dep, appA, address(token), 1_000_000, keccak256("u1"));

        vm.prank(customer);
        registry.revokeStack(stackHash);
        vm.prank(customer);
        splitter.payFees(dep, appA, address(token), 1_000_000, keccak256("u2"));

        vm.prank(owner);
        platform.revokeImage(imageId, "tcb");
        vm.prank(customer);
        splitter.payFees(dep, appB, address(token), 1_000_000, keccak256("u3"));
        assertEq(splitter.credited(address(token), maintainer), 600_000);

        // The owner's lever against a malicious maintainer.
        vm.prank(owner);
        apps.setMaintainerShare(appA, 0);
        vm.prank(customer);
        splitter.payFees(dep, appA, address(token), 1_000_000, keccak256("u4"));
        assertEq(splitter.credited(address(token), maintainer), 600_000);
    }

    /// logic-F2 (fixed): the approval's release list cannot be rewritten for the same stackHash, so the release
    /// revocation holds for the running deployment and for new registrations of the same compose.
    function test_F3_releaseRevocationBypassedByReapproval() public {
        _approve(customer, stackHash, _singleton(releaseA), imageId, 0);
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        _register(r);
        bytes32 dep = r.deploymentId;

        vm.prank(owner);
        apps.revokeRelease(releaseA, "incident");
        assertFalse(registry.isStackApproved(customer, stackHash));

        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ReleasesChanged.selector, customer, stackHash));
        registry.approveStack(stackHash, _singleton(releaseB), imageId, 0);
        assertFalse(registry.isStackApproved(customer, stackHash));

        uint64 t1 = uint64(block.timestamp + 60);
        vm.warp(t1);
        bytes memory ev = _heartbeatEvidence(dep, keccak256("q2"), t1);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(dep, keccak256("q2"), t1, 1, ev);

        IDeploymentRegistry.Record memory r2 = _record(bytes32(uint256(2)));
        bytes memory ev2 = _oracleEvidence(r2);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.registerDeployment(r2, 1, ev2);

        assertTrue(registry.appInDeployment(dep, appA));
        assertFalse(registry.appInDeployment(dep, appB));
    }

    /// logic-F4: (1) acknowledged, re-approval after revokeStack restores heartbeats of deployments that were not
    /// closed (that is what un-revoke means; closeDeployment is the per-deployment kill). (2) fixed, a re-approval
    /// cannot switch the image and strand the deployments.
    function test_F4_reapprovalRevivesOldDeployments() public {
        bytes32 oldDep = _deployDefault();
        vm.prank(customer);
        registry.revokeStack(stackHash);
        _approveDefault();
        uint64 t1 = uint64(block.timestamp + 1);
        vm.warp(t1);
        registry.heartbeat(oldDep, keccak256("q2"), t1, 1, _heartbeatEvidence(oldDep, keccak256("q2"), t1));
        (IDeploymentRegistry.DeploymentStatus st,,) = registry.deploymentParties(oldDep);
        assertEq(uint8(st), uint8(IDeploymentRegistry.DeploymentStatus.Active));

        bytes32 imageB = _addImage("sealed-os", "1.1.0", false);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ImageMismatch.selector, imageB, imageId));
        registry.approveStack(stackHash, _releases2(), imageB, 0);
    }

    /// logic-F7 (acknowledged, spec + D-013): deprecating an image un-approves every stack on it at once.
    function test_F5_deprecateImageHaltsRunningDeployments() public {
        bytes32 dep = _deployDefault();
        vm.prank(owner);
        platform.deprecateImage(imageId);
        assertFalse(registry.isStackApproved(customer, stackHash));
        uint64 t1 = uint64(block.timestamp + 1);
        vm.warp(t1);
        bytes memory ev = _heartbeatEvidence(dep, keccak256("q2"), t1);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(dep, keccak256("q2"), t1, 1, ev);
    }

    /// logic-F6 (fixed): an approval that contains a since-deprecated release can be restored after revokeStack.
    function test_F6_cannotRestoreApprovalWithDeprecatedRelease() public {
        bytes32 dep = _deployDefault();
        vm.prank(owner);
        apps.deprecateRelease(releaseA);
        assertTrue(registry.isStackApproved(customer, stackHash));
        vm.prank(customer);
        registry.revokeStack(stackHash);
        _approveDefault();
        assertTrue(registry.isStackApproved(customer, stackHash));
        uint64 t1 = uint64(block.timestamp + 1);
        vm.warp(t1);
        registry.heartbeat(dep, keccak256("q2"), t1, 1, _heartbeatEvidence(dep, keccak256("q2"), t1));
    }

    /// logic-F5 (fixed): revoked measurements and bundles cannot come back under a new id.
    function test_F7_revokedContentReaddedUnderNewId() public {
        string memory label = "sealed-os@1.0.0";
        bytes32 mh = platform.getImage(imageId).measurementsHash;
        assertEq(platform.imageByMeasurements(mh), imageId);
        vm.startPrank(owner);
        platform.revokeImage(imageId, "vulnerable");
        bytes32 again = keccak256("same measurements, new id");
        bytes memory m0 = _measurementOf(label, 0);
        bytes memory m1 = _measurementOf(label, 1);
        bytes memory m2 = _measurementOf(label, 2);
        bytes memory m3 = _measurementOf(label, 3);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.MeasurementsAlreadyRegistered.selector, mh, imageId));
        platform.addImage(again, "sealed-os", "1.0.0-r", m0, m1, m2, m3, false, "");
        vm.stopPrank();

        vm.prank(owner);
        apps.revokeRelease(releaseA, "malicious");
        bytes32 bundle = apps.getRelease(releaseA).bundleHash;
        assertEq(apps.releaseByBundle(appA, bundle), releaseA);
        vm.prank(ops);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.BundleAlreadyPublished.selector, appA, bundle, releaseA));
        apps.publishRelease(appA, "1.0.1", bundle, bytes32(0), bytes32(0), "", "");
    }

    /// logic-F8 (fixed in part): a signed record from before the current approval cannot be registered later.
    function test_F8_staleRecordAfterReapproval() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(5)));
        bytes memory ev = _oracleEvidence(r);
        vm.prank(customer);
        registry.revokeStack(stackHash);
        vm.warp(block.timestamp + 1 hours);
        _approveDefault();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                DeploymentRegistry.AttestedBeforeApproval.selector, r.attestedAt, uint64(block.timestamp)
            )
        );
        registry.registerDeployment(r, 1, ev);
    }

    /// logic-F9 (fixed): FeeSplitter refuses an AppRegistry other than the registry's.
    function test_F9_appRegistryMustMatch() public {
        AppRegistry otherApps = new AppRegistry(owner);
        vm.expectRevert(
            abi.encodeWithSelector(FeeSplitter.AppRegistryMismatch.selector, address(apps), address(otherApps))
        );
        new FeeSplitter(owner, registry, otherApps, address(token), treasury, 1, 2);
    }
}
