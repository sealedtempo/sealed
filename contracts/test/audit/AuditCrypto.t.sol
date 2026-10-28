// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {IAttestationVerifier} from "../../src/IAttestationVerifier.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {SealedTest} from "../utils/SealedTest.sol";

/// @notice A plausible method-2 verifier that checks only what the INTERFACES.md section 3 "evidence" report_data
///         commits to: sha256(tag || stackHash || configHash || enclaveSigner || nonce2). The quote itself is modelled
///         as already proven. It cannot check customer, deploymentId or attestedAt because nothing in the quote
///         commits to them. Kept as a negative example: method 2 must not be enabled with a verifier like this
///         (crypto-SEAL-03).
contract ReportDataZkVerifier is IAttestationVerifier {
    DeploymentRegistry public immutable registry;

    constructor(DeploymentRegistry r) {
        registry = r;
    }

    function verify(bytes32 digest, bytes calldata evidence) external view returns (bool) {
        (IDeploymentRegistry.Record memory r, bytes32 provenQuoteHash, bytes32 provenReportData, bytes32 nonce2) =
            abi.decode(evidence, (IDeploymentRegistry.Record, bytes32, bytes32, bytes32));
        if (registry.recordDigest(r) != digest) return false;
        if (provenQuoteHash != r.quoteHash) return false;
        bytes32 expected =
            sha256(abi.encodePacked("sealed/evidence/v1", r.stackHash, r.configHash, r.enclaveSigner, nonce2));
        return provenReportData == expected;
    }
}

/// @notice Contract review, attestation / signature lens (crypto-SEAL-01 .. crypto-SEAL-09). Each test replays the
///         auditor's PoC. Fixed findings assert the fix; acknowledged findings pin the documented behavior.
///         Record: sealed-platform/docs/notes/contract-review.md.
contract AuditCryptoTest is SealedTest {
    address internal attacker = makeAddr("attacker");
    address internal attackerEnclave = makeAddr("attackerEnclave");

    /// crypto-SEAL-02 (fixed): usage keys are per deployment.
    function test_usageHashSquatAcrossDeployments() public {
        bytes32 victimId = _deployDefault();

        bytes32 attackerStack = keccak256("attacker-stack");
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = releaseA;
        _approve(attacker, attackerStack, ids, imageId, 0);
        IDeploymentRegistry.Record memory ar = IDeploymentRegistry.Record({
            deploymentId: _deploymentId(attacker, attackerStack, bytes32(uint256(9))),
            customer: attacker,
            stackHash: attackerStack,
            imageId: imageId,
            quoteHash: keccak256("aq"),
            eventLogHash: keccak256("ae"),
            configHash: keccak256("ac"),
            enclaveSigner: attackerEnclave,
            attestedAt: uint64(block.timestamp)
        });
        _register(ar);

        bytes32 usageHash = keccak256("victim-usage-report");
        _fund(attacker, 1);
        vm.prank(attacker);
        splitter.payFees(ar.deploymentId, appA, address(token), 1, usageHash);

        _fund(enclaveSigner, 5_000_000);
        vm.prank(enclaveSigner);
        splitter.payFees(victimId, appA, address(token), 5_000_000, usageHash);
        assertEq(splitter.usagePaid(victimId, usageHash, appA), 5_000_000);
    }

    /// crypto-SEAL-04 (acknowledged): deploymentId is bound to (customer, stackHash, salt) by the oracle, not
    /// onchain (the Record type and registerDeployment ABI are fixed by the spec). Needs a misbehaving oracle.
    function test_deploymentIdSquat() public {
        _approveDefault();
        bytes32 victimId = _deploymentId(customer, stackHash, bytes32(uint256(1)));

        bytes32 attackerStack = keccak256("attacker-stack");
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = releaseA;
        _approve(attacker, attackerStack, ids, imageId, 0);
        IDeploymentRegistry.Record memory ar = IDeploymentRegistry.Record({
            deploymentId: victimId, // not keccak(attacker, attackerStack, salt)
            customer: attacker,
            stackHash: attackerStack,
            imageId: imageId,
            quoteHash: keccak256("aq"),
            eventLogHash: keccak256("ae"),
            configHash: keccak256("ac"),
            enclaveSigner: attackerEnclave,
            attestedAt: uint64(block.timestamp)
        });
        _register(ar); // accepted only because the oracle signed it

        IDeploymentRegistry.Record memory vr = _record(bytes32(uint256(1)));
        assertEq(vr.deploymentId, victimId);
        bytes memory ev = _oracleEvidence(vr);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.DeploymentAlreadyRegistered.selector, victimId));
        registry.registerDeployment(vr, 1, ev);
    }

    /// crypto-SEAL-05 (fixed): a record attested before a revoke and re-approval is rejected.
    function test_recordFromBeforeRevocationRegistrableAfterReapproval() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(7)));
        bytes memory ev = _oracleEvidence(r);

        vm.prank(customer);
        registry.revokeStack(stackHash);
        vm.warp(block.timestamp + 12 hours);
        _approveDefault();

        (,,,, uint64 approvedAt) = registry.getStackApproval(customer, stackHash);
        assertGt(approvedAt, r.attestedAt);
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(DeploymentRegistry.AttestedBeforeApproval.selector, r.attestedAt, approvedAt)
        );
        registry.registerDeployment(r, 1, ev);
    }

    /// crypto-SEAL-03 (d) (fixed): a heartbeat cannot repeat the current quoteHash.
    function test_heartbeatReusesQuoteHash() public {
        bytes32 id = _deployDefault();
        bytes32 q = registry.getDeployment(id).quoteHash;
        vm.warp(block.timestamp + 1 hours);
        uint64 t = uint64(block.timestamp);
        bytes memory ev = _heartbeatEvidence(id, q, t);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.QuoteReused.selector, q));
        registry.heartbeat(id, q, t, 1, ev);
    }

    /// crypto-SEAL-03 (a, b, c) (acknowledged, method 2 unset and asserted unset by Deploy.s.sol): a verifier that
    /// only checks today's evidence report_data cannot bind customer, deploymentId or time. Method 2 needs the
    /// report_data v2 design in contract-review.md before setVerifier(2, ...).
    function test_zkPathCannotBindCustomerIdOrTime() public {
        ReportDataZkVerifier zk = new ReportDataZkVerifier(registry);
        vm.prank(owner);
        registry.setVerifier(2, address(zk));

        bytes32 nonce2 = keccak256("nonce2");
        bytes32 configHash = keccak256("victim-config");
        bytes32 quoteHash = keccak256("victim-quote");
        bytes32 reportData =
            sha256(abi.encodePacked("sealed/evidence/v1", stackHash, configHash, enclaveSigner, nonce2));

        _approve(attacker, stackHash, _releases2(), imageId, 0);

        vm.warp(block.timestamp + 90 days);
        IDeploymentRegistry.Record memory r = IDeploymentRegistry.Record({
            deploymentId: keccak256("anything"),
            customer: attacker,
            stackHash: stackHash,
            imageId: imageId,
            quoteHash: quoteHash,
            eventLogHash: keccak256("whatever"),
            configHash: configHash,
            enclaveSigner: enclaveSigner,
            attestedAt: uint64(block.timestamp)
        });
        registry.registerDeployment(r, 2, abi.encode(r, quoteHash, reportData, nonce2));
        assertEq(registry.getDeployment(r.deploymentId).customer, attacker);
    }

    /// crypto-SEAL-06 (fixed): an approval with a since-deprecated release can be extended.
    function test_cannotExtendApprovalWithDeprecatedRelease() public {
        _approve(customer, stackHash, _releases2(), imageId, uint64(block.timestamp + 1 days));
        vm.prank(owner);
        apps.deprecateRelease(releaseA);
        assertTrue(registry.isStackApproved(customer, stackHash));
        _approve(customer, stackHash, _releases2(), imageId, uint64(block.timestamp + 30 days));
        vm.warp(block.timestamp + 1 days);
        assertTrue(registry.isStackApproved(customer, stackHash));
    }

    /// crypto-SEAL-08 (acknowledged, spec + D-013): deprecating an image stops every deployment on it.
    function test_imageDeprecationKillsHeartbeats() public {
        bytes32 id = _deployDefault();
        vm.prank(owner);
        platform.deprecateImage(imageId);
        vm.warp(block.timestamp + 60);
        uint64 t = uint64(block.timestamp);
        bytes32 q = keccak256("q");
        bytes memory ev = _heartbeatEvidence(id, q, t);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(id, q, t, 1, ev);
    }

    /// crypto-SEAL-07 interop note: v in {0,1} (go-ethereum crypto.Sign output) is rejected; the Go oracle adds 27.
    function test_vZeroOneRejected() public {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(3)));
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(oracleKey, registry.recordDigest(r));
        bytes memory ev = abi.encode(abi.encodePacked(rr, s, v - 27));
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.InvalidAttestation.selector, 1));
        registry.registerDeployment(r, 1, ev);
    }
}

contract AuditReleaseSwapTest is SealedTest {
    /// crypto-SEAL-01 (fixed): the release kill switch cannot be undone by re-approving the same stackHash with a
    /// different release list.
    function test_revokedReleaseBypassedByReapprovingSameStackHash() public {
        bytes32 id = _deployDefault(); // stackHash runs releaseA + releaseB

        vm.prank(owner);
        apps.revokeRelease(releaseA, "CVE");
        assertFalse(registry.isStackApproved(customer, stackHash));

        bytes32 releaseA2 = _publish(appA, "1.0.1");
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = releaseA2;
        ids[1] = releaseB;
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ReleasesChanged.selector, customer, stackHash));
        registry.approveStack(stackHash, ids, imageId, 0);
        assertFalse(registry.isStackApproved(customer, stackHash));

        vm.warp(block.timestamp + 60);
        uint64 t = uint64(block.timestamp);
        bytes32 q = keccak256("q-after-revoke");
        bytes memory ev = _heartbeatEvidence(id, q, t);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(id, q, t, 1, ev);
    }
}
