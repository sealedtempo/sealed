// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {stdError} from "forge-std/StdError.sol";

import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {SealedTest} from "../utils/SealedTest.sol";

/// @notice Behavior the invariant and fork work (docs/notes/contract-invariants.md) surfaced. Neither is a defect
///         of a payment or deployment flow; both pin what the deployed contracts do, so a change shows up here.
contract AuditInvariantsTest is SealedTest {
    /// @dev splitAmount is a pure helper for offchain callers and does not cap shareBps. Above 10000 bps it returns
    ///      a maintainer part up to the whole amount while amount * shareBps / 10000 <= amount, and reverts with
    ///      Panic(0x11) (the treasury part underflows) once it is larger, instead of a named error. payFees and
    ///      topUpFees never reach it: they compute the split from AppRegistry's share, which is capped at 5000.
    function test_splitAmount_aboveAFullShare() public {
        (uint256 m, uint256 t) = splitter.splitAmount(1_000_001, 10_000);
        assertEq(m, 1_000_001);
        assertEq(t, 0);
        (m, t) = splitter.splitAmount(9999, 10_001);
        assertEq(m, 9999, "rounds down to the whole amount");
        assertEq(t, 0);
        vm.expectRevert(stdError.arithmeticError);
        splitter.splitAmount(10_000, 10_001);
        (m, t) = splitter.splitAmount(0, type(uint16).max);
        assertEq(m + t, 0, "zero amount never underflows");
    }

    /// @dev CR-3 rejects a registration record attested more than MAX_FUTURE_SKEW before the approval it relies on.
    ///      Heartbeats have no such bound: a heartbeat signed before revokeStack and withheld is accepted after a
    ///      re-approval while it is still fresh and newer than the last one. Its attestedAt is still the true
    ///      attestation time, and re-approval restores every unclosed deployment by design (revokeStack NatSpec).
    function test_heartbeat_attestedBeforeReapprovalIsAccepted() public {
        bytes32 id = _deployDefault();
        vm.warp(block.timestamp + 60);
        uint64 t0 = uint64(block.timestamp);
        bytes32 quote = keccak256("withheld-heartbeat");
        bytes memory evidence = _heartbeatEvidence(id, quote, t0);

        vm.warp(block.timestamp + 60);
        vm.prank(customer);
        registry.revokeStack(stackHash);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.StackNotApproved.selector, customer, stackHash));
        registry.heartbeat(id, quote, t0, 1, evidence);

        vm.warp(block.timestamp + 1 hours);
        _approveDefault();
        (,,,, uint64 approvedAt) = registry.getStackApproval(customer, stackHash);
        assertGt(approvedAt, t0 + registry.MAX_FUTURE_SKEW(), "the heartbeat predates the re-approval");

        // A registration record from t0 would be rejected ...
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(2)));
        r.attestedAt = t0;
        bytes memory recordEvidence = _oracleEvidence(r);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.AttestedBeforeApproval.selector, t0, approvedAt));
        registry.registerDeployment(r, 1, recordEvidence);

        // ... the withheld heartbeat from t0 is accepted.
        registry.heartbeat(id, quote, t0, 1, evidence);
        assertEq(registry.getDeployment(id).lastAttestedAt, t0);
    }
}
