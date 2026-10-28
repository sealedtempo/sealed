// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {SealedTest} from "../utils/SealedTest.sol";

/// @notice Contract review, funds lens (funds-F-01 .. funds-F-10). Each test replays the auditor's PoC. Fixed
///         findings assert the fix; acknowledged findings pin the documented behavior.
///         Record: sealed-platform/docs/notes/contract-review.md.
contract AuditFundsTest is SealedTest {
    bytes32 internal victimDeployment;
    bytes32 internal attackerDeployment;
    address internal attacker;
    address internal attackerEnclave;

    function setUp() public override {
        super.setUp();
        // Victim: the default customer and deployment (stack with appA + appB).
        victimDeployment = _deployDefault();
        _fund(customer, 1_000_000_000);
        _fund(enclaveSigner, 1_000_000_000);

        // Attacker: an unrelated platform customer whose own (attested) deployment also contains appA.
        attacker = makeAddr("attacker");
        attackerEnclave = makeAddr("attackerEnclave");
        bytes32 attackerStack = keccak256("attacker-stack");
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = releaseA;
        _approve(attacker, attackerStack, ids, imageId, 0);
        IDeploymentRegistry.Record memory r = IDeploymentRegistry.Record({
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
        _register(r);
        attackerDeployment = r.deploymentId;
        _fund(attacker, 1_000_000);
    }

    /// funds-F-01 (fixed): a third party's payment on its own deployment does not touch the victim's usage key.
    function test_PoC_crossDeploymentUsageHashSquat() public {
        bytes32 victimUsageHash = keccak256(abi.encode("UsageReport", victimDeployment, uint64(0), uint64(3600)));

        vm.prank(attacker);
        splitter.payFees(attackerDeployment, appA, address(token), 1, victimUsageHash);
        assertEq(splitter.usagePaid(attackerDeployment, victimUsageHash, appA), 1);
        assertEq(splitter.usagePaid(victimDeployment, victimUsageHash, appA), 0);

        vm.prank(enclaveSigner);
        splitter.payFees(victimDeployment, appA, address(token), 4_000_000, victimUsageHash);
        assertEq(splitter.usagePaid(victimDeployment, victimUsageHash, appA), 4_000_000);
    }

    /// funds-F-01 (fixed): squatting one leg no longer reverts the victim's atomic per-report batch.
    function test_PoC_squatRevertsWholeBatch() public {
        BatchPayer bp = new BatchPayer(splitter, address(token));
        bytes32 st = keccak256("victim2-stack");
        address victim2 = makeAddr("victim2");
        _approve(victim2, st, _releases2(), imageId, 0);
        IDeploymentRegistry.Record memory r = IDeploymentRegistry.Record({
            deploymentId: _deploymentId(victim2, st, bytes32(uint256(7))),
            customer: victim2,
            stackHash: st,
            imageId: imageId,
            quoteHash: keccak256("vq"),
            eventLogHash: keccak256("ve"),
            configHash: keccak256("vc"),
            enclaveSigner: address(bp),
            attestedAt: uint64(block.timestamp)
        });
        _register(r);
        token.mint(address(bp), 10_000_000);

        bytes32 h = keccak256("victim2-report");
        vm.prank(attacker);
        splitter.payFees(attackerDeployment, appA, address(token), 1, h);

        bp.payReport(r.deploymentId, appA, 2_000_000, appB, 2_000_000, h);
        assertEq(splitter.usagePaid(r.deploymentId, h, appA), 2_000_000);
        assertEq(splitter.usagePaid(r.deploymentId, h, appB), 2_000_000);
        assertEq(splitter.credited(address(token), maintainer), 800_000);
    }

    /// funds-F-02 (fixed with topUpFees and the agent's settlement rule): the deployment's own customer can still
    /// open a leg first with a smaller amount, and payFees cannot repeat it, but the leg is not settled: the enclave
    /// signer tops it up to the report's fee and the maintainer gets the full share.
    function test_PoC_customerUnderpaysThenEnclaveTopsUp() public {
        bytes32 h = keccak256("report-with-fee-5000000");
        vm.prank(customer);
        splitter.payFees(victimDeployment, appA, address(token), 1, h);
        assertEq(splitter.usagePaid(victimDeployment, h, appA), 1);
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageAlreadyPaid.selector, victimDeployment, h, appA));
        splitter.payFees(victimDeployment, appA, address(token), 5_000_000, h);

        uint256 before = IERC20(address(token)).balanceOf(enclaveSigner);
        vm.prank(enclaveSigner);
        splitter.topUpFees(victimDeployment, appA, address(token), 5_000_000, h);
        assertEq(splitter.usagePaid(victimDeployment, h, appA), 5_000_000, "leg raised to the report's fee");
        assertEq(before - IERC20(address(token)).balanceOf(enclaveSigner), 4_999_999, "only the shortfall is pulled");
        assertEq(splitter.credited(address(token), maintainer), 999_999, "0 of the 1-unit payment + 20% of 4_999_999");
        assertEq(splitter.credited(address(token), treasury), 4_000_001);
        // The customer cannot undo or repeat it: the leg is at the fee.
        vm.prank(customer);
        vm.expectRevert(
            abi.encodeWithSelector(FeeSplitter.NothingToTopUp.selector, victimDeployment, h, appA, 5_000_000)
        );
        splitter.topUpFees(victimDeployment, appA, address(token), 5_000_000, h);
    }

    /// funds-F-04 (acknowledged, spec formula day = timestamp / 1 days): up to 2x the daily cap around midnight UTC.
    function test_PoC_dayBoundaryDoubleCap() public {
        uint256 dayEnd = (block.timestamp / 1 days + 1) * 1 days;
        vm.warp(dayEnd - 1);
        for (uint256 i; i < 4; ++i) {
            vm.prank(customer);
            splitter.payFees(victimDeployment, appA, address(token), PER_PAYMENT_CAP, keccak256(abi.encode("a", i)));
        }
        vm.warp(dayEnd);
        for (uint256 i; i < 4; ++i) {
            vm.prank(customer);
            splitter.payFees(victimDeployment, appA, address(token), PER_PAYMENT_CAP, keccak256(abi.encode("b", i)));
        }
        assertEq(splitter.totalCredited(address(token)), 2 * DAILY_CAP);
    }

    /// funds-F-07 (acknowledged, spec "deployment Active"): payments continue after revocations.
    function test_PoC_paysAfterRevocations() public {
        vm.prank(customer);
        registry.revokeStack(stackHash);
        vm.prank(owner);
        apps.revokeRelease(releaseA, "malicious");
        vm.warp(block.timestamp + 365 days);
        assertFalse(registry.isStackApproved(customer, stackHash));
        vm.prank(enclaveSigner);
        splitter.payFees(victimDeployment, appA, address(token), 1_000_000, keccak256("late"));
        assertEq(splitter.credited(address(token), maintainer), 200_000);
    }

    /// funds-F-03 (fixed): re-approving the same stackHash cannot change a live deployment's release set.
    function test_PoC_reapprovalMutatesLiveDeployment() public {
        bytes32 appC = _registerApp("scraper", 5000);
        bytes32 releaseC = _publish(appC, "1.0.0");

        vm.prank(owner);
        apps.revokeRelease(releaseA, "vuln");
        assertFalse(registry.isStackApproved(customer, stackHash));

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = releaseB;
        ids[1] = releaseC;
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(DeploymentRegistry.ReleasesChanged.selector, customer, stackHash));
        registry.approveStack(stackHash, ids, imageId, 0);
        assertFalse(registry.isStackApproved(customer, stackHash));
        assertFalse(registry.appInDeployment(victimDeployment, appC));
        assertTrue(registry.appInDeployment(victimDeployment, appA));

        // The enclave can still settle appA, which the running stack contains.
        vm.prank(enclaveSigner);
        splitter.payFees(victimDeployment, appA, address(token), 1_000_000, keccak256("x"));
    }

    /// funds-F-06 (fixed): the treasury cannot be FeeSplitter itself, and a maintainer set to it gets no share, so
    /// no credit is stranded.
    function test_PoC_selfTreasuryLocksFunds() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.InvalidTreasury.selector, address(splitter)));
        splitter.setTreasury(address(splitter));
        vm.prank(maintainer);
        apps.setMaintainer(appA, address(splitter));
        vm.prank(customer);
        splitter.payFees(victimDeployment, appA, address(token), 1_000_000, keccak256("lock"));
        assertEq(splitter.credited(address(token), address(splitter)), 0);
        assertEq(splitter.credited(address(token), treasury), 1_000_000);
        vm.prank(treasury);
        splitter.withdraw(address(token));
        assertEq(token.balanceOf(address(splitter)), 0);
    }

    /// funds-F-05 (acknowledged, spec "deployment Active"): a closed deployment cannot pay; the stop flow settles
    /// before closeDeployment.
    function test_PoC_closedCannotSettle() public {
        vm.prank(customer);
        registry.closeDeployment(victimDeployment);
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DeploymentNotActive.selector, victimDeployment));
        splitter.payFees(victimDeployment, appA, address(token), 1_000_000, keccak256("final"));
    }
}

/// @notice Stands in for an enclave-signer account sending one atomic Tempo batch (approve + payFees per app).
contract BatchPayer {
    FeeSplitter internal immutable s;
    address internal immutable t;

    constructor(FeeSplitter s_, address t_) {
        s = s_;
        t = t_;
    }

    function payReport(bytes32 dep, bytes32 a1, uint256 f1, bytes32 a2, uint256 f2, bytes32 h) external {
        IERC20(t).approve(address(s), f1 + f2);
        s.payFees(dep, a1, t, f1, h);
        s.payFees(dep, a2, t, f2, h);
    }
}
