// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {AppRegistry} from "../src/AppRegistry.sol";
import {FeeSplitter} from "../src/FeeSplitter.sol";
import {IAppRegistry} from "../src/interfaces/IAppRegistry.sol";
import {IDeploymentRegistry} from "../src/interfaces/IDeploymentRegistry.sol";
import {OwnableNoRenounce} from "../src/utils/OwnableNoRenounce.sol";
import {FeeOnTransferERC20, MockERC20, ReentrantERC20} from "./mocks/MockERC20.sol";
import {SealedTest} from "./utils/SealedTest.sol";

contract FeeSplitterTest is SealedTest {
    event FeesPaid(
        bytes32 indexed deploymentId,
        bytes32 indexed appId,
        address indexed payer,
        address token,
        uint256 amount,
        uint256 maintainerAmount,
        bytes32 usageHash
    );
    event Credited(
        address indexed recipient,
        address indexed token,
        bytes32 indexed appId,
        FeeSplitter.CreditKind kind,
        uint256 amount,
        uint256 newBalance
    );
    event Withdrawn(address indexed account, address indexed token, uint256 amount);
    event Swept(address indexed token, address indexed treasury, uint256 amount);
    event TokenConfigured(address indexed token, bool allowed, uint256 perPaymentCap, uint256 perDeploymentDailyCap);
    event TreasurySet(address indexed previousTreasury, address indexed newTreasury);

    bytes32 internal deploymentId;
    bytes32 internal constant USAGE = keccak256("usage-report-1");

    function setUp() public override {
        super.setUp();
        deploymentId = _deployDefault();
        _fund(customer, 1_000_000_000);
        _fund(enclaveSigner, 1_000_000_000);
    }

    function _pay(address payer, bytes32 appId, uint256 amount, bytes32 usageHash) internal {
        vm.prank(payer);
        splitter.payFees(deploymentId, appId, address(token), amount, usageHash);
    }

    function _assertInvariant(address t) internal view {
        assertEq(IERC20Like(t).balanceOf(address(splitter)), splitter.totalCredited(t), "balance == totalCredited");
    }

    // ------------------------------------------------------------------------------------------------------
    // Constructor and metadata
    // ------------------------------------------------------------------------------------------------------

    function test_metadata() public view {
        assertEq(splitter.VERSION(), "1.0.0");
        assertEq(splitter.BPS_DENOMINATOR(), 10_000);
        assertEq(splitter.FEE_TOKEN(), address(token));
        assertEq(splitter.treasury(), treasury);
        assertEq(address(splitter.deploymentRegistry()), address(registry));
        assertEq(address(splitter.appRegistry()), address(apps));
        assertEq(splitter.owner(), owner);
        FeeSplitter.TokenConfig memory cfg = splitter.tokenConfig(address(token));
        assertTrue(cfg.allowed);
        assertEq(cfg.perPaymentCap, 5_000_000);
        assertEq(cfg.perDeploymentDailyCap, 20_000_000);
        assertTrue(splitter.isTokenAllowed(address(token)));
        assertEq(splitter.TIP20_ADDRESS_PREFIX(), bytes12(0x20c000000000000000000000));
    }

    function test_constructor_emitsConfig() public {
        vm.expectEmit();
        emit TreasurySet(address(0), treasury);
        vm.expectEmit();
        emit TokenConfigured(address(token), true, 1, 2);
        new FeeSplitter(owner, registry, apps, address(token), treasury, 1, 2);
    }

    function test_constructor_revertsOnZeroRegistry() public {
        vm.expectRevert(FeeSplitter.ZeroAddress.selector);
        new FeeSplitter(owner, IDeploymentRegistry(address(0)), apps, address(token), treasury, 1, 2);
    }

    function test_constructor_revertsOnZeroApps() public {
        vm.expectRevert(FeeSplitter.ZeroAddress.selector);
        new FeeSplitter(owner, registry, IAppRegistry(address(0)), address(token), treasury, 1, 2);
    }

    function test_constructor_revertsOnZeroToken() public {
        vm.expectRevert(FeeSplitter.ZeroAddress.selector);
        new FeeSplitter(owner, registry, apps, address(0), treasury, 1, 2);
    }

    function test_constructor_revertsOnZeroTreasury() public {
        vm.expectRevert(FeeSplitter.ZeroAddress.selector);
        new FeeSplitter(owner, registry, apps, address(token), address(0), 1, 2);
    }

    function test_constructor_revertsOnAppRegistryMismatch() public {
        AppRegistry otherApps = new AppRegistry(owner);
        vm.expectRevert(
            abi.encodeWithSelector(FeeSplitter.AppRegistryMismatch.selector, address(apps), address(otherApps))
        );
        new FeeSplitter(owner, registry, otherApps, address(token), treasury, 1, 2);
    }

    function test_constructor_revertsOnSelfTreasury() public {
        address next = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.InvalidTreasury.selector, next));
        new FeeSplitter(owner, registry, apps, address(token), next, 1, 2);
    }

    function test_constructor_revertsOnTip20Treasury() public {
        address pathUsd = 0x20C0000000000000000000000000000000000000;
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.InvalidTreasury.selector, pathUsd));
        new FeeSplitter(owner, registry, apps, address(token), pathUsd, 1, 2);
    }

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new FeeSplitter(address(0), registry, apps, address(token), treasury, 1, 2);
    }

    function test_renounceOwnership_disabled() public {
        vm.prank(owner);
        vm.expectRevert(OwnableNoRenounce.RenounceOwnershipDisabled.selector);
        splitter.renounceOwnership();
    }

    // ------------------------------------------------------------------------------------------------------
    // payFees
    // ------------------------------------------------------------------------------------------------------

    function test_payFees_byCustomer() public {
        uint256 before = token.balanceOf(customer);
        vm.expectEmit(address(splitter));
        emit Credited(maintainer, address(token), appA, FeeSplitter.CreditKind.Maintainer, 200_000, 200_000);
        vm.expectEmit(address(splitter));
        emit Credited(treasury, address(token), appA, FeeSplitter.CreditKind.Treasury, 800_000, 800_000);
        vm.expectEmit(address(splitter));
        emit FeesPaid(deploymentId, appA, customer, address(token), 1_000_000, 200_000, USAGE);
        _pay(customer, appA, 1_000_000, USAGE);

        assertEq(token.balanceOf(customer), before - 1_000_000);
        assertEq(token.balanceOf(address(splitter)), 1_000_000);
        assertEq(splitter.credited(address(token), maintainer), 200_000);
        assertEq(splitter.credited(address(token), treasury), 800_000);
        assertEq(splitter.totalCredited(address(token)), 1_000_000);
        assertEq(splitter.dailyPaid(deploymentId, address(token), block.timestamp / 1 days), 1_000_000);
        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), 1_000_000, "records the amount paid");
        assertEq(splitter.usagePaid(deploymentId, USAGE, appB), 0);
        assertEq(splitter.remainingDailyAllowance(deploymentId, address(token)), 19_000_000);
        _assertInvariant(address(token));
    }

    function test_payFees_byEnclaveSigner() public {
        vm.expectEmit(address(splitter));
        emit FeesPaid(deploymentId, appB, enclaveSigner, address(token), 3, 0, USAGE);
        _pay(enclaveSigner, appB, 3, USAGE);
        // 3 * 2000 / 10000 = 0: the maintainer gets nothing, the treasury gets everything.
        assertEq(splitter.credited(address(token), maintainer), 0);
        assertEq(splitter.credited(address(token), treasury), 3);
    }

    function test_payFees_sameUsageDifferentApps() public {
        _pay(customer, appA, 100, USAGE);
        _pay(customer, appB, 100, USAGE);
        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), 100);
        assertEq(splitter.usagePaid(deploymentId, USAGE, appB), 100);
    }

    function test_payFees_exactCaps() public {
        _pay(customer, appA, PER_PAYMENT_CAP, keccak256("u1"));
        _pay(customer, appA, PER_PAYMENT_CAP, keccak256("u2"));
        _pay(customer, appB, PER_PAYMENT_CAP, keccak256("u3"));
        _pay(enclaveSigner, appB, PER_PAYMENT_CAP, keccak256("u4"));
        assertEq(splitter.dailyPaid(deploymentId, address(token), block.timestamp / 1 days), DAILY_CAP);
        assertEq(splitter.remainingDailyAllowance(deploymentId, address(token)), 0);
    }

    function test_payFees_revertsWhenPaused() public {
        vm.prank(owner);
        splitter.pause();
        vm.prank(customer);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        splitter.payFees(deploymentId, appA, address(token), 1, USAGE);
    }

    function test_payFees_revertsOnDisallowedToken() public {
        MockERC20 other = new MockERC20("Other", "OTH");
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.TokenNotAllowed.selector, address(other)));
        splitter.payFees(deploymentId, appA, address(other), 1, USAGE);
    }

    function test_payFees_revertsOnZeroAmount() public {
        vm.prank(customer);
        vm.expectRevert(FeeSplitter.ZeroAmount.selector);
        splitter.payFees(deploymentId, appA, address(token), 0, USAGE);
    }

    function test_payFees_revertsAbovePerPaymentCap() public {
        vm.prank(customer);
        vm.expectRevert(
            abi.encodeWithSelector(FeeSplitter.PerPaymentCapExceeded.selector, PER_PAYMENT_CAP + 1, PER_PAYMENT_CAP)
        );
        splitter.payFees(deploymentId, appA, address(token), PER_PAYMENT_CAP + 1, USAGE);
    }

    function test_payFees_revertsOnZeroUsageHash() public {
        vm.prank(customer);
        vm.expectRevert(FeeSplitter.ZeroUsageHash.selector);
        splitter.payFees(deploymentId, appA, address(token), 1, bytes32(0));
    }

    function test_payFees_revertsForUnknownDeployment() public {
        bytes32 unknown = keccak256("unknown");
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DeploymentNotActive.selector, unknown));
        splitter.payFees(unknown, appA, address(token), 1, USAGE);
    }

    function test_payFees_revertsForClosedDeployment() public {
        vm.prank(customer);
        registry.closeDeployment(deploymentId);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DeploymentNotActive.selector, deploymentId));
        splitter.payFees(deploymentId, appA, address(token), 1, USAGE);
    }

    function test_payFees_revertsForUnauthorizedPayer() public {
        _fund(stranger, 1_000_000);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UnauthorizedPayer.selector, stranger));
        splitter.payFees(deploymentId, appA, address(token), 1, USAGE);
        vm.prank(maintainer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UnauthorizedPayer.selector, maintainer));
        splitter.payFees(deploymentId, appA, address(token), 1, USAGE);
    }

    function test_payFees_revertsForAppNotInDeployment() public {
        bytes32 appC = _registerApp("scraper", 1000);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.AppNotInDeployment.selector, deploymentId, appC));
        splitter.payFees(deploymentId, appC, address(token), 1, USAGE);
    }

    function test_payFees_revertsOnRepeatedUsage() public {
        _pay(customer, appA, 1, USAGE);
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageAlreadyPaid.selector, deploymentId, USAGE, appA));
        splitter.payFees(deploymentId, appA, address(token), 1, USAGE);
    }

    /// @dev Review fix (logic-F1 / funds-F-01 / crypto-SEAL-02): the usage key includes the deployment, so a payment
    ///      on one deployment never consumes another deployment's (usageHash, appId).
    function test_payFees_usageKeyIsPerDeployment() public {
        bytes32 other = _record(bytes32(uint256(2))).deploymentId;
        _register(_record(bytes32(uint256(2))));
        _pay(customer, appA, 7, USAGE);
        vm.prank(customer);
        splitter.payFees(other, appA, address(token), 9, USAGE);
        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), 7);
        assertEq(splitter.usagePaid(other, USAGE, appA), 9);
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageAlreadyPaid.selector, other, USAGE, appA));
        splitter.payFees(other, appA, address(token), 1, USAGE);
    }

    function test_payFees_revertsAboveDailyCap() public {
        for (uint256 i; i < 4; ++i) {
            _pay(customer, appA, PER_PAYMENT_CAP, keccak256(abi.encode(i)));
        }
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DailyCapExceeded.selector, DAILY_CAP + 1, DAILY_CAP));
        splitter.payFees(deploymentId, appB, address(token), 1, keccak256("x"));
    }

    function test_payFees_dailyCapResetsNextDay() public {
        for (uint256 i; i < 4; ++i) {
            _pay(customer, appA, PER_PAYMENT_CAP, keccak256(abi.encode(i)));
        }
        uint256 nextDay = (block.timestamp / 1 days + 1) * 1 days;
        vm.warp(nextDay - 1);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DailyCapExceeded.selector, DAILY_CAP + 1, DAILY_CAP));
        splitter.payFees(deploymentId, appB, address(token), 1, keccak256("x"));
        vm.warp(nextDay);
        _pay(customer, appB, PER_PAYMENT_CAP, keccak256("x"));
        assertEq(splitter.dailyPaid(deploymentId, address(token), nextDay / 1 days), PER_PAYMENT_CAP);
    }

    function test_payFees_dailyCapIsPerDeployment() public {
        IDeploymentRegistry.Record memory r2 = _record(bytes32(uint256(2)));
        _register(r2);
        for (uint256 i; i < 4; ++i) {
            _pay(customer, appA, PER_PAYMENT_CAP, keccak256(abi.encode(i)));
        }
        vm.prank(customer);
        splitter.payFees(r2.deploymentId, appA, address(token), PER_PAYMENT_CAP, keccak256("other deployment"));
    }

    function test_payFees_revertsOnInsufficientAllowance() public {
        address payer = enclaveSigner;
        vm.prank(payer);
        token.approve(address(splitter), 10);
        vm.prank(payer);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(splitter), 10, 11)
        );
        splitter.payFees(deploymentId, appA, address(token), 11, USAGE);
    }

    function test_payFees_revertsOnInsufficientBalance() public {
        uint256 balance = token.balanceOf(customer);
        vm.prank(customer);
        assertTrue(token.transfer(stranger, balance - 5));
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, customer, 5, 6));
        splitter.payFees(deploymentId, appA, address(token), 6, USAGE);
    }

    function test_payFees_rejectsFeeOnTransferToken() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        vm.prank(owner);
        splitter.setToken(address(fot), true, PER_PAYMENT_CAP, DAILY_CAP);
        fot.mint(customer, 1_000_000);
        vm.startPrank(customer);
        fot.approve(address(splitter), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.TransferAmountMismatch.selector, 1_000_000, 990_000));
        splitter.payFees(deploymentId, appA, address(fot), 1_000_000, USAGE);
        vm.stopPrank();
    }

    function test_payFees_blocksReentrancy() public {
        ReentrantERC20 evil = new ReentrantERC20();
        vm.prank(owner);
        splitter.setToken(address(evil), true, PER_PAYMENT_CAP, DAILY_CAP);
        evil.mint(customer, 1_000_000);
        vm.prank(customer);
        evil.approve(address(splitter), type(uint256).max);
        evil.arm(
            address(splitter),
            abi.encodeCall(FeeSplitter.payFees, (deploymentId, appA, address(evil), 1, keccak256("inner"))),
            true,
            false
        );
        vm.prank(customer);
        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        splitter.payFees(deploymentId, appA, address(evil), 1, USAGE);
    }

    function test_payFees_usesCurrentMaintainerAndTreasury() public {
        _pay(customer, appA, 1_000_000, keccak256("u1"));
        address newMaintainer = makeAddr("newMaintainer");
        address newTreasury = makeAddr("newTreasury");
        vm.prank(maintainer);
        apps.setMaintainer(appA, newMaintainer);
        vm.startPrank(owner);
        splitter.setTreasury(newTreasury);
        apps.setMaintainerShare(appA, 5000);
        vm.stopPrank();
        _pay(customer, appA, 1_000_000, keccak256("u2"));

        assertEq(splitter.credited(address(token), maintainer), 200_000, "old maintainer keeps old credit");
        assertEq(splitter.credited(address(token), treasury), 800_000, "old treasury keeps old credit");
        assertEq(splitter.credited(address(token), newMaintainer), 500_000);
        assertEq(splitter.credited(address(token), newTreasury), 500_000);
        _assertInvariant(address(token));
    }

    function test_payFees_maintainerIsTreasury() public {
        vm.prank(owner);
        apps.setMaintainer(appA, treasury);
        _pay(customer, appA, 1_000_000, USAGE);
        assertEq(splitter.credited(address(token), treasury), 1_000_000);
        _assertInvariant(address(token));
    }

    /// @dev Review fix (funds-F-06): a maintainer address that can never withdraw gets no share, so nothing locks.
    function test_payFees_unwithdrawableMaintainerShareGoesToTreasury() public {
        vm.prank(maintainer);
        apps.setMaintainer(appA, address(splitter));
        vm.expectEmit(address(splitter));
        emit Credited(treasury, address(token), appA, FeeSplitter.CreditKind.Treasury, 1_000_000, 1_000_000);
        vm.expectEmit(address(splitter));
        emit FeesPaid(deploymentId, appA, customer, address(token), 1_000_000, 0, USAGE);
        _pay(customer, appA, 1_000_000, USAGE);
        assertEq(splitter.credited(address(token), address(splitter)), 0);

        address ousd = 0x20c0000000000000000000006a37DA5C996874BE;
        vm.prank(owner);
        apps.setMaintainer(appA, ousd);
        _pay(customer, appA, 1_000_000, keccak256("u2"));
        assertEq(splitter.credited(address(token), ousd), 0);
        assertEq(splitter.credited(address(token), treasury), 2_000_000);
        _assertInvariant(address(token));
    }

    function test_payFees_zeroShareEmitsSingleCredit() public {
        vm.prank(owner);
        apps.setMaintainerShare(appA, 0);
        vm.recordLogs();
        _pay(customer, appA, 1_000_000, USAGE);
        assertEq(vm.getRecordedLogs().length, 3, "Transfer + one Credited + FeesPaid");
        assertEq(splitter.credited(address(token), maintainer), 0);
        assertEq(splitter.credited(address(token), treasury), 1_000_000);
    }

    // ------------------------------------------------------------------------------------------------------
    // topUpFees (verification fix for logic-F1 b / funds-F-02: a short leg can be raised to the report's fee)
    // ------------------------------------------------------------------------------------------------------

    function _topUp(address payer, bytes32 appId, uint256 total, bytes32 usageHash) internal {
        vm.prank(payer);
        splitter.topUpFees(deploymentId, appId, address(token), total, usageHash);
    }

    function test_topUpFees_raisesShortLegToTotal() public {
        _pay(customer, appA, 100_000, USAGE);
        uint256 before = token.balanceOf(enclaveSigner);
        vm.expectEmit(address(splitter));
        emit Credited(maintainer, address(token), appA, FeeSplitter.CreditKind.Maintainer, 180_000, 200_000);
        vm.expectEmit(address(splitter));
        emit Credited(treasury, address(token), appA, FeeSplitter.CreditKind.Treasury, 720_000, 800_000);
        vm.expectEmit(address(splitter));
        emit FeesPaid(deploymentId, appA, enclaveSigner, address(token), 900_000, 180_000, USAGE);
        _topUp(enclaveSigner, appA, 1_000_000, USAGE);

        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), 1_000_000, "leg raised to the total");
        assertEq(token.balanceOf(enclaveSigner), before - 900_000, "pulls only the difference");
        assertEq(splitter.dailyPaid(deploymentId, address(token), block.timestamp / 1 days), 1_000_000);
        assertEq(splitter.credited(address(token), maintainer), 200_000);
        assertEq(splitter.credited(address(token), treasury), 800_000);
        _assertInvariant(address(token));
    }

    function test_topUpFees_repeatedTopUpsPullOnlyTheRest() public {
        _pay(customer, appB, 1, USAGE);
        _topUp(customer, appB, 10, USAGE);
        uint256 before = token.balanceOf(enclaveSigner);
        vm.expectEmit(address(splitter));
        emit FeesPaid(deploymentId, appB, enclaveSigner, address(token), 999_990, 199_998, USAGE);
        _topUp(enclaveSigner, appB, 1_000_000, USAGE);
        assertEq(token.balanceOf(enclaveSigner), before - 999_990);
        assertEq(splitter.usagePaid(deploymentId, USAGE, appB), 1_000_000);
        assertEq(splitter.totalCredited(address(token)), 1_000_000, "the leg's FeesPaid amounts sum to usagePaid");
        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), 0, "other legs untouched");
        _assertInvariant(address(token));
    }

    function test_topUpFees_retryDoesNotPayTwice() public {
        _pay(customer, appA, 1, USAGE);
        _topUp(enclaveSigner, appA, 1_000_000, USAGE);
        vm.prank(enclaveSigner);
        vm.expectRevert(
            abi.encodeWithSelector(FeeSplitter.NothingToTopUp.selector, deploymentId, USAGE, appA, 1_000_000)
        );
        splitter.topUpFees(deploymentId, appA, address(token), 1_000_000, USAGE);
        vm.prank(customer);
        vm.expectRevert(
            abi.encodeWithSelector(FeeSplitter.NothingToTopUp.selector, deploymentId, USAGE, appA, 1_000_000)
        );
        splitter.topUpFees(deploymentId, appA, address(token), 999_999, USAGE);
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageAlreadyPaid.selector, deploymentId, USAGE, appA));
        splitter.payFees(deploymentId, appA, address(token), 1_000_000, USAGE);
        assertEq(splitter.totalCredited(address(token)), 1_000_000);
    }

    function test_topUpFees_revertsOnUnopenedLeg() public {
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageNotPaid.selector, deploymentId, USAGE, appA));
        splitter.topUpFees(deploymentId, appA, address(token), 1_000_000, USAGE);
        // The leg key is per deployment and app: opening it elsewhere does not open it here.
        IDeploymentRegistry.Record memory r2 = _record(bytes32(uint256(2)));
        _register(r2);
        vm.prank(customer);
        splitter.payFees(r2.deploymentId, appA, address(token), 1, USAGE);
        _pay(customer, appB, 1, USAGE);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageNotPaid.selector, deploymentId, USAGE, appA));
        splitter.topUpFees(deploymentId, appA, address(token), 1_000_000, USAGE);
    }

    function test_topUpFees_revertsWhenPaused() public {
        _pay(customer, appA, 1, USAGE);
        vm.prank(owner);
        splitter.pause();
        vm.prank(customer);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        splitter.topUpFees(deploymentId, appA, address(token), 2, USAGE);
    }

    function test_topUpFees_checksTokenAmountCapAndUsageHash() public {
        _pay(customer, appA, 1, USAGE);
        MockERC20 other = new MockERC20("Other", "OTH");
        vm.startPrank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.TokenNotAllowed.selector, address(other)));
        splitter.topUpFees(deploymentId, appA, address(other), 2, USAGE);
        vm.expectRevert(FeeSplitter.ZeroAmount.selector);
        splitter.topUpFees(deploymentId, appA, address(token), 0, USAGE);
        vm.expectRevert(
            abi.encodeWithSelector(FeeSplitter.PerPaymentCapExceeded.selector, PER_PAYMENT_CAP + 1, PER_PAYMENT_CAP)
        );
        splitter.topUpFees(deploymentId, appA, address(token), PER_PAYMENT_CAP + 1, USAGE);
        vm.expectRevert(FeeSplitter.ZeroUsageHash.selector);
        splitter.topUpFees(deploymentId, appA, address(token), 2, bytes32(0));
        vm.stopPrank();
        _topUp(customer, appA, PER_PAYMENT_CAP, USAGE);
        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), PER_PAYMENT_CAP, "a leg tops up to the cap exactly");
    }

    function test_topUpFees_requiresTheLegsToken() public {
        _pay(customer, appA, 1000, USAGE);
        assertEq(splitter.usageToken(deploymentId, USAGE, appA), address(token), "leg remembers its token");
        MockERC20 other = new MockERC20("Other", "OTH");
        vm.prank(owner);
        splitter.setToken(address(other), true, PER_PAYMENT_CAP, PER_PAYMENT_CAP);
        other.mint(customer, 1_000_000);
        vm.startPrank(customer);
        other.approve(address(splitter), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UsageTokenMismatch.selector, address(token), address(other)));
        splitter.topUpFees(deploymentId, appA, address(other), 1_000_000, USAGE);
        vm.stopPrank();
        _topUp(customer, appA, 1_000_000, USAGE);
        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), 1_000_000, "same-token top-up still works");
        _assertInvariant(address(token));
        _assertInvariant(address(other));
    }

    function test_topUpFees_checksPayerDeploymentAndApp() public {
        _pay(customer, appA, 1, USAGE);
        _fund(stranger, 1_000_000);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.UnauthorizedPayer.selector, stranger));
        splitter.topUpFees(deploymentId, appA, address(token), 2, USAGE);
        bytes32 appC = _registerApp("scraper", 1000);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.AppNotInDeployment.selector, deploymentId, appC));
        splitter.topUpFees(deploymentId, appC, address(token), 2, USAGE);
        vm.prank(customer);
        registry.closeDeployment(deploymentId);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DeploymentNotActive.selector, deploymentId));
        splitter.topUpFees(deploymentId, appA, address(token), 2, USAGE);
    }

    function test_topUpFees_differenceCountsAgainstDailyCap() public {
        for (uint256 i; i < 3; ++i) {
            _pay(customer, appA, PER_PAYMENT_CAP, keccak256(abi.encode(i)));
        }
        _pay(customer, appA, 1, keccak256("x"));
        _pay(customer, appB, 1, keccak256("y"));
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DailyCapExceeded.selector, DAILY_CAP + 1, DAILY_CAP));
        splitter.topUpFees(deploymentId, appA, address(token), PER_PAYMENT_CAP, keccak256("x"));
        _topUp(enclaveSigner, appA, PER_PAYMENT_CAP - 1, keccak256("x"));
        assertEq(splitter.dailyPaid(deploymentId, address(token), block.timestamp / 1 days), DAILY_CAP);
        uint256 nextDay = (block.timestamp / 1 days + 1) * 1 days;
        vm.warp(nextDay);
        _topUp(enclaveSigner, appA, PER_PAYMENT_CAP, keccak256("x"));
        assertEq(splitter.dailyPaid(deploymentId, address(token), nextDay / 1 days), 1, "counted on the day it is paid");
    }

    function test_topUpFees_needsOnlyTheDifferenceApproved() public {
        _pay(customer, appA, 400_000, USAGE);
        address payer = enclaveSigner;
        vm.prank(payer);
        token.approve(address(splitter), 599_999);
        vm.prank(payer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientAllowance.selector, address(splitter), 599_999, 600_000
            )
        );
        splitter.topUpFees(deploymentId, appA, address(token), 1_000_000, USAGE);
        vm.prank(payer);
        token.approve(address(splitter), 600_000);
        _topUp(payer, appA, 1_000_000, USAGE);
        assertEq(token.allowance(payer, address(splitter)), 0, "an exact approval ends at zero");
    }

    function test_topUpFees_blocksReentrancy() public {
        ReentrantERC20 evil = new ReentrantERC20();
        vm.prank(owner);
        splitter.setToken(address(evil), true, PER_PAYMENT_CAP, DAILY_CAP);
        evil.mint(customer, 1_000_000);
        vm.prank(customer);
        evil.approve(address(splitter), type(uint256).max);
        vm.prank(customer);
        splitter.payFees(deploymentId, appA, address(evil), 1, USAGE);
        evil.arm(
            address(splitter),
            abi.encodeCall(FeeSplitter.topUpFees, (deploymentId, appA, address(evil), 3, USAGE)),
            true,
            false
        );
        vm.prank(customer);
        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        splitter.topUpFees(deploymentId, appA, address(evil), 2, USAGE);
    }

    function test_topUpFees_unwithdrawableMaintainerShareGoesToTreasury() public {
        _pay(customer, appA, 1, USAGE);
        vm.prank(maintainer);
        apps.setMaintainer(appA, address(splitter));
        vm.expectEmit(address(splitter));
        emit FeesPaid(deploymentId, appA, customer, address(token), 999_999, 0, USAGE);
        _topUp(customer, appA, 1_000_000, USAGE);
        assertEq(splitter.credited(address(token), address(splitter)), 0);
        assertEq(splitter.credited(address(token), treasury), 1_000_000);
        _assertInvariant(address(token));
    }

    // ------------------------------------------------------------------------------------------------------
    // withdraw
    // ------------------------------------------------------------------------------------------------------

    function test_withdraw() public {
        _pay(customer, appA, 1_000_000, USAGE);
        vm.expectEmit(address(splitter));
        emit Withdrawn(maintainer, address(token), 200_000);
        vm.prank(maintainer);
        splitter.withdraw(address(token));
        assertEq(token.balanceOf(maintainer), 200_000);
        assertEq(splitter.credited(address(token), maintainer), 0);
        assertEq(splitter.totalCredited(address(token)), 800_000);
        _assertInvariant(address(token));

        vm.prank(treasury);
        splitter.withdraw(address(token));
        assertEq(token.balanceOf(treasury), 800_000);
        assertEq(token.balanceOf(address(splitter)), 0);
        _assertInvariant(address(token));
    }

    function test_withdraw_revertsWhenNothing() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.NothingToWithdraw.selector, address(token)));
        splitter.withdraw(address(token));
    }

    function test_withdraw_twiceReverts() public {
        _pay(customer, appA, 1_000_000, USAGE);
        vm.startPrank(maintainer);
        splitter.withdraw(address(token));
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.NothingToWithdraw.selector, address(token)));
        splitter.withdraw(address(token));
        vm.stopPrank();
    }

    function test_withdraw_worksWhilePaused() public {
        _pay(customer, appA, 1_000_000, USAGE);
        vm.prank(owner);
        splitter.pause();
        vm.prank(maintainer);
        splitter.withdraw(address(token));
        assertEq(token.balanceOf(maintainer), 200_000);
    }

    function test_withdraw_worksAfterTokenDisallowed() public {
        _pay(customer, appA, 1_000_000, USAGE);
        vm.prank(owner);
        splitter.setToken(address(token), false, 0, 0);
        vm.prank(treasury);
        splitter.withdraw(address(token));
        assertEq(token.balanceOf(treasury), 800_000);
    }

    function test_withdraw_blocksReentrancy() public {
        ReentrantERC20 evil = new ReentrantERC20();
        vm.prank(owner);
        splitter.setToken(address(evil), true, PER_PAYMENT_CAP, DAILY_CAP);
        evil.mint(customer, 1_000_000);
        vm.prank(customer);
        evil.approve(address(splitter), type(uint256).max);
        vm.prank(customer);
        splitter.payFees(deploymentId, appA, address(evil), 1_000_000, USAGE);

        evil.arm(address(splitter), abi.encodeCall(FeeSplitter.withdraw, (address(evil))), false, true);
        vm.prank(treasury);
        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        splitter.withdraw(address(evil));
    }

    // ------------------------------------------------------------------------------------------------------
    // sweepUnaccounted
    // ------------------------------------------------------------------------------------------------------

    function test_sweepUnaccounted() public {
        _pay(customer, appA, 1_000_000, USAGE);
        token.mint(address(splitter), 777);
        assertEq(token.balanceOf(address(splitter)), splitter.totalCredited(address(token)) + 777);
        vm.expectEmit(address(splitter));
        emit Credited(treasury, address(token), bytes32(0), FeeSplitter.CreditKind.Sweep, 777, 800_777);
        vm.expectEmit(address(splitter));
        emit Swept(address(token), treasury, 777);
        vm.prank(owner);
        splitter.sweepUnaccounted(address(token));
        assertEq(splitter.credited(address(token), treasury), 800_777);
        _assertInvariant(address(token));
    }

    function test_sweepUnaccounted_anyToken() public {
        MockERC20 stray = new MockERC20("Stray", "STR");
        stray.mint(address(splitter), 5);
        vm.prank(owner);
        splitter.sweepUnaccounted(address(stray));
        vm.prank(treasury);
        splitter.withdraw(address(stray));
        assertEq(stray.balanceOf(treasury), 5);
    }

    function test_sweepUnaccounted_revertsWhenNothing() public {
        _pay(customer, appA, 1_000_000, USAGE);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.NothingToSweep.selector, address(token)));
        splitter.sweepUnaccounted(address(token));
    }

    function test_sweepUnaccounted_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        splitter.sweepUnaccounted(address(token));
    }

    // ------------------------------------------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------------------------------------------

    function test_setToken() public {
        MockERC20 other = new MockERC20("Other", "OTH");
        vm.expectEmit(address(splitter));
        emit TokenConfigured(address(other), true, 7, 70);
        vm.prank(owner);
        splitter.setToken(address(other), true, 7, 70);
        FeeSplitter.TokenConfig memory cfg = splitter.tokenConfig(address(other));
        assertTrue(cfg.allowed);
        assertEq(cfg.perPaymentCap, 7);
        assertEq(cfg.perDeploymentDailyCap, 70);
    }

    function test_setToken_disable() public {
        vm.prank(owner);
        splitter.setToken(address(token), false, 0, 0);
        assertFalse(splitter.isTokenAllowed(address(token)));
        assertEq(splitter.remainingDailyAllowance(deploymentId, address(token)), 0);
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.TokenNotAllowed.selector, address(token)));
        splitter.payFees(deploymentId, appA, address(token), 1, USAGE);
    }

    function test_setToken_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(FeeSplitter.ZeroAddress.selector);
        splitter.setToken(address(0), true, 1, 1);
    }

    function test_setToken_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        splitter.setToken(address(token), true, 1, 1);
    }

    function test_setCaps() public {
        vm.expectEmit(address(splitter));
        emit TokenConfigured(address(token), true, 1_000_000, 2_000_000);
        vm.prank(owner);
        splitter.setCaps(address(token), 1_000_000, 2_000_000);
        _pay(customer, appA, 1_000_000, keccak256("a"));
        _pay(customer, appA, 1_000_000, keccak256("b"));
        vm.prank(customer);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DailyCapExceeded.selector, 2_000_001, 2_000_000));
        splitter.payFees(deploymentId, appA, address(token), 1, keccak256("c"));
    }

    function test_setCaps_revertsForDisallowedToken() public {
        MockERC20 other = new MockERC20("Other", "OTH");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.TokenNotAllowed.selector, address(other)));
        splitter.setCaps(address(other), 1, 1);
    }

    function test_setCaps_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        splitter.setCaps(address(token), 1, 1);
    }

    function test_setTreasury() public {
        address next = makeAddr("next");
        vm.expectEmit(address(splitter));
        emit TreasurySet(treasury, next);
        vm.prank(owner);
        splitter.setTreasury(next);
        assertEq(splitter.treasury(), next);
    }

    function test_setTreasury_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(FeeSplitter.ZeroAddress.selector);
        splitter.setTreasury(address(0));
    }

    function test_setTreasury_revertsOnUnwithdrawableAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.InvalidTreasury.selector, address(splitter)));
        splitter.setTreasury(address(splitter));
        address pathUsd = 0x20C0000000000000000000000000000000000000;
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.InvalidTreasury.selector, pathUsd));
        splitter.setTreasury(pathUsd);
        vm.stopPrank();
        // An address that merely starts with 0x20c0 is fine.
        vm.prank(owner);
        splitter.setTreasury(0x20c0000000000000000000010000000000000000);
    }

    function test_setTreasury_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        splitter.setTreasury(stranger);
    }

    function test_pauseUnpause() public {
        vm.startPrank(owner);
        splitter.pause();
        assertTrue(splitter.paused());
        splitter.unpause();
        assertFalse(splitter.paused());
        vm.stopPrank();
        _pay(customer, appA, 1, USAGE);
    }

    function test_pause_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        splitter.pause();
    }

    function test_unpause_revertsForNonOwner() public {
        vm.prank(owner);
        splitter.pause();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        splitter.unpause();
    }

    // ------------------------------------------------------------------------------------------------------
    // Fuzz: fee math and caps
    // ------------------------------------------------------------------------------------------------------

    function testFuzz_splitAmount(uint256 amount, uint16 bps) public view {
        amount = bound(amount, 0, type(uint256).max / 10_000);
        bps = uint16(bound(bps, 0, 5000));
        (uint256 m, uint256 t) = splitter.splitAmount(amount, bps);
        assertEq(m + t, amount, "no dust lost or created");
        assertEq(m, amount * bps / 10_000);
        assertLe(m, amount / 2, "maintainer share is at most half");
        assertGe(t, amount - amount / 2);
    }

    function testFuzz_payFees_split(uint256 amount, uint16 bps) public {
        amount = bound(amount, 1, PER_PAYMENT_CAP);
        bps = uint16(bound(bps, 0, 5000));
        vm.prank(owner);
        apps.setMaintainerShare(appA, bps);
        uint256 payerBefore = token.balanceOf(customer);
        _pay(customer, appA, amount, USAGE);
        uint256 m = amount * bps / 10_000;
        assertEq(splitter.credited(address(token), maintainer), m);
        assertEq(splitter.credited(address(token), treasury), amount - m);
        assertEq(token.balanceOf(customer), payerBefore - amount);
        _assertInvariant(address(token));
    }

    function testFuzz_topUpFees_split(uint256 first, uint256 total, uint16 bps) public {
        first = bound(first, 1, PER_PAYMENT_CAP - 1);
        total = bound(total, first + 1, PER_PAYMENT_CAP);
        bps = uint16(bound(bps, 0, 5000));
        vm.prank(owner);
        apps.setMaintainerShare(appA, bps);
        uint256 customerBefore = token.balanceOf(customer);
        uint256 signerBefore = token.balanceOf(enclaveSigner);
        _pay(customer, appA, first, USAGE);
        _topUp(enclaveSigner, appA, total, USAGE);
        uint256 m = first * bps / 10_000 + (total - first) * bps / 10_000;
        assertEq(splitter.usagePaid(deploymentId, USAGE, appA), total);
        assertEq(splitter.credited(address(token), maintainer), m);
        assertEq(splitter.credited(address(token), treasury), total - m);
        assertEq(customerBefore - token.balanceOf(customer) + signerBefore - token.balanceOf(enclaveSigner), total);
        assertEq(splitter.dailyPaid(deploymentId, address(token), block.timestamp / 1 days), total);
        _assertInvariant(address(token));
    }

    function testFuzz_perPaymentCap(uint256 cap, uint256 amount) public {
        cap = bound(cap, 1, 1e18);
        amount = bound(amount, 1, 2e18);
        vm.prank(owner);
        splitter.setCaps(address(token), cap, type(uint256).max);
        token.mint(customer, amount);
        vm.prank(customer);
        if (amount > cap) {
            vm.expectRevert(abi.encodeWithSelector(FeeSplitter.PerPaymentCapExceeded.selector, amount, cap));
        }
        splitter.payFees(deploymentId, appA, address(token), amount, USAGE);
    }

    function testFuzz_dailyCap(uint256 dailyCap, uint256[6] memory amounts) public {
        dailyCap = bound(dailyCap, 1, 50_000_000);
        vm.prank(owner);
        splitter.setCaps(address(token), PER_PAYMENT_CAP, dailyCap);
        uint256 total;
        for (uint256 i; i < amounts.length; ++i) {
            uint256 amount = bound(amounts[i], 1, PER_PAYMENT_CAP);
            bytes32 usage = keccak256(abi.encode("u", i));
            vm.prank(customer);
            if (total + amount > dailyCap) {
                vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DailyCapExceeded.selector, total + amount, dailyCap));
                splitter.payFees(deploymentId, appA, address(token), amount, usage);
            } else {
                splitter.payFees(deploymentId, appA, address(token), amount, usage);
                total += amount;
            }
        }
        assertEq(splitter.dailyPaid(deploymentId, address(token), block.timestamp / 1 days), total);
        assertLe(total, dailyCap);
        _assertInvariant(address(token));
    }

    function testFuzz_dayBoundary(uint256 secondsIntoDay) public {
        uint256 dayStart = (block.timestamp / 1 days + 1) * 1 days;
        secondsIntoDay = bound(secondsIntoDay, 0, 1 days - 1);
        vm.warp(dayStart + secondsIntoDay);
        _pay(customer, appA, 1, USAGE);
        assertEq(splitter.dailyPaid(deploymentId, address(token), dayStart / 1 days), 1);
    }
}

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
}
