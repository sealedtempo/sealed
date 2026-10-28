// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {MockERC20} from "../mocks/MockERC20.sol";

/// @notice Drives FeeSplitter with random payments, withdrawals, maintainer/treasury/share changes, direct
///         transfers (followed by a sweep), cap changes and time jumps, while tracking every address that can
///         hold a credit and ghost totals of what went in and out.
contract FeeSplitterHandler is Test {
    FeeSplitter public immutable splitter;
    AppRegistry public immutable apps;
    DeploymentRegistry public immutable registry;
    address public immutable owner;

    MockERC20[] public tokens;
    bytes32[] public deploymentIds;
    mapping(bytes32 deploymentId => address[2] payers) internal _payers;
    bytes32[] public appIds;

    address[] public accounts;
    mapping(address account => bool) public isAccount;
    address[] internal _maintainerPool;
    address[] internal _treasuryPool;

    mapping(address token => uint256) public ghostPaidIn;
    mapping(address token => uint256) public ghostSwept;
    mapping(address token => uint256) public ghostWithdrawn;
    mapping(bytes32 key => uint256) public ghostDaily; // keccak(deploymentId, token, day)

    uint256 public usageNonce;
    bool public capViolated;
    bool public unexpectedRevert;
    bool public withdrawMismatch;
    mapping(string name => uint256) public calls;

    constructor(
        FeeSplitter splitter_,
        AppRegistry apps_,
        DeploymentRegistry registry_,
        address owner_,
        MockERC20[] memory tokens_,
        bytes32[] memory deploymentIds_,
        address[2][] memory payers_,
        bytes32[] memory appIds_,
        address[] memory initialAccounts
    ) {
        splitter = splitter_;
        apps = apps_;
        registry = registry_;
        owner = owner_;
        for (uint256 i; i < tokens_.length; ++i) {
            tokens.push(tokens_[i]);
        }
        for (uint256 i; i < deploymentIds_.length; ++i) {
            deploymentIds.push(deploymentIds_[i]);
            _payers[deploymentIds_[i]] = payers_[i];
        }
        for (uint256 i; i < appIds_.length; ++i) {
            appIds.push(appIds_[i]);
        }
        for (uint256 i; i < initialAccounts.length; ++i) {
            _track(initialAccounts[i]);
        }
        for (uint256 i; i < 4; ++i) {
            _maintainerPool.push(makeAddr(string.concat("maintainer-pool-", vm.toString(i))));
            _treasuryPool.push(makeAddr(string.concat("treasury-pool-", vm.toString(i))));
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Views for the invariant contract
    // ------------------------------------------------------------------------------------------------------

    function tokenCount() external view returns (uint256) {
        return tokens.length;
    }

    function accountCount() external view returns (uint256) {
        return accounts.length;
    }

    function deploymentCount() external view returns (uint256) {
        return deploymentIds.length;
    }

    // ------------------------------------------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------------------------------------------

    function payFees(uint256 depSeed, uint256 appSeed, uint256 tokenSeed, uint256 amount, bool bySigner) external {
        bytes32 id = deploymentIds[depSeed % deploymentIds.length];
        bytes32 appId = appIds[appSeed % appIds.length];
        MockERC20 token = tokens[tokenSeed % tokens.length];
        FeeSplitter.TokenConfig memory cfg = splitter.tokenConfig(address(token));
        if (!cfg.allowed || cfg.perPaymentCap == 0) return;
        uint256 remaining = splitter.remainingDailyAllowance(id, address(token));
        uint256 maxAmount = remaining < cfg.perPaymentCap ? remaining : cfg.perPaymentCap;
        if (maxAmount == 0) return;
        amount = bound(amount, 1, maxAmount);

        address payer = _payers[id][bySigner ? 1 : 0];
        token.mint(payer, amount);
        vm.prank(payer);
        token.approve(address(splitter), amount);

        bytes32 usageHash = keccak256(abi.encode("usage", ++usageNonce));
        vm.prank(payer);
        splitter.payFees(id, appId, address(token), amount, usageHash);

        ghostPaidIn[address(token)] += amount;
        ghostDaily[keccak256(abi.encode(id, address(token), block.timestamp / 1 days))] += amount;
        calls["payFees"]++;
    }

    /// @dev Tries to pay more than the day's remaining allowance (within the per-payment cap) and records a
    ///      violation if FeeSplitter accepts it.
    function payFeesOverDailyCap(uint256 depSeed, uint256 tokenSeed, uint256 extra) external {
        bytes32 id = deploymentIds[depSeed % deploymentIds.length];
        MockERC20 token = tokens[tokenSeed % tokens.length];
        FeeSplitter.TokenConfig memory cfg = splitter.tokenConfig(address(token));
        uint256 remaining = splitter.remainingDailyAllowance(id, address(token));
        if (!cfg.allowed || remaining >= cfg.perPaymentCap) return;
        uint256 amount = bound(extra, remaining + 1, cfg.perPaymentCap);
        address payer = _payers[id][0];
        token.mint(payer, amount);
        vm.prank(payer);
        token.approve(address(splitter), amount);
        vm.prank(payer);
        try splitter.payFees(id, appIds[0], address(token), amount, keccak256(abi.encode("over", ++usageNonce))) {
            capViolated = true;
        } catch (bytes memory reason) {
            // forge-lint: disable-next-line(unsafe-typecast)
            if (bytes4(reason) != FeeSplitter.DailyCapExceeded.selector) unexpectedRevert = true;
        }
        calls["payFeesOverDailyCap"]++;
    }

    function withdraw(uint256 accountSeed, uint256 tokenSeed) external {
        address account = accounts[accountSeed % accounts.length];
        MockERC20 token = tokens[tokenSeed % tokens.length];
        uint256 credit = splitter.credited(address(token), account);
        if (credit == 0) return;
        uint256 before = token.balanceOf(account);
        vm.prank(account);
        splitter.withdraw(address(token));
        if (token.balanceOf(account) != before + credit) withdrawMismatch = true;
        ghostWithdrawn[address(token)] += credit;
        calls["withdraw"]++;
    }

    function setMaintainer(uint256 appSeed, uint256 poolSeed) external {
        bytes32 appId = appIds[appSeed % appIds.length];
        address next = _maintainerPool[poolSeed % _maintainerPool.length];
        vm.prank(owner);
        apps.setMaintainer(appId, next);
        _track(next);
        calls["setMaintainer"]++;
    }

    function setMaintainerShare(uint256 appSeed, uint256 bps) external {
        bytes32 appId = appIds[appSeed % appIds.length];
        vm.prank(owner);
        apps.setMaintainerShare(appId, uint16(bound(bps, 0, 5000)));
        calls["setMaintainerShare"]++;
    }

    function setTreasury(uint256 poolSeed) external {
        address next = _treasuryPool[poolSeed % _treasuryPool.length];
        vm.prank(owner);
        splitter.setTreasury(next);
        _track(next);
        calls["setTreasury"]++;
    }

    function setCaps(uint256 tokenSeed, uint256 perPayment, uint256 daily) external {
        MockERC20 token = tokens[tokenSeed % tokens.length];
        perPayment = bound(perPayment, 1, 10_000_000);
        daily = bound(daily, perPayment, 50_000_000);
        vm.prank(owner);
        splitter.setCaps(address(token), perPayment, daily);
        calls["setCaps"]++;
    }

    /// @dev A direct transfer breaks balance == totalCredited until the owner sweeps, so both happen in one step.
    function directTransferAndSweep(uint256 tokenSeed, uint256 amount) external {
        MockERC20 token = tokens[tokenSeed % tokens.length];
        amount = bound(amount, 1, 10_000_000);
        token.mint(address(splitter), amount);
        vm.prank(owner);
        splitter.sweepUnaccounted(address(token));
        ghostSwept[address(token)] += amount;
        calls["sweep"]++;
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 2 days));
        calls["warp"]++;
    }

    function _track(address account) internal {
        if (!isAccount[account]) {
            isAccount[account] = true;
            accounts.push(account);
        }
    }
}
