// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {ITIP20, ITIP403, Tip20} from "../utils/Tip20.sol";

/// @notice Drives a FeeSplitter that holds two real TIP-20 tokens (the Tempo precompile, local genesis AlphaUSD and
///         BetaUSD), each bound to its own TIP-403 blacklist. Besides payments, top-ups, withdrawals and admin
///         changes it blacklists and unblacklists payers, recipients and FeeSplitter itself, and pauses the
///         tokens, so token transfers fail inside payFees, topUpFees and withdraw.
///         Every call is checked on its own: a success moves exactly `amount` from the payer to FeeSplitter and
///         credits exactly floor(amount * share / 10000) to the maintainer (0 if it can never withdraw) and the
///         rest to the treasury, and no other credit moves; a failure reverts with the token's own error and
///         leaves every credit, balance, daily total and leg as it was, so the same payment can be retried.
contract FeeSplitterTip20Handler is Test {
    uint256 internal constant FUNDING = 1e15;

    FeeSplitter public immutable splitter;
    AppRegistry public immutable apps;
    address public immutable owner;

    ITIP20[] public tokens;
    mapping(address token => uint64) public policyOf;
    bytes32[] public deploymentIds;
    mapping(bytes32 deploymentId => address[2] payers) internal _payers;
    bytes32[] public appIds;

    address[] public accounts;
    mapping(address account => bool) public isAccount;
    address[] internal _maintainerPool;
    address[] internal _treasuryPool;
    address[] internal _blockable;

    mapping(address token => mapping(address account => bool)) public blocked;
    mapping(address token => bool) public tokenPaused;
    bool public splitterPaused;

    mapping(address token => mapping(address account => uint256)) public ghostCredit;
    mapping(address token => uint256) public ghostPaidIn;
    mapping(address token => uint256) public ghostSwept;
    mapping(address token => uint256) public ghostWithdrawn;

    struct Leg {
        bytes32 deploymentId;
        bytes32 usageHash;
        bytes32 appId;
        ITIP20 token;
    }

    Leg[] internal _legs;
    mapping(bytes32 legKey => uint256) public ghostLegPaid;

    /// @notice A payment that a token failure stopped; retryFailed pays it again with the same usage key.
    struct Failed {
        bytes32 deploymentId;
        bytes32 usageHash;
        bytes32 appId;
        ITIP20 token;
        uint256 amount;
        uint8 payerIndex;
    }

    Failed[] internal _failed;

    uint256 public usageNonce;
    bool public unexpectedOutcome;
    bool public splitMismatch;
    bool public dirtyRevert;
    string public lastMismatch;
    mapping(string name => uint256) public calls;

    constructor(
        FeeSplitter splitter_,
        AppRegistry apps_,
        address owner_,
        ITIP20[] memory tokens_,
        bytes32[] memory deploymentIds_,
        address[2][] memory payers_,
        bytes32[] memory appIds_,
        address[] memory initialAccounts
    ) {
        splitter = splitter_;
        apps = apps_;
        owner = owner_;
        for (uint256 i; i < tokens_.length; ++i) {
            tokens.push(tokens_[i]);
        }
        for (uint256 i; i < deploymentIds_.length; ++i) {
            deploymentIds.push(deploymentIds_[i]);
            _payers[deploymentIds_[i]] = payers_[i];
            _blockable.push(payers_[i][0]);
            _blockable.push(payers_[i][1]);
        }
        for (uint256 i; i < appIds_.length; ++i) {
            appIds.push(appIds_[i]);
        }
        for (uint256 i; i < initialAccounts.length; ++i) {
            _track(initialAccounts[i]);
            _blockable.push(initialAccounts[i]);
        }
        _blockable.push(address(splitter_));
        for (uint256 i; i < 3; ++i) {
            address m = makeAddr(string.concat("tip20-maintainer-", vm.toString(i)));
            address t = makeAddr(string.concat("tip20-treasury-", vm.toString(i)));
            _maintainerPool.push(m);
            _treasuryPool.push(t);
            _blockable.push(m);
            _blockable.push(t);
        }
        // Recipients that can never withdraw: FeeSplitter itself, a TIP-20 token, and any 0x20c0... address.
        _maintainerPool.push(address(splitter_));
        _maintainerPool.push(address(tokens_[0]));
        _maintainerPool.push(0x20c000000000000000000000000000000000beeF);
        _treasuryPool.push(address(splitter_));
        _treasuryPool.push(address(tokens_[1]));
        _treasuryPool.push(0x20c00000000000000000000000000000000000ff);
        // The first maintainer can also become the treasury, so one account receives both parts.
        _treasuryPool.push(_maintainerPool[0]);
    }

    /// @notice Called by the test once the policies exist (the handler is their admin).
    function setPolicy(address token, uint64 policyId) external {
        policyOf[token] = policyId;
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

    function legCount() external view returns (uint256) {
        return _legs.length;
    }

    function leg(uint256 i) external view returns (Leg memory) {
        return _legs[i];
    }

    function failedCount() external view returns (uint256) {
        return _failed.length;
    }

    function failed(uint256 i) external view returns (Failed memory) {
        return _failed[i];
    }

    function legKey(bytes32 deploymentId, bytes32 usageHash, bytes32 appId) public pure returns (bytes32) {
        return keccak256(abi.encode(deploymentId, usageHash, appId));
    }

    function cannotWithdraw(address account) public view returns (bool) {
        return account == address(splitter) || bytes12(bytes20(account)) == bytes12(0x20c000000000000000000000);
    }

    // ------------------------------------------------------------------------------------------------------
    // Payments
    // ------------------------------------------------------------------------------------------------------

    function payFees(uint256 depSeed, uint256 appSeed, uint256 tokenSeed, uint256 amount, bool bySigner) external {
        bytes32 id = deploymentIds[depSeed % deploymentIds.length];
        ITIP20 token = tokens[tokenSeed % tokens.length];
        uint256 maxAmount = _payable(id, token, 0);
        if (maxAmount == 0) return;
        amount = bound(amount, 1, maxAmount);
        bytes32 usageHash = keccak256(abi.encode("tip20-usage", ++usageNonce));
        _pay(id, appIds[appSeed % appIds.length], token, amount, usageHash, bySigner ? 1 : 0, false, 0);
    }

    function topUpFees(uint256 legSeed, uint256 total, bool bySigner) external {
        if (_legs.length == 0) return;
        Leg memory l = _legs[legSeed % _legs.length];
        uint256 paid = splitter.usagePaid(l.deploymentId, l.usageHash, l.appId);
        uint256 maxTotal = _payable(l.deploymentId, l.token, paid);
        if (maxTotal <= paid) return;
        total = bound(total, paid + 1, maxTotal);
        _pay(l.deploymentId, l.appId, l.token, total, l.usageHash, bySigner ? 1 : 0, true, paid);
    }

    /// @dev Pays a payment that a token failure stopped earlier, with the same usage key and amount.
    function retryFailed(uint256 seed) external {
        if (_failed.length == 0) return;
        uint256 i = seed % _failed.length;
        Failed memory f = _failed[i];
        _failed[i] = _failed[_failed.length - 1];
        _failed.pop();
        if (_payable(f.deploymentId, f.token, 0) < f.amount) return; // a cap moved since; drop it
        if (splitter.usagePaid(f.deploymentId, f.usageHash, f.appId) != 0) {
            _mismatch("a failed payment opened its leg");
            return;
        }
        _pay(f.deploymentId, f.appId, f.token, f.amount, f.usageHash, f.payerIndex, false, 0);
        calls["retryFailed"]++;
    }

    function withdraw(uint256 accountSeed, uint256 tokenSeed) external {
        address account = accounts[accountSeed % accounts.length];
        ITIP20 token = tokens[tokenSeed % tokens.length];
        uint256 credit = ghostCredit[address(token)][account];
        if (credit == 0) return;
        bytes4 expectedError = _transferError(token, address(splitter), account);
        bytes32 before = _snapshot(token);
        uint256 balanceBefore = token.balanceOf(account);

        vm.prank(account);
        try splitter.withdraw(address(token)) {
            if (expectedError != bytes4(0)) _mismatch("withdraw succeeded through a token failure");
            if (token.balanceOf(account) != balanceBefore + credit) {
                splitMismatch = true;
                lastMismatch = "withdraw paid a different amount than the credit";
            }
            ghostCredit[address(token)][account] = 0;
            ghostWithdrawn[address(token)] += credit;
            calls["withdraw"]++;
        } catch (bytes memory reason) {
            _checkFailure(expectedError, reason, "withdraw");
            if (_snapshot(token) != before || token.balanceOf(account) != balanceBefore) {
                dirtyRevert = true;
                lastMismatch = "failed withdraw changed state";
            }
            calls["withdrawFailed"]++;
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Token failures
    // ------------------------------------------------------------------------------------------------------

    function setBlocked(uint256 tokenSeed, uint256 targetSeed, uint256 restrictSeed) external {
        ITIP20 token = tokens[tokenSeed % tokens.length];
        address target = _blockable[targetSeed % _blockable.length];
        bool restricted = restrictSeed % 3 == 0;
        Tip20.REGISTRY.modifyPolicyBlacklist(policyOf[address(token)], target, restricted);
        blocked[address(token)][target] = restricted;
        calls[restricted ? "block" : "unblock"]++;
    }

    /// @dev Unblocks everyone for a token, so failed payments become payable again.
    function unblockAll(uint256 tokenSeed) external {
        ITIP20 token = tokens[tokenSeed % tokens.length];
        for (uint256 i; i < _blockable.length; ++i) {
            if (blocked[address(token)][_blockable[i]]) {
                Tip20.REGISTRY.modifyPolicyBlacklist(policyOf[address(token)], _blockable[i], false);
                blocked[address(token)][_blockable[i]] = false;
            }
        }
        if (tokenPaused[address(token)]) {
            token.unpause();
            tokenPaused[address(token)] = false;
        }
        calls["unblockAll"]++;
    }

    function setTokenPaused(uint256 tokenSeed, uint256 pauseSeed) external {
        ITIP20 token = tokens[tokenSeed % tokens.length];
        bool pause = pauseSeed % 4 == 0;
        if (pause == tokenPaused[address(token)]) return;
        if (pause) token.pause();
        else token.unpause();
        tokenPaused[address(token)] = pause;
        calls[pause ? "tokenPause" : "tokenUnpause"]++;
    }

    function setSplitterPaused(uint256 pauseSeed) external {
        bool pause = pauseSeed % 4 == 0;
        if (pause == splitterPaused) return;
        vm.prank(owner);
        if (pause) splitter.pause();
        else splitter.unpause();
        splitterPaused = pause;
        calls[pause ? "splitterPause" : "splitterUnpause"]++;
    }

    // ------------------------------------------------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------------------------------------------------

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
        try splitter.setTreasury(next) {
            if (cannotWithdraw(next)) _mismatch("setTreasury accepted an address that can never withdraw");
            _track(next);
            calls["setTreasury"]++;
        } catch (bytes memory reason) {
            // forge-lint: disable-next-line(unsafe-typecast)
            if (!cannotWithdraw(next) || bytes4(reason) != FeeSplitter.InvalidTreasury.selector) {
                _mismatch("setTreasury rejected a valid treasury");
            }
            calls["setTreasuryRejected"]++;
        }
    }

    function setCaps(uint256 tokenSeed, uint256 perPayment, uint256 daily) external {
        ITIP20 token = tokens[tokenSeed % tokens.length];
        perPayment = bound(perPayment, 1, 10_000_000);
        daily = bound(daily, perPayment, 50_000_000);
        vm.prank(owner);
        splitter.setCaps(address(token), perPayment, daily);
        calls["setCaps"]++;
    }

    /// @dev A direct transfer breaks balance == totalCredited until the owner sweeps, so both happen in one step.
    function directTransferAndSweep(uint256 tokenSeed, uint256 amount) external {
        ITIP20 token = tokens[tokenSeed % tokens.length];
        if (tokenPaused[address(token)] || blocked[address(token)][address(splitter)]) return;
        amount = bound(amount, 1, 10_000_000);
        token.mint(address(splitter), amount);
        address t = splitter.treasury();
        vm.prank(owner);
        splitter.sweepUnaccounted(address(token));
        ghostCredit[address(token)][t] += amount;
        ghostSwept[address(token)] += amount;
        calls["sweep"]++;
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 2 days));
        calls["warp"]++;
    }

    // ------------------------------------------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------------------------------------------

    /// @dev The highest total payable now for a leg already at `paid` (0 when none).
    function _payable(bytes32 id, ITIP20 token, uint256 paid) internal view returns (uint256) {
        FeeSplitter.TokenConfig memory cfg = splitter.tokenConfig(address(token));
        if (!cfg.allowed) return 0;
        uint256 maxTotal = paid + splitter.remainingDailyAllowance(id, address(token));
        return maxTotal < cfg.perPaymentCap ? maxTotal : cfg.perPaymentCap;
    }

    struct PayCall {
        bytes32 id;
        bytes32 appId;
        ITIP20 token;
        uint256 total;
        bytes32 usageHash;
        address payer;
        bool topUp;
        uint256 amount;
        address maintainer;
        address treasury;
        uint256 maintainerAmount;
        bytes4 expectedError;
        bytes32 snapshot;
        uint256 payerBefore;
        uint256 splitterBefore;
        uint256[] creditsBefore;
    }

    function _pay(
        bytes32 id,
        bytes32 appId,
        ITIP20 token,
        uint256 total,
        bytes32 usageHash,
        uint8 payerIndex,
        bool topUp,
        uint256 paid
    ) internal {
        PayCall memory c;
        c.id = id;
        c.appId = appId;
        c.token = token;
        c.total = total;
        c.usageHash = usageHash;
        c.payer = _payers[id][payerIndex];
        c.topUp = topUp;
        c.amount = total - paid;
        uint16 bps;
        (c.maintainer, bps) = apps.payoutInfo(appId);
        c.treasury = splitter.treasury();
        c.maintainerAmount = cannotWithdraw(c.maintainer) ? 0 : c.amount * bps / 10_000;
        c.expectedError =
            splitterPaused ? Pausable.EnforcedPause.selector : _transferError(token, c.payer, address(splitter));
        c.snapshot = _snapshot(token);
        c.payerBefore = token.balanceOf(c.payer);
        c.splitterBefore = token.balanceOf(address(splitter));
        c.creditsBefore = _credits(token);

        bool ok;
        bytes memory reason;
        vm.prank(c.payer);
        if (topUp) {
            try splitter.topUpFees(id, appId, address(token), total, usageHash) {
                ok = true;
            } catch (bytes memory r) {
                reason = r;
            }
        } else {
            try splitter.payFees(id, appId, address(token), total, usageHash) {
                ok = true;
            } catch (bytes memory r) {
                reason = r;
            }
        }
        if (ok) _paid(c, payerIndex);
        else _payFailed(c, reason, payerIndex);
    }

    function _paid(PayCall memory c, uint8) internal {
        string memory what = c.topUp ? "topUpFees" : "payFees";
        if (c.expectedError != bytes4(0)) _mismatch(string.concat(what, " succeeded through a failure"));
        uint256 treasuryAmount = c.amount - c.maintainerAmount;
        if (treasuryAmount < c.maintainerAmount) _splitFail("maintainer got more than the treasury");
        if (c.token.balanceOf(c.payer) + c.amount != c.payerBefore) _splitFail("payer did not pay exactly amount");
        if (c.token.balanceOf(address(splitter)) != c.splitterBefore + c.amount) {
            _splitFail("FeeSplitter did not receive exactly amount");
        }
        // Exactly the maintainer and the treasury gain, by their shares, which sum to the amount.
        uint256[] memory creditsAfter = _credits(c.token);
        uint256 gained;
        for (uint256 i; i < accounts.length; ++i) {
            address a = accounts[i];
            uint256 expected = (a == c.maintainer ? c.maintainerAmount : 0) + (a == c.treasury ? treasuryAmount : 0);
            uint256 beforeCredit = i < c.creditsBefore.length ? c.creditsBefore[i] : 0;
            if (creditsAfter[i] != beforeCredit + expected) _splitFail("a credit moved by other than its share");
            gained += creditsAfter[i] - beforeCredit;
        }
        if (gained != c.amount) _splitFail("credits gained != amount");
        if (splitter.totalCredited(address(c.token)) != _sum(creditsAfter)) _splitFail("totalCredited");

        ghostCredit[address(c.token)][c.maintainer] += c.maintainerAmount;
        ghostCredit[address(c.token)][c.treasury] += treasuryAmount;
        ghostPaidIn[address(c.token)] += c.amount;
        bytes32 k = legKey(c.id, c.usageHash, c.appId);
        if (!c.topUp) _legs.push(Leg(c.id, c.usageHash, c.appId, c.token));
        ghostLegPaid[k] = c.total;
        calls[what]++;
        if (c.maintainerAmount == 0 && cannotWithdraw(c.maintainer)) calls["shareRedirectedToTreasury"]++;
        if (c.maintainer == c.treasury) calls["maintainerIsTreasury"]++;
    }

    function _payFailed(PayCall memory c, bytes memory reason, uint8 payerIndex) internal {
        string memory what = c.topUp ? "topUpFees" : "payFees";
        _checkFailure(c.expectedError, reason, what);
        if (
            _snapshot(c.token) != c.snapshot || c.token.balanceOf(c.payer) != c.payerBefore
                || c.token.balanceOf(address(splitter)) != c.splitterBefore
        ) {
            dirtyRevert = true;
            lastMismatch = string.concat("failed ", what, " changed state");
        }
        uint256 legPaid = splitter.usagePaid(c.id, c.usageHash, c.appId);
        if (legPaid != (c.topUp ? c.total - c.amount : 0)) {
            dirtyRevert = true;
            lastMismatch = string.concat("failed ", what, " moved its leg");
        }
        if (!c.topUp) _failed.push(Failed(c.id, c.usageHash, c.appId, c.token, c.amount, payerIndex));
        calls[string.concat(what, "Failed")]++;
    }

    /// @dev The error a transfer of `token` from `from` to `to` reverts with now, or 0 if it goes through.
    function _transferError(ITIP20 token, address from, address to) internal view returns (bytes4) {
        if (tokenPaused[address(token)]) return Tip20.CONTRACT_PAUSED;
        if (blocked[address(token)][from] || blocked[address(token)][to]) return Tip20.POLICY_FORBIDS;
        return bytes4(0);
    }

    function _checkFailure(bytes4 expectedError, bytes memory reason, string memory what) internal {
        if (expectedError == bytes4(0)) {
            _mismatch(string.concat(what, " reverted without a token failure"));
            return;
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes4 got = bytes4(reason);
        // A paused token that also blocks the account may report either failure.
        bool alsoBlocked = expectedError == Tip20.CONTRACT_PAUSED && got == Tip20.POLICY_FORBIDS;
        if (got != expectedError && !alsoBlocked) _mismatch(string.concat(what, " reverted with another error"));
    }

    /// @dev Hash of everything a payment or withdrawal could touch for `token`.
    function _snapshot(ITIP20 token) internal view returns (bytes32 h) {
        h = keccak256(
            abi.encode(
                splitter.totalCredited(address(token)),
                token.balanceOf(address(splitter)),
                _credits(token),
                block.timestamp / 1 days
            )
        );
        for (uint256 i; i < deploymentIds.length; ++i) {
            h = keccak256(abi.encode(h, splitter.dailyPaid(deploymentIds[i], address(token), block.timestamp / 1 days)));
        }
    }

    function _credits(ITIP20 token) internal view returns (uint256[] memory c) {
        c = new uint256[](accounts.length);
        for (uint256 i; i < accounts.length; ++i) {
            c[i] = splitter.credited(address(token), accounts[i]);
        }
    }

    function _sum(uint256[] memory xs) internal pure returns (uint256 s) {
        for (uint256 i; i < xs.length; ++i) {
            s += xs[i];
        }
    }

    function _track(address account) internal {
        if (!isAccount[account]) {
            isAccount[account] = true;
            accounts.push(account);
        }
    }

    function _splitFail(string memory what) internal {
        splitMismatch = true;
        lastMismatch = what;
    }

    function _mismatch(string memory what) internal {
        unexpectedOutcome = true;
        lastMismatch = what;
    }
}
