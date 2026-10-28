// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IAppRegistry} from "./interfaces/IAppRegistry.sol";
import {IDeploymentRegistry} from "./interfaces/IDeploymentRegistry.sol";
import {OwnableNoRenounce} from "./utils/OwnableNoRenounce.sol";

/// @title FeeSplitter
/// @notice Collects per-app usage fees from a deployment's customer (or its enclave signer) and splits each payment
///         between the app's maintainer and the platform treasury. Recipients withdraw with a pull pattern.
/// @dev Invariant, per token: sum of credited balances == totalCredited[token] == token.balanceOf(this), as long as
///      nobody transfers tokens in directly (sweepUnaccounted credits such transfers to the treasury and restores
///      equality). Fee-on-transfer tokens are rejected by a balance-delta check. Pausing stops payments only;
///      withdrawals always work.
///      Usage dedupe (contract review): payFees opens each (deploymentId, usageHash, appId) once. A usageHash is the
///      EIP-712 digest of a report that already names its deployment, so keying by deployment changes nothing for
///      honest payers and stops the payer of one deployment from consuming another deployment's usage keys.
///      FeeSplitter does not see the signed report, so a deployment's own payer can open a leg with less than the
///      report's fee; topUpFees raises an open leg to a higher total, which settlement does for every short leg.
contract FeeSplitter is OwnableNoRenounce, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Contract version.
    string public constant VERSION = "1.0.0";

    /// @notice Basis-point denominator.
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Address prefix of Tempo TIP-20 tokens (pathUSD is 0x20c0000000000000000000000000000000000000).
    bytes12 public constant TIP20_ADDRESS_PREFIX = 0x20c000000000000000000000;

    /// @notice Allowlist entry and caps for a payment token.
    /// @param allowed Whether payFees and topUpFees accept the token.
    /// @param perPaymentCap Maximum amount of one payFees call (and of a leg after topUpFees), in token base units.
    /// @param perDeploymentDailyCap Maximum total per deployment per UTC day (block.timestamp / 1 days).
    struct TokenConfig {
        bool allowed;
        uint256 perPaymentCap;
        uint256 perDeploymentDailyCap;
    }

    /// @notice Where credits come from, as emitted in Credited.
    enum CreditKind {
        Maintainer,
        Treasury,
        Sweep
    }

    /// @notice The deployment registry.
    IDeploymentRegistry public immutable deploymentRegistry;
    /// @notice The app catalog.
    IAppRegistry public immutable appRegistry;
    /// @notice The fee token allowlisted at deploy (pathUSD on Tempo).
    address public immutable FEE_TOKEN;

    /// @notice Current treasury. Receives the non-maintainer part of every payment.
    address public treasury;

    mapping(address token => TokenConfig config) private _tokenConfigs;

    /// @notice Withdrawable balance per (token, account).
    mapping(address token => mapping(address account => uint256 amount)) public credited;

    /// @notice Sum of all credited balances per token.
    mapping(address token => uint256 amount) public totalCredited;

    /// @notice Amount paid per (deployment, token, day), where day = timestamp / 1 days.
    mapping(bytes32 deploymentId => mapping(address token => mapping(uint256 day => uint256 amount))) public dailyPaid;

    /// @notice Amount paid for (deploymentId, usageHash, appId); 0 when unpaid (payments are always > 0). Offchain
    ///         settlement compares it with the fee of the signed usage report (the contract does not see the report)
    ///         and tops a short leg up to the fee with topUpFees.
    mapping(bytes32 deploymentId => mapping(bytes32 usageHash => mapping(bytes32 appId => uint256 amount))) public
        usagePaid;

    /// @notice Emitted for every payment.
    /// @param maintainerAmount The part credited to the maintainer; the rest went to the treasury.
    event FeesPaid(
        bytes32 indexed deploymentId,
        bytes32 indexed appId,
        address indexed payer,
        address token,
        uint256 amount,
        uint256 maintainerAmount,
        bytes32 usageHash
    );

    /// @notice Emitted for every non-zero credit.
    /// @param appId The app the credit came from (bytes32(0) for sweeps).
    /// @param newBalance The recipient's credited balance after this credit.
    event Credited(
        address indexed recipient,
        address indexed token,
        bytes32 indexed appId,
        CreditKind kind,
        uint256 amount,
        uint256 newBalance
    );

    /// @notice Emitted by withdraw.
    /// @param account The account whose full credit was paid out to itself.
    event Withdrawn(address indexed account, address indexed token, uint256 amount);

    /// @notice Emitted by sweepUnaccounted.
    event Swept(address indexed token, address indexed treasury, uint256 amount);

    /// @notice Emitted by setToken, setCaps and the constructor with the token's full configuration.
    event TokenConfigured(address indexed token, bool allowed, uint256 perPaymentCap, uint256 perDeploymentDailyCap);

    /// @notice Emitted by setTreasury and the constructor.
    event TreasurySet(address indexed previousTreasury, address indexed newTreasury);

    /// @notice A zero address was given.
    error ZeroAddress();
    /// @notice The token is not allowlisted.
    error TokenNotAllowed(address token);
    /// @notice amount was zero.
    error ZeroAmount();
    /// @notice usageHash was zero.
    error ZeroUsageHash();
    /// @notice amount is above the token's per-payment cap.
    error PerPaymentCapExceeded(uint256 amount, uint256 cap);
    /// @notice The day's total for the deployment would exceed the daily cap.
    error DailyCapExceeded(uint256 newDailyTotal, uint256 cap);
    /// @notice The deployment is not Active.
    error DeploymentNotActive(bytes32 deploymentId);
    /// @notice The app is not part of the deployment's approved stack.
    error AppNotInDeployment(bytes32 deploymentId, bytes32 appId);
    /// @notice The caller is neither the deployment's customer nor its enclave signer.
    error UnauthorizedPayer(address caller);
    /// @notice This (deploymentId, usageHash, appId) was already paid.
    error UsageAlreadyPaid(bytes32 deploymentId, bytes32 usageHash, bytes32 appId);
    /// @notice topUpFees on a (deploymentId, usageHash, appId) that payFees has not opened.
    error UsageNotPaid(bytes32 deploymentId, bytes32 usageHash, bytes32 appId);
    /// @notice topUpFees with a total that is not above the amount already paid.
    error NothingToTopUp(bytes32 deploymentId, bytes32 usageHash, bytes32 appId, uint256 paid);
    /// @notice The contract's balance did not grow by exactly the amount (fee-on-transfer or rebasing token).
    error TransferAmountMismatch(uint256 expected, uint256 received);
    /// @notice The caller has no credited balance for the token.
    error NothingToWithdraw(address token);
    /// @notice The contract holds no unaccounted balance for the token.
    error NothingToSweep(address token);
    /// @notice The treasury cannot receive withdrawals: FeeSplitter itself or a TIP-20 token address.
    error InvalidTreasury(address treasury);
    /// @notice appRegistry_ is not the AppRegistry that deploymentRegistry_ resolves releases with.
    error AppRegistryMismatch(address deploymentRegistryApps, address appRegistry);

    /// @param initialOwner The owner (OWNER).
    /// @param deploymentRegistry_ The DeploymentRegistry.
    /// @param appRegistry_ The AppRegistry.
    /// @param feeToken The fee token to allowlist (pathUSD).
    /// @param treasury_ The treasury.
    /// @param perPaymentCap Per-payment cap for feeToken (default 5_000_000 = 5 USD).
    /// @param perDeploymentDailyCap Per-deployment daily cap for feeToken (default 20_000_000 = 20 USD).
    constructor(
        address initialOwner,
        IDeploymentRegistry deploymentRegistry_,
        IAppRegistry appRegistry_,
        address feeToken,
        address treasury_,
        uint256 perPaymentCap,
        uint256 perDeploymentDailyCap
    ) OwnableNoRenounce(initialOwner) {
        if (
            address(deploymentRegistry_) == address(0) || address(appRegistry_) == address(0) || feeToken == address(0)
                || treasury_ == address(0)
        ) revert ZeroAddress();
        // appInDeployment resolves apps through the registry's AppRegistry and payoutInfo through ours: they must
        // be the same contract.
        address registryApps = address(deploymentRegistry_.appRegistry());
        if (registryApps != address(appRegistry_)) revert AppRegistryMismatch(registryApps, address(appRegistry_));
        if (_cannotWithdraw(treasury_)) revert InvalidTreasury(treasury_);
        deploymentRegistry = deploymentRegistry_;
        appRegistry = appRegistry_;
        FEE_TOKEN = feeToken;
        treasury = treasury_;
        emit TreasurySet(address(0), treasury_);
        _setToken(feeToken, true, perPaymentCap, perDeploymentDailyCap);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Payments
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Pays a usage fee for one app of a deployment. The caller must be the deployment's customer or its
    ///         enclave signer and must have approved this contract for `amount` of `token`.
    /// @dev Credits amount * maintainerShareBps / 10000 (rounded down) to the app's current maintainer and the rest
    ///      to the current treasury. A maintainer address that could never withdraw (this contract or a TIP-20 token
    ///      address) gets no share: the whole amount goes to the treasury (FeesPaid.maintainerAmount is 0), so no
    ///      credit is locked forever. Zero credits emit no Credited event.
    /// @param deploymentId An Active deployment.
    /// @param appId An app of the deployment's approved stack.
    /// @param token An allowlisted token.
    /// @param amount Amount in token base units, 1..perPaymentCap.
    /// @param usageHash EIP-712 digest of the usage report (non-zero); payFees opens each (deploymentId, usageHash,
    ///        appId) once, and topUpFees completes a short one.
    function payFees(bytes32 deploymentId, bytes32 appId, address token, uint256 amount, bytes32 usageHash)
        external
        whenNotPaused
        nonReentrant
    {
        _checkPayer(deploymentId, appId);
        _recordPayment(deploymentId, appId, token, amount, usageHash, false);
        _collect(deploymentId, appId, token, amount, usageHash);
    }

    /// @notice Raises the amount paid for an opened (deploymentId, usageHash, appId) to `total` and pulls the
    ///         difference. Settlement uses it when a leg was paid less than its report's fee (contract review
    ///         logic-F1 b / funds-F-02): FeeSplitter cannot see the report, the deployment's own payer can open a
    ///         leg with any amount, and payFees cannot be repeated. Same callers, caps and split as payFees; the
    ///         difference counts against the daily cap and emits FeesPaid with that difference as `amount`, so the
    ///         FeesPaid amounts of a leg sum to usagePaid.
    /// @dev Retry-safe: a second call with the same total reverts NothingToTopUp instead of paying twice, and a
    ///      payer's own earlier top-up only lowers the difference pulled. The caller approves at least
    ///      `total - usagePaid(deploymentId, usageHash, appId)` of `token`.
    /// @param deploymentId An Active deployment.
    /// @param appId An app of the deployment's approved stack.
    /// @param token An allowlisted token.
    /// @param total The leg's new amount paid (the report's fee), above usagePaid and at most perPaymentCap.
    /// @param usageHash A usage key that payFees already opened for this deployment and app.
    function topUpFees(bytes32 deploymentId, bytes32 appId, address token, uint256 total, bytes32 usageHash)
        external
        whenNotPaused
        nonReentrant
    {
        _checkPayer(deploymentId, appId);
        uint256 amount = _recordPayment(deploymentId, appId, token, total, usageHash, true);
        _collect(deploymentId, appId, token, amount, usageHash);
    }

    /// @notice Withdraws the caller's full credited balance of a token to the caller. Works while paused.
    /// @dev Pays only msg.sender, never a third address: an account that the token's TIP-403 policy blocks from
    ///      receiving cannot move its credit elsewhere.
    /// @param token The token.
    function withdraw(address token) external nonReentrant {
        uint256 amount = credited[token][msg.sender];
        if (amount == 0) revert NothingToWithdraw(token);
        credited[token][msg.sender] = 0;
        totalCredited[token] -= amount;
        emit Withdrawn(msg.sender, token, amount);
        IERC20(token).safeTransfer(msg.sender, amount);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Admin
    // ---------------------------------------------------------------------------------------------------------

    /// @notice Credits tokens held by this contract beyond totalCredited (direct transfers) to the treasury.
    ///         Owner only.
    /// @param token The token.
    function sweepUnaccounted(address token) external onlyOwner nonReentrant {
        uint256 balance = IERC20(token).balanceOf(address(this));
        uint256 accounted = totalCredited[token];
        if (balance <= accounted) revert NothingToSweep(token);
        uint256 excess = balance - accounted;
        address treasury_ = treasury;
        _credit(token, treasury_, bytes32(0), CreditKind.Sweep, excess);
        emit Swept(token, treasury_, excess);
    }

    /// @notice Adds, updates or disables a payment token. Owner only.
    /// @param token The token (non-zero).
    /// @param allowed Whether payFees and topUpFees accept it.
    /// @param perPaymentCap Per-payment cap in base units.
    /// @param perDeploymentDailyCap Per-deployment daily cap in base units.
    function setToken(address token, bool allowed, uint256 perPaymentCap, uint256 perDeploymentDailyCap)
        external
        onlyOwner
    {
        _setToken(token, allowed, perPaymentCap, perDeploymentDailyCap);
    }

    /// @notice Updates the caps of an allowlisted token. Owner only.
    /// @param token An allowlisted token.
    /// @param perPaymentCap Per-payment cap in base units.
    /// @param perDeploymentDailyCap Per-deployment daily cap in base units.
    function setCaps(address token, uint256 perPaymentCap, uint256 perDeploymentDailyCap) external onlyOwner {
        if (!_tokenConfigs[token].allowed) revert TokenNotAllowed(token);
        _setToken(token, true, perPaymentCap, perDeploymentDailyCap);
    }

    /// @notice Sets the treasury for future credits. Existing credits stay with the previous treasury. Owner only.
    /// @param newTreasury The new treasury (non-zero, not this contract, not a TIP-20 token address).
    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert ZeroAddress();
        if (_cannotWithdraw(newTreasury)) revert InvalidTreasury(newTreasury);
        address previous = treasury;
        treasury = newTreasury;
        emit TreasurySet(previous, newTreasury);
    }

    /// @notice Pauses payFees and topUpFees. Owner only. Withdrawals keep working.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses. Owner only.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ---------------------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------------------

    /// @notice The configuration of a token (all zero when never configured).
    /// @param token The token.
    /// @return The configuration.
    function tokenConfig(address token) external view returns (TokenConfig memory) {
        return _tokenConfigs[token];
    }

    /// @notice Whether payFees and topUpFees accept a token.
    /// @param token The token.
    /// @return True when allowlisted.
    function isTokenAllowed(address token) external view returns (bool) {
        return _tokenConfigs[token].allowed;
    }

    /// @notice Amount still payable today for a deployment and token before the daily cap is reached.
    /// @param deploymentId The deployment id.
    /// @param token The token.
    /// @return The remaining amount (0 when the token is not allowed).
    function remainingDailyAllowance(bytes32 deploymentId, address token) external view returns (uint256) {
        TokenConfig storage cfg = _tokenConfigs[token];
        if (!cfg.allowed) return 0;
        uint256 paid = dailyPaid[deploymentId][token][block.timestamp / 1 days];
        return paid >= cfg.perDeploymentDailyCap ? 0 : cfg.perDeploymentDailyCap - paid;
    }

    /// @notice The maintainer part of a payment for a given share: amount * shareBps / 10000, rounded down.
    /// @param amount The payment amount.
    /// @param shareBps The maintainer share in basis points.
    /// @return maintainerAmount The maintainer part.
    /// @return treasuryAmount The treasury part.
    function splitAmount(uint256 amount, uint16 shareBps)
        external
        pure
        returns (uint256 maintainerAmount, uint256 treasuryAmount)
    {
        maintainerAmount = amount * shareBps / BPS_DENOMINATOR;
        treasuryAmount = amount - maintainerAmount;
    }

    // ---------------------------------------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------------------------------------

    /// @dev The deployment is Active, the caller is its customer or enclave signer, and the app is in its stack.
    function _checkPayer(bytes32 deploymentId, bytes32 appId) private view {
        (IDeploymentRegistry.DeploymentStatus status, address customer, address enclaveSigner) =
            deploymentRegistry.deploymentParties(deploymentId);
        if (status != IDeploymentRegistry.DeploymentStatus.Active) revert DeploymentNotActive(deploymentId);
        if (msg.sender != customer && msg.sender != enclaveSigner) revert UnauthorizedPayer(msg.sender);
        if (!deploymentRegistry.appInDeployment(deploymentId, appId)) revert AppNotInDeployment(deploymentId, appId);
    }

    /// @dev Checks token, amount, caps and the leg's state, then records the leg's new total and the daily total.
    ///      For payFees (topUp false) `total` is the payment and the leg must be unpaid. For topUpFees the leg must be
    ///      open and `total` above its amount. Returns the amount to pull: total minus what the leg already had.
    function _recordPayment(
        bytes32 deploymentId,
        bytes32 appId,
        address token,
        uint256 total,
        bytes32 usageHash,
        bool topUp
    ) private returns (uint256 amount) {
        TokenConfig storage cfg = _tokenConfigs[token];
        if (!cfg.allowed) revert TokenNotAllowed(token);
        if (total == 0) revert ZeroAmount();
        if (total > cfg.perPaymentCap) revert PerPaymentCapExceeded(total, cfg.perPaymentCap);
        if (usageHash == bytes32(0)) revert ZeroUsageHash();
        mapping(bytes32 appId => uint256 amount) storage paidForUsage = usagePaid[deploymentId][usageHash];
        uint256 paid = paidForUsage[appId];
        if (topUp) {
            if (paid == 0) revert UsageNotPaid(deploymentId, usageHash, appId);
            if (total <= paid) revert NothingToTopUp(deploymentId, usageHash, appId, paid);
        } else if (paid != 0) {
            revert UsageAlreadyPaid(deploymentId, usageHash, appId);
        }
        amount = total - paid;

        mapping(uint256 day => uint256 amount) storage paidByDay = dailyPaid[deploymentId][token];
        uint256 day = block.timestamp / 1 days;
        uint256 newDaily = paidByDay[day] + amount;
        if (newDaily > cfg.perDeploymentDailyCap) revert DailyCapExceeded(newDaily, cfg.perDeploymentDailyCap);

        paidForUsage[appId] = total;
        paidByDay[day] = newDaily;
    }

    /// @dev Pulls `amount`, splits it between the app's maintainer and the treasury, and emits FeesPaid.
    function _collect(bytes32 deploymentId, bytes32 appId, address token, uint256 amount, bytes32 usageHash) private {
        (address maintainer, uint16 shareBps) = appRegistry.payoutInfo(appId);
        uint256 maintainerAmount = _cannotWithdraw(maintainer) ? 0 : amount * shareBps / BPS_DENOMINATOR;

        _pull(token, amount);

        _credit(token, maintainer, appId, CreditKind.Maintainer, maintainerAmount);
        _credit(token, treasury, appId, CreditKind.Treasury, amount - maintainerAmount);

        emit FeesPaid(deploymentId, appId, msg.sender, token, amount, maintainerAmount, usageHash);
    }

    /// @dev True for accounts that can never call withdraw or receive the token: this contract, and TIP-20 token
    ///      addresses (TIP20_ADDRESS_PREFIX), which TIP-20 rejects as recipients.
    function _cannotWithdraw(address account) private view returns (bool) {
        return account == address(this) || bytes12(bytes20(account)) == TIP20_ADDRESS_PREFIX;
    }

    /// @dev Pulls exactly `amount` from the caller, rejecting tokens whose transfer delivers a different amount.
    function _pull(address token, uint256 amount) private {
        IERC20 erc20 = IERC20(token);
        uint256 balanceBefore = erc20.balanceOf(address(this));
        erc20.safeTransferFrom(msg.sender, address(this), amount);
        uint256 balanceAfter = erc20.balanceOf(address(this));
        uint256 received = balanceAfter > balanceBefore ? balanceAfter - balanceBefore : 0;
        if (received != amount) revert TransferAmountMismatch(amount, received);
    }

    function _setToken(address token, bool allowed, uint256 perPaymentCap, uint256 perDeploymentDailyCap) private {
        if (token == address(0)) revert ZeroAddress();
        _tokenConfigs[token] = TokenConfig(allowed, perPaymentCap, perDeploymentDailyCap);
        emit TokenConfigured(token, allowed, perPaymentCap, perDeploymentDailyCap);
    }

    function _credit(address token, address recipient, bytes32 appId, CreditKind kind, uint256 amount) private {
        if (amount == 0) return;
        uint256 newBalance = credited[token][recipient] + amount;
        credited[token][recipient] = newBalance;
        totalCredited[token] += amount;
        emit Credited(recipient, token, appId, kind, amount, newBalance);
    }
}
