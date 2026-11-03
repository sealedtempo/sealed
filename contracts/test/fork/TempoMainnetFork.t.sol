// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test, console} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {OracleSignatureVerifier} from "../../src/OracleSignatureVerifier.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";

interface ITIP20Like {
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
    function currency() external view returns (string memory);
    function transferPolicyId() external view returns (uint64);
    function paused() external view returns (bool);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface ITIP403RegistryLike {
    function policyData(uint64 policyId) external view returns (uint8 policyType, address admin);
    function isAuthorized(uint64 policyId, address user) external view returns (bool);
}

/// @notice Deploys the whole system on a fork of Tempo mainnet and moves real pathUSD through FeeSplitter:
///         approve + payFees (transferFrom into the contract) + withdraw (transfer out of the contract).
/// @dev RPC: TEMPO_RPC_URL, falling back to https://rpc.tempo.xyz. Every test is skipped when the RPC is not
///      reachable or SKIP_FORK_TESTS=true. Needs Foundry 1.8.6+ with foundry.toml `hardfork` at mainnet's
///      hardfork (tempo:t13, active since 2026-11-03 15:00 UTC): older rules read the token policy ids as 0
///      and every transfer reverts PolicyForbids. Nothing is patched; see README "Fork tests".
contract TempoMainnetForkTest is Test {
    ITIP20Like internal constant PATH_USD = ITIP20Like(0x20C0000000000000000000000000000000000000);
    /// @dev USDC.e, the mainnet FEE_TOKEN (D-035).
    ITIP20Like internal constant USDC_E = ITIP20Like(0x20C000000000000000000000b9537d11c60E8b50);
    ITIP403RegistryLike internal constant TIP403 = ITIP403RegistryLike(0x403c000000000000000000000000000000000000);
    /// @dev Stablecoin DEX precompile: the largest pathUSD and USDC.e holder, impersonated to fund test accounts.
    address internal constant FUNDER = 0xDEc0000000000000000000000000000000000000;
    /// @dev An address on pathUSD's blacklist (policy 2) at the time of writing.
    address internal constant BLACKLISTED = 0xfEC8A60023265364D066a1212fDE3930F6Ae8da7;
    uint64 internal constant MAINNET_POLICY_ID = 2;
    /// @dev TIP-403 built-in policy 1: always allow. USDC.e is bound to it.
    uint64 internal constant ALWAYS_ALLOW_POLICY_ID = 1;
    /// @dev TIP-20 `PolicyForbids()`.
    bytes4 internal constant POLICY_FORBIDS = 0x54cfe659;
    uint256 internal constant TEMPO_CHAIN_ID = 4217;

    address internal owner = makeAddr("fork-owner");
    address internal ops = makeAddr("fork-ops");
    address internal treasury = makeAddr("fork-treasury");
    address internal maintainer = makeAddr("fork-maintainer");
    address internal customer;
    uint256 internal customerKey;
    address internal enclaveSigner;
    address internal oracle;
    uint256 internal oracleKey;

    PlatformRegistry internal platform;
    AppRegistry internal apps;
    OracleSignatureVerifier internal verifier;
    DeploymentRegistry internal registry;
    FeeSplitter internal splitter;

    bytes32 internal imageId;
    bytes32 internal appId;
    bytes32 internal releaseId;
    bytes32 internal stackHash = keccak256("fork-stack");
    bytes32 internal deploymentId;

    function setUp() public {
        if (vm.envOr("SKIP_FORK_TESTS", false)) {
            vm.skip(true);
            return;
        }
        string memory rpc = vm.envOr("TEMPO_RPC_URL", string(""));
        if (bytes(rpc).length == 0) rpc = "https://rpc.tempo.xyz";
        try vm.createSelectFork(rpc) {}
        catch {
            console.log("Tempo RPC not reachable; skipping fork tests");
            vm.skip(true);
            return;
        }
        if (block.chainid != TEMPO_CHAIN_ID) {
            console.log("RPC is not Tempo mainnet; skipping fork tests");
            vm.skip(true);
            return;
        }
        // Fails loudly instead of patching: a policy id of 0 means Foundry runs the fork with pre-T9 rules.
        require(
            PATH_USD.transferPolicyId() == MAINNET_POLICY_ID && USDC_E.transferPolicyId() == ALWAYS_ALLOW_POLICY_ID,
            "fork reads stale token policy ids: use Foundry 1.8.6+ with hardfork = tempo:t12 or newer"
        );

        (customer, customerKey) = makeAddrAndKey("fork-customer");
        (oracle, oracleKey) = makeAddrAndKey("fork-oracle");
        enclaveSigner = makeAddr("fork-enclave");

        platform = new PlatformRegistry(owner);
        apps = new AppRegistry(owner);
        verifier = new OracleSignatureVerifier(owner);
        registry = new DeploymentRegistry(owner, platform, apps);
        splitter = new FeeSplitter(owner, registry, apps, address(PATH_USD), treasury, 5_000_000, 20_000_000);

        vm.startPrank(owner);
        apps.grantRegistrar(ops);
        verifier.addSigner(oracle);
        registry.setVerifier(1, address(verifier));
        bytes memory m = new bytes(48);
        imageId = keccak256("fork-image");
        platform.addImage(imageId, "sealed-os", "1.0.0", m, m, m, m, false, "");
        appId = keccak256("llm-gateway");
        apps.registerApp(appId, "llm-gateway", "LLM Gateway", "MIT", maintainer, 2000, "");
        vm.stopPrank();
        vm.prank(ops);
        releaseId = apps.publishRelease(appId, "1.0.0", keccak256("bundle"), bytes32(0), bytes32(0), "", "");

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = releaseId;
        vm.prank(customer);
        registry.approveStack(stackHash, ids, imageId, 0);
        deploymentId = keccak256(abi.encode(customer, stackHash, bytes32(uint256(1))));
        IDeploymentRegistry.Record memory r = IDeploymentRegistry.Record({
            deploymentId: deploymentId,
            customer: customer,
            stackHash: stackHash,
            imageId: imageId,
            quoteHash: keccak256("quote"),
            eventLogHash: keccak256("eventlog"),
            configHash: keccak256("config"),
            enclaveSigner: enclaveSigner,
            attestedAt: uint64(block.timestamp)
        });
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(oracleKey, registry.recordDigest(r));
        vm.prank(ops);
        registry.registerDeployment(r, 1, abi.encode(abi.encodePacked(rr, s, v)));
    }

    /// @dev Funds `to` with real pathUSD by impersonating a large holder (no storage writes).
    function _fund(address to, uint256 amount) internal {
        vm.prank(FUNDER);
        assertTrue(PATH_USD.transfer(to, amount));
    }

    /// @dev Funds `to` with real USDC.e the same way.
    function _fundUsdcE(address to, uint256 amount) internal {
        vm.prank(FUNDER);
        assertTrue(USDC_E.transfer(to, amount));
    }

    function test_fork_usdcEFacts() public view {
        assertEq(USDC_E.decimals(), 6);
        assertEq(USDC_E.symbol(), "USDC.e");
        assertEq(USDC_E.currency(), "USD");
        assertFalse(USDC_E.paused());
        assertEq(USDC_E.transferPolicyId(), ALWAYS_ALLOW_POLICY_ID, "USDC.e is bound to policy 1 (always allow)");
        assertTrue(TIP403.isAuthorized(ALWAYS_ALLOW_POLICY_ID, BLACKLISTED), "policy 1 authorizes everyone");
        assertGt(USDC_E.balanceOf(FUNDER), 1_000_000_000, "funder holds USDC.e");
    }

    /// @dev The mainnet FeeSplitter takes USDC.e (FEE_TOKEN). Same flow as the pathUSD test, unpatched.
    function test_fork_payFeesAndWithdrawWithRealUsdcE() public {
        vm.prank(owner);
        splitter.setToken(address(USDC_E), true, 5_000_000, 20_000_000);
        _fundUsdcE(customer, 10_000_000);

        vm.prank(customer);
        assertTrue(USDC_E.approve(address(splitter), 3_000_000));
        vm.prank(customer);
        splitter.payFees(deploymentId, appId, address(USDC_E), 2_500_000, keccak256("usage-usdce-1"));
        assertEq(USDC_E.balanceOf(customer), 7_500_000);
        assertEq(USDC_E.balanceOf(address(splitter)), 2_500_000, "transferFrom into the contract");
        assertEq(splitter.credited(address(USDC_E), maintainer), 500_000);
        assertEq(splitter.credited(address(USDC_E), treasury), 2_000_000);

        vm.prank(maintainer);
        splitter.withdraw(address(USDC_E));
        vm.prank(treasury);
        splitter.withdraw(address(USDC_E));
        assertEq(USDC_E.balanceOf(maintainer), 500_000, "transfer out of the contract");
        assertEq(USDC_E.balanceOf(treasury), 2_000_000);
        assertEq(USDC_E.balanceOf(address(splitter)), 0);
        assertEq(splitter.totalCredited(address(USDC_E)), 0);
    }

    function test_fork_pathUsdFacts() public view {
        assertEq(block.chainid, TEMPO_CHAIN_ID);
        assertEq(PATH_USD.decimals(), 6);
        assertEq(PATH_USD.symbol(), "pathUSD");
        assertEq(PATH_USD.currency(), "USD");
        assertFalse(PATH_USD.paused());
        assertEq(PATH_USD.transferPolicyId(), MAINNET_POLICY_ID);
        (uint8 policyType,) = TIP403.policyData(MAINNET_POLICY_ID);
        assertEq(policyType, 1, "policy 2 is a BLACKLIST");
        assertGt(PATH_USD.balanceOf(FUNDER), 1_000_000_000, "funder holds pathUSD");
    }

    function test_fork_policyAllowsOurContracts() public view {
        uint64 policy = PATH_USD.transferPolicyId();
        assertTrue(TIP403.isAuthorized(policy, address(splitter)), "FeeSplitter can send and receive");
        assertTrue(TIP403.isAuthorized(policy, customer));
        assertTrue(TIP403.isAuthorized(policy, maintainer));
        assertTrue(TIP403.isAuthorized(policy, treasury));
        assertFalse(TIP403.isAuthorized(policy, BLACKLISTED), "blacklist entry is live");
    }

    function test_fork_payFeesAndWithdrawWithRealPathUsd() public {
        _fund(customer, 10_000_000);
        assertEq(PATH_USD.balanceOf(customer), 10_000_000);

        vm.prank(customer);
        assertTrue(PATH_USD.approve(address(splitter), 3_000_000));
        vm.prank(customer);
        splitter.payFees(deploymentId, appId, address(PATH_USD), 2_500_000, keccak256("usage-1"));

        assertEq(PATH_USD.balanceOf(customer), 7_500_000);
        assertEq(PATH_USD.balanceOf(address(splitter)), 2_500_000, "transferFrom into the contract");
        assertEq(splitter.credited(address(PATH_USD), maintainer), 500_000);
        assertEq(splitter.credited(address(PATH_USD), treasury), 2_000_000);
        assertEq(splitter.totalCredited(address(PATH_USD)), PATH_USD.balanceOf(address(splitter)));

        vm.prank(maintainer);
        splitter.withdraw(address(PATH_USD));
        vm.prank(treasury);
        splitter.withdraw(address(PATH_USD));
        assertEq(PATH_USD.balanceOf(maintainer), 500_000, "transfer out of the contract");
        assertEq(PATH_USD.balanceOf(treasury), 2_000_000);
        assertEq(PATH_USD.balanceOf(address(splitter)), 0);
        assertEq(splitter.totalCredited(address(PATH_USD)), 0);
    }

    function test_fork_enclaveSignerPaysAndHeartbeat() public {
        _fund(enclaveSigner, 1_000_000);
        vm.prank(enclaveSigner);
        assertTrue(PATH_USD.approve(address(splitter), type(uint256).max));
        vm.prank(enclaveSigner);
        splitter.payFees(deploymentId, appId, address(PATH_USD), 1_000_000, keccak256("usage-2"));
        assertEq(PATH_USD.balanceOf(address(splitter)), 1_000_000);

        vm.warp(block.timestamp + 60);
        uint64 t = uint64(block.timestamp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, registry.heartbeatDigest(deploymentId, keccak256("q2"), t));
        registry.heartbeat(deploymentId, keccak256("q2"), t, 1, abi.encode(abi.encodePacked(r, s, v)));
        assertEq(registry.getDeployment(deploymentId).lastAttestedAt, t);

        vm.prank(customer);
        registry.closeDeployment(deploymentId);
        vm.prank(enclaveSigner);
        vm.expectRevert(abi.encodeWithSelector(FeeSplitter.DeploymentNotActive.selector, deploymentId));
        splitter.payFees(deploymentId, appId, address(PATH_USD), 1, keccak256("usage-3"));
    }

    function test_fork_blacklistedMaintainerCannotWithdraw() public {
        vm.prank(owner);
        apps.setMaintainer(appId, BLACKLISTED);
        _fund(customer, 1_000_000);
        vm.prank(customer);
        assertTrue(PATH_USD.approve(address(splitter), 1_000_000));
        vm.prank(customer);
        splitter.payFees(deploymentId, appId, address(PATH_USD), 1_000_000, keccak256("usage-4"));
        assertEq(splitter.credited(address(PATH_USD), BLACKLISTED), 200_000);

        // TIP-403 rejects the payout (PolicyForbids); the credit stays and the invariant holds.
        vm.prank(BLACKLISTED);
        vm.expectRevert(POLICY_FORBIDS);
        splitter.withdraw(address(PATH_USD));
        assertEq(splitter.credited(address(PATH_USD), BLACKLISTED), 200_000);
        assertEq(splitter.totalCredited(address(PATH_USD)), PATH_USD.balanceOf(address(splitter)));
    }

    function test_fork_blacklistedPayerRejected() public {
        address payer = BLACKLISTED;
        bytes32 stack2 = keccak256("fork-stack-2");
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = releaseId;
        vm.prank(payer);
        registry.approveStack(stack2, ids, imageId, 0);
        bytes32 id2 = keccak256(abi.encode(payer, stack2, bytes32(uint256(2))));
        IDeploymentRegistry.Record memory r = IDeploymentRegistry.Record({
            deploymentId: id2,
            customer: payer,
            stackHash: stack2,
            imageId: imageId,
            quoteHash: bytes32(0),
            eventLogHash: bytes32(0),
            configHash: bytes32(0),
            enclaveSigner: enclaveSigner,
            attestedAt: uint64(block.timestamp)
        });
        (uint8 v, bytes32 rr, bytes32 s) = vm.sign(oracleKey, registry.recordDigest(r));
        registry.registerDeployment(r, 1, abi.encode(abi.encodePacked(rr, s, v)));
        vm.prank(payer);
        PATH_USD.approve(address(splitter), type(uint256).max);
        vm.prank(payer);
        vm.expectRevert(POLICY_FORBIDS); // from the token's transferFrom; the whole payment reverts
        splitter.payFees(id2, appId, address(PATH_USD), 1, keccak256("usage-5"));
    }
}
