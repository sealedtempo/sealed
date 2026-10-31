// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {OracleSignatureVerifier} from "../../src/OracleSignatureVerifier.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IAppRegistry} from "../../src/interfaces/IAppRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";

/// @notice The contracts deployed on Tempo mainnet (deployments/tempo-mainnet.json) against this source, on a local
///         fork: the runtime code equals the code this source builds with the recorded constructor arguments, the
///         configuration equals the deployment record, the pure functions agree with a fresh build, and one full
///         lifecycle (catalog, approval, registration, heartbeats, signer removal, payments, top-ups, withdrawals,
///         deprecation, revocation, close) gives the same outcome step by step on the deployed contracts and on a
///         fresh build from source.
/// @dev Read-only towards the network: every write happens on the local fork (forge's in-memory state), with the
///      owner and ops addresses impersonated there. Same RPC and skip rules as TempoMainnetFork.t.sol.
contract DeployedContractsForkTest is Test {
    using stdJson for string;

    uint256 internal constant TEMPO_CHAIN_ID = 4217;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    /// @dev Stablecoin DEX precompile, the largest USDC.e holder, impersonated to fund test accounts.
    address internal constant FUNDER = 0xDEc0000000000000000000000000000000000000;

    struct Sys {
        PlatformRegistry platform;
        AppRegistry apps;
        OracleSignatureVerifier verifier;
        DeploymentRegistry registry;
        FeeSplitter splitter;
    }

    string internal json;
    Sys internal live;
    address internal owner;
    address internal ops;
    address internal oracleSigner;
    address internal treasury;
    address internal feeToken;
    uint256 internal perPaymentCap;
    uint256 internal dailyCap;
    uint64 internal maxAge;

    address internal stranger = makeAddr("fork-diff-stranger");
    address internal maintainer = makeAddr("fork-diff-maintainer");
    address internal customer = makeAddr("fork-diff-customer");
    address internal enclave = makeAddr("fork-diff-enclave");
    address internal testOracle;
    uint256 internal testOracleKey;
    uint256 internal rogueKey;

    string[] internal _labels;
    bytes[] internal _outcomes;

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
        console.log("fork block", block.number, "timestamp", block.timestamp);

        json = vm.readFile("deployments/tempo-mainnet.json");
        live = Sys(
            PlatformRegistry(json.readAddress(".contracts.PlatformRegistry.address")),
            AppRegistry(json.readAddress(".contracts.AppRegistry.address")),
            OracleSignatureVerifier(json.readAddress(".contracts.OracleSignatureVerifier.address")),
            DeploymentRegistry(json.readAddress(".contracts.DeploymentRegistry.address")),
            FeeSplitter(json.readAddress(".contracts.FeeSplitter.address"))
        );
        owner = json.readAddress(".config.owner");
        ops = json.readAddress(".config.ops");
        oracleSigner = json.readAddress(".config.oracleSigner");
        treasury = json.readAddress(".config.treasury");
        feeToken = json.readAddress(".config.feeToken");
        perPaymentCap = vm.parseUint(json.readString(".config.perPaymentCap"));
        dailyCap = vm.parseUint(json.readString(".config.perDeploymentDailyCap"));
        maxAge = uint64(json.readUint(".config.maxAttestationAge"));
        (testOracle, testOracleKey) = makeAddrAndKey("fork-diff-oracle");
        (, rogueKey) = makeAddrAndKey("fork-diff-rogue");
    }

    // ------------------------------------------------------------------------------------------------------
    // Code and configuration
    // ------------------------------------------------------------------------------------------------------

    /// @dev Runs this source's creation code with the recorded constructor arguments at the deployed address (so
    ///      address-dependent immutables match) and compares the result with the code on mainnet.
    function test_fork_deployedCodeEqualsSource() public {
        _compareCode("PlatformRegistry", address(live.platform), type(PlatformRegistry).creationCode);
        _compareCode("AppRegistry", address(live.apps), type(AppRegistry).creationCode);
        _compareCode("OracleSignatureVerifier", address(live.verifier), type(OracleSignatureVerifier).creationCode);
        _compareCode("DeploymentRegistry", address(live.registry), type(DeploymentRegistry).creationCode);
        _compareCode("FeeSplitter", address(live.splitter), type(FeeSplitter).creationCode);
    }

    function _compareCode(string memory name, address target, bytes memory creationCode) internal {
        bytes memory deployed = target.code;
        assertGt(deployed.length, 0, string.concat(name, ": no code at the recorded address"));
        bytes memory args = json.readBytes(string.concat(".contracts.", name, ".constructorArgs"));
        vm.etch(target, abi.encodePacked(creationCode, args));
        (bool ok, bytes memory built) = target.call("");
        assertTrue(ok, string.concat(name, ": constructor reverted"));
        vm.etch(target, deployed);
        if (keccak256(built) != keccak256(deployed)) {
            console.log(name, "differs; lengths", built.length, deployed.length);
            assertEq(
                keccak256(_stripMetadata(built)),
                keccak256(_stripMetadata(deployed)),
                string.concat(name, ": code differs beyond the metadata hash")
            );
            revert(string.concat(name, ": only the metadata hash differs (source text changed since deploy)"));
        }
        console.log(name, "runtime code identical, bytes:", deployed.length);
    }

    function _stripMetadata(bytes memory code) internal pure returns (bytes memory out) {
        uint256 n = code.length;
        uint256 metaLen = (uint256(uint8(code[n - 2])) << 8) | uint256(uint8(code[n - 1]));
        out = new bytes(n - metaLen - 2);
        for (uint256 i; i < out.length; ++i) {
            out[i] = code[i];
        }
    }

    function test_fork_deployedConfigMatchesRecord() public view {
        address[5] memory all = [
            address(live.platform),
            address(live.apps),
            address(live.verifier),
            address(live.registry),
            address(live.splitter)
        ];
        for (uint256 i; i < all.length; ++i) {
            assertEq(OwnerView(all[i]).owner(), owner, "owner");
            assertEq(OwnerView(all[i]).pendingOwner(), address(0), "no pending owner");
            assertEq(OwnerView(all[i]).VERSION(), "1.0.0", "VERSION");
        }
        assertEq(address(live.registry.platformRegistry()), address(live.platform), "registry.platformRegistry");
        assertEq(address(live.registry.appRegistry()), address(live.apps), "registry.appRegistry");
        assertEq(address(live.registry.verifiers(1)), address(live.verifier), "method 1 verifier");
        assertEq(address(live.registry.verifiers(2)), address(0), "method 2 unset");
        assertEq(live.registry.maxAttestationAge(), maxAge, "maxAttestationAge");
        assertFalse(live.registry.paused(), "registry paused");
        assertEq(
            live.registry.domainSeparator(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256("Sealed DeploymentRegistry"),
                    keccak256("1"),
                    TEMPO_CHAIN_ID,
                    address(live.registry)
                )
            ),
            "EIP-712 domain"
        );
        assertEq(
            live.registry.RECORD_TYPEHASH(),
            keccak256(
                "Record(bytes32 deploymentId,address customer,bytes32 stackHash,bytes32 imageId,bytes32 quoteHash,bytes32 eventLogHash,bytes32 configHash,address enclaveSigner,uint64 attestedAt)"
            ),
            "RECORD_TYPEHASH"
        );
        assertEq(
            live.registry.HEARTBEAT_TYPEHASH(),
            keccak256("Heartbeat(bytes32 deploymentId,bytes32 quoteHash,uint64 attestedAt)"),
            "HEARTBEAT_TYPEHASH"
        );
        assertTrue(live.verifier.isSigner(oracleSigner), "oracle signer allowed");
        assertEq(live.verifier.signerCount(), 1, "one oracle signer");
        assertTrue(live.apps.hasRole(live.apps.REGISTRAR_ROLE(), ops), "ops is registrar");
        assertFalse(live.apps.hasRole(bytes32(0), owner), "no DEFAULT_ADMIN_ROLE for owner");
        assertFalse(live.apps.hasRole(bytes32(0), ops), "no DEFAULT_ADMIN_ROLE for ops");
        assertEq(address(live.splitter.deploymentRegistry()), address(live.registry), "splitter.deploymentRegistry");
        assertEq(address(live.splitter.appRegistry()), address(live.apps), "splitter.appRegistry");
        assertEq(live.splitter.FEE_TOKEN(), feeToken, "FEE_TOKEN");
        assertEq(live.splitter.treasury(), treasury, "treasury");
        assertFalse(live.splitter.paused(), "splitter paused");
        FeeSplitter.TokenConfig memory cfg = live.splitter.tokenConfig(feeToken);
        assertTrue(cfg.allowed, "fee token allowed");
        assertEq(cfg.perPaymentCap, perPaymentCap, "perPaymentCap");
        assertEq(cfg.perDeploymentDailyCap, dailyCap, "perDeploymentDailyCap");
    }

    /// @dev Solvency and catalog sanity of the live state (read-only).
    function test_fork_liveStateIsConsistent() public view {
        uint256 credited = live.splitter.totalCredited(feeToken);
        uint256 balance = IERC20(feeToken).balanceOf(address(live.splitter));
        console.log("FeeSplitter fee token: totalCredited", credited, "balance", balance);
        assertLe(credited, balance, "FeeSplitter holds at least what it owes");
        uint256 n = live.apps.appCount();
        console.log("apps", n, "images", live.platform.imageCount());
        console.log("deployments", live.registry.deploymentCount());
        for (uint256 i; i < n; ++i) {
            bytes32 appId = live.apps.appAt(i);
            IAppRegistry.App memory a = live.apps.getApp(appId);
            assertEq(appId, keccak256(bytes(a.slug)), "appId == keccak256(slug)");
            assertTrue(a.maintainer != address(0), "maintainer set");
            assertLe(a.maintainerShareBps, 5000, "share cap");
            uint256 r = live.apps.releaseCount(appId);
            for (uint256 j; j < r; ++j) {
                assertEq(live.apps.appOfRelease(live.apps.releaseAt(appId, j)), appId, "release belongs to its app");
            }
            console.log(a.slug, a.maintainerShareBps, r);
        }
    }

    /// @dev The deployed pure and view helpers give the same answers as a fresh build of this source.
    /// forge-config: default.fuzz.runs = 32
    /// forge-config: ci.fuzz.runs = 32
    /// forge-config: deep.fuzz.runs = 32
    function testFuzz_fork_pureFunctionsMatchSource(
        bytes32 digest,
        uint256 keySeed,
        uint8 v,
        uint256 amount,
        uint16 bps
    ) public {
        Sys memory fresh = _deployFresh();
        bytes32 r = _checkRecover(fresh, digest, bound(keySeed, 1, N - 1), v);
        // amount > 0 so a share above 100% always underflows the treasury part.
        _checkSplit(fresh, bound(amount, 1, type(uint128).max), uint16(bound(bps, 0, 12_000)));
        assertEq(live.apps.computeReleaseId(digest, "1.0.0", r), fresh.apps.computeReleaseId(digest, "1.0.0", r));
        // Truncating to bytes16 is intended: 32 + 16 = 48 bytes, one TDX register.
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory m = abi.encodePacked(digest, bytes16(r));
        assertEq(live.platform.computeMeasurementsHash(m, m, m, m), fresh.platform.computeMeasurementsHash(m, m, m, m));
    }

    function _checkRecover(Sys memory fresh, bytes32 digest, uint256 key, uint8 v) internal view returns (bytes32) {
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(key, digest);
        bytes[4] memory variants = [
            abi.encode(abi.encodePacked(r, s, sv)),
            abi.encode(abi.encodePacked(r, bytes32(N - uint256(s)), sv == 27 ? uint8(28) : uint8(27))),
            abi.encode(abi.encodePacked(r, s, v)),
            abi.encodePacked(r, s, sv)
        ];
        for (uint256 i; i < variants.length; ++i) {
            (bool okLive, address recLive) = live.verifier.recoverSigner(digest, variants[i]);
            (bool okFresh, address recFresh) = fresh.verifier.recoverSigner(digest, variants[i]);
            assertEq(okLive, okFresh, "recoverSigner ok");
            assertEq(recLive, recFresh, "recoverSigner address");
        }
        assertFalse(live.verifier.verify(digest, variants[1]), "high-s rejected by the deployed verifier");
        return r;
    }

    /// @dev splitAmount is a pure helper for offchain callers and does not cap shareBps: once
    ///      amount * shareBps / 10000 exceeds the amount it reverts with Panic(0x11) on both builds (the treasury
    ///      part underflows). Payments never reach it, since AppRegistry caps shares at 5000.
    function _checkSplit(Sys memory fresh, uint256 amount, uint16 bps) internal view {
        bool overflows = amount * bps / 10_000 > amount;
        try live.splitter.splitAmount(amount, bps) returns (uint256 mLive, uint256 tLive) {
            (uint256 mFresh, uint256 tFresh) = fresh.splitter.splitAmount(amount, bps);
            assertEq(mLive, mFresh, "splitAmount maintainer");
            assertEq(tLive, tFresh, "splitAmount treasury");
            assertEq(mLive, amount * bps / 10_000, "maintainer part rounds down");
            assertEq(mLive + tLive, amount, "split sums to the amount");
            assertFalse(overflows, "splitAmount returned a maintainer part above the amount");
        } catch (bytes memory liveErr) {
            assertTrue(overflows, "splitAmount reverted although the maintainer part fits");
            try fresh.splitter.splitAmount(amount, bps) {
                revert("fresh build accepted what the deployed one rejected");
            } catch (bytes memory freshErr) {
                assertEq(liveErr, freshErr, "same revert");
                assertEq(liveErr, abi.encodeWithSignature("Panic(uint256)", 0x11), "arithmetic panic");
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------
    // Differential lifecycle
    // ------------------------------------------------------------------------------------------------------

    /// @dev The same scenario on the deployed contracts and on a fresh build gives the same outcome (success and
    ///      return or revert data) at every step. Both runs start from the same fork state and time.
    function test_fork_deployedLifecycleMatchesSource() public {
        Sys memory fresh = _deployFresh();
        uint256 t0 = block.timestamp;
        uint256 snap = vm.snapshotState();

        _scenario(live);
        uint256 n = _outcomes.length;
        string[] memory labels = new string[](n);
        bytes[] memory liveOut = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            labels[i] = _labels[i];
            liveOut[i] = _outcomes[i];
        }

        assertTrue(vm.revertToState(snap), "revert to snapshot");
        vm.warp(t0);
        delete _labels;
        delete _outcomes;
        _scenario(fresh);
        assertEq(_outcomes.length, n, "same number of steps");
        for (uint256 i; i < n; ++i) {
            assertEq(_labels[i], labels[i], "same step");
            assertEq(_outcomes[i], liveOut[i], labels[i]);
        }
        console.log("steps compared", n);
    }

    function _deployFresh() internal returns (Sys memory s) {
        s.platform = new PlatformRegistry(owner);
        s.apps = new AppRegistry(owner);
        s.verifier = new OracleSignatureVerifier(owner);
        s.registry = new DeploymentRegistry(owner, s.platform, s.apps);
        s.splitter = new FeeSplitter(owner, s.registry, s.apps, feeToken, treasury, perPaymentCap, dailyCap);
        vm.startPrank(owner);
        s.apps.grantRegistrar(ops);
        s.verifier.addSigner(oracleSigner);
        s.registry.setVerifier(1, address(s.verifier));
        vm.stopPrank();
    }

    struct Ctx {
        bytes32 imageId;
        bytes32 appId;
        bytes32 releaseId;
        bytes32 stackHash;
        bytes32 deploymentId;
        bytes32 usage;
        IDeploymentRegistry.Record r;
    }

    function _scenario(Sys memory s) internal {
        Ctx memory c;
        c.imageId = keccak256("fork-diff-image");
        c.appId = keccak256("fork-diff-app");
        c.stackHash = keccak256("fork-diff-stack");
        c.usage = keccak256("fork-diff-usage");
        _phaseStrangers(s, c);
        _phaseCatalog(s, c);
        _phaseRegistration(s, c);
        _phaseHeartbeats(s, c);
        _phasePayments(s, c);
        _phaseRevocations(s, c);
        _phaseClose(s, c);
    }

    function _measurements(bytes32 seed) internal pure returns (bytes memory) {
        // Truncating to bytes16 is intended: 32 + 16 = 48 bytes, one TDX register.
        // forge-lint: disable-next-line(unsafe-typecast)
        return abi.encodePacked(seed, bytes16(seed));
    }

    function _releaseList(Ctx memory c) internal pure returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = c.releaseId;
    }

    /// @dev Callers without a role.
    function _phaseStrangers(Sys memory s, Ctx memory c) internal {
        bytes memory m = _measurements(c.imageId);
        _step(
            "stranger addImage",
            stranger,
            address(s.platform),
            abi.encodeCall(PlatformRegistry.addImage, (c.imageId, "x", "1", m, m, m, m, false, ""))
        );
        _step(
            "stranger registerApp",
            stranger,
            address(s.apps),
            abi.encodeCall(
                AppRegistry.registerApp, (c.appId, "fork-diff-app", "Fork diff", "MIT", maintainer, 2000, "")
            )
        );
        _step(
            "stranger addSigner",
            stranger,
            address(s.verifier),
            abi.encodeCall(OracleSignatureVerifier.addSigner, (stranger))
        );
        _step(
            "stranger setVerifier",
            stranger,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.setVerifier, (2, address(s.verifier)))
        );
        _step(
            "stranger setTreasury", stranger, address(s.splitter), abi.encodeCall(FeeSplitter.setTreasury, (stranger))
        );
        _step("stranger pause", stranger, address(s.splitter), abi.encodeCall(FeeSplitter.pause, ()));
        _step("renounceOwnership", owner, address(s.registry), abi.encodeWithSignature("renounceOwnership()"));
    }

    function _phaseCatalog(Sys memory s, Ctx memory c) internal {
        bytes memory m = _measurements(c.imageId);
        _step(
            "addImage",
            owner,
            address(s.platform),
            abi.encodeCall(PlatformRegistry.addImage, (c.imageId, "sealed-os", "fork-diff", m, m, m, m, false, ""))
        );
        _step(
            "addImage again",
            owner,
            address(s.platform),
            abi.encodeCall(
                PlatformRegistry.addImage, (keccak256("fork-diff-image-2"), "sealed-os", "2", m, m, m, m, false, "")
            )
        );
        _step(
            "registerApp",
            owner,
            address(s.apps),
            abi.encodeCall(
                AppRegistry.registerApp, (c.appId, "fork-diff-app", "Fork diff", "MIT", maintainer, 2000, "ipfs://x")
            )
        );
        _step(
            "stranger publishRelease",
            stranger,
            address(s.apps),
            abi.encodeCall(
                AppRegistry.publishRelease, (c.appId, "1.0.0", keccak256("b"), bytes32(0), bytes32(0), "", "")
            )
        );
        bytes memory ret = _step(
            "publishRelease",
            ops,
            address(s.apps),
            abi.encodeCall(
                AppRegistry.publishRelease, (c.appId, "1.0.0", keccak256("b"), bytes32(0), bytes32(0), "", "")
            )
        );
        c.releaseId = abi.decode(_returned(ret), (bytes32));
        _step(
            "publishRelease same bundle",
            ops,
            address(s.apps),
            abi.encodeCall(
                AppRegistry.publishRelease, (c.appId, "1.0.1", keccak256("b"), bytes32(0), bytes32(0), "", "")
            )
        );
        _step("addSigner", owner, address(s.verifier), abi.encodeCall(OracleSignatureVerifier.addSigner, (testOracle)));
    }

    /// @dev Approval and registration, with rejected evidence first.
    function _phaseRegistration(Sys memory s, Ctx memory c) internal {
        bytes32[] memory ids = _releaseList(c);
        _step(
            "approveStack",
            customer,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.approveStack, (c.stackHash, ids, c.imageId, 0))
        );
        c.deploymentId = keccak256(abi.encode(customer, c.stackHash, bytes32(uint256(1))));
        c.r = IDeploymentRegistry.Record({
            deploymentId: c.deploymentId,
            customer: customer,
            stackHash: c.stackHash,
            imageId: c.imageId,
            quoteHash: keccak256("fork-diff-quote"),
            eventLogHash: keccak256("fork-diff-eventlog"),
            configHash: keccak256("fork-diff-config"),
            enclaveSigner: enclave,
            attestedAt: uint64(block.timestamp)
        });
        bytes32 digest = s.registry.recordDigest(c.r);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(testOracleKey, digest);
        _step(
            "register high-s",
            ops,
            address(s.registry),
            abi.encodeCall(
                DeploymentRegistry.registerDeployment,
                (c.r, 1, abi.encode(abi.encodePacked(rr, bytes32(N - uint256(ss)), v == 27 ? uint8(28) : uint8(27))))
            )
        );
        _step(
            "register v of 0 or 1",
            ops,
            address(s.registry),
            abi.encodeCall(
                DeploymentRegistry.registerDeployment, (c.r, 1, abi.encode(abi.encodePacked(rr, ss, v - 27)))
            )
        );
        _step(
            "register by a non-signer",
            ops,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.registerDeployment, (c.r, 1, _sig(rogueKey, digest)))
        );
        _step(
            "register method 2",
            ops,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.registerDeployment, (c.r, 2, _sig(testOracleKey, digest)))
        );
        _step(
            "register",
            stranger,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.registerDeployment, (c.r, 1, abi.encode(abi.encodePacked(rr, ss, v))))
        );
        _step(
            "register again",
            ops,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.registerDeployment, (c.r, 1, abi.encode(abi.encodePacked(rr, ss, v))))
        );
    }

    /// @dev Heartbeats and signer removal.
    function _phaseHeartbeats(Sys memory s, Ctx memory c) internal {
        vm.warp(block.timestamp + 60);
        _heartbeat("heartbeat", s, c, keccak256("q2"), testOracleKey);
        _heartbeat("heartbeat at the same time", s, c, keccak256("q2b"), testOracleKey);
        vm.warp(block.timestamp + 1);
        _heartbeat("heartbeat reused quote", s, c, keccak256("q2"), testOracleKey);
        _step(
            "removeSigner",
            owner,
            address(s.verifier),
            abi.encodeCall(OracleSignatureVerifier.removeSigner, (testOracle))
        );
        vm.warp(block.timestamp + 60);
        _heartbeat("heartbeat by a removed signer", s, c, keccak256("q3"), testOracleKey);
        _step(
            "addSigner again",
            owner,
            address(s.verifier),
            abi.encodeCall(OracleSignatureVerifier.addSigner, (testOracle))
        );
        _heartbeat("heartbeat after re-adding", s, c, keccak256("q3"), testOracleKey);
    }

    /// @dev Payments in the real fee token.
    function _phasePayments(Sys memory s, Ctx memory c) internal {
        vm.prank(FUNDER);
        assertTrue(IERC20(feeToken).transfer(customer, 10_000_000));
        vm.prank(customer);
        assertTrue(IERC20(feeToken).approve(address(s.splitter), 10_000_000));
        uint256 treasuryBefore = s.splitter.credited(feeToken, treasury);
        _pay("payFees", s, c, customer, 1_000_001, false);
        _pay("payFees again", s, c, customer, 1, false);
        _pay("payFees by a stranger", s, c, stranger, 1, false);
        _pay("topUpFees", s, c, enclave, 1_500_003, true);
        _pay("topUpFees same total", s, c, customer, 1_500_003, true);
        _pay("payFees over the per-payment cap", s, c, customer, perPaymentCap + 1, false);
        _record(
            "credits",
            abi.encode(
                s.splitter.credited(feeToken, maintainer),
                s.splitter.credited(feeToken, treasury) - treasuryBefore,
                s.splitter.usagePaid(c.deploymentId, c.usage, c.appId),
                s.splitter.usageToken(c.deploymentId, c.usage, c.appId) == feeToken
            )
        );
        uint256 maintainerBalance = IERC20(feeToken).balanceOf(maintainer);
        _step("withdraw", maintainer, address(s.splitter), abi.encodeCall(FeeSplitter.withdraw, (feeToken)));
        _record("withdrawn", abi.encode(IERC20(feeToken).balanceOf(maintainer) - maintainerBalance));
        _step("withdraw again", maintainer, address(s.splitter), abi.encodeCall(FeeSplitter.withdraw, (feeToken)));
    }

    /// @dev Deprecation keeps the stack approved; revocation stops it.
    function _phaseRevocations(Sys memory s, Ctx memory c) internal {
        bytes32[] memory ids = _releaseList(c);
        _step("deprecateRelease", owner, address(s.apps), abi.encodeCall(AppRegistry.deprecateRelease, (c.releaseId)));
        _record("approved after deprecate", abi.encode(s.registry.isStackApproved(customer, c.stackHash)));
        vm.warp(block.timestamp + 60);
        _heartbeat("heartbeat after deprecate", s, c, keccak256("q4"), testOracleKey);
        _step("revokeRelease", owner, address(s.apps), abi.encodeCall(AppRegistry.revokeRelease, (c.releaseId, "x")));
        _record("approved after revoke", abi.encode(s.registry.isStackApproved(customer, c.stackHash)));
        vm.warp(block.timestamp + 60);
        _heartbeat("heartbeat after revoke", s, c, keccak256("q5"), testOracleKey);
        _step(
            "re-approve with a revoked release",
            customer,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.approveStack, (c.stackHash, ids, c.imageId, 0))
        );
        _step("revokeImage", owner, address(s.platform), abi.encodeCall(PlatformRegistry.revokeImage, (c.imageId, "x")));
        _record("image approved after revoke", abi.encode(s.platform.isApprovedImage(c.imageId)));
    }

    /// @dev Close is final.
    function _phaseClose(Sys memory s, Ctx memory c) internal {
        _step(
            "stranger closes",
            stranger,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.closeDeployment, (c.deploymentId))
        );
        _step(
            "close", customer, address(s.registry), abi.encodeCall(DeploymentRegistry.closeDeployment, (c.deploymentId))
        );
        _step(
            "close again",
            owner,
            address(s.registry),
            abi.encodeCall(DeploymentRegistry.closeDeployment, (c.deploymentId))
        );
        _pay("payFees after close", s, c, customer, 1, false);
        IDeploymentRegistry.Deployment memory d = s.registry.getDeployment(c.deploymentId);
        _record("deployment", abi.encode(d));
        _record("appInDeployment", abi.encode(s.registry.appInDeployment(c.deploymentId, c.appId)));
        _record(
            "solvency",
            abi.encode(s.splitter.totalCredited(feeToken) <= IERC20(feeToken).balanceOf(address(s.splitter)))
        );
    }

    function _heartbeat(string memory label, Sys memory s, Ctx memory c, bytes32 quote, uint256 key) internal {
        uint64 t = uint64(block.timestamp);
        _step(
            label,
            ops,
            address(s.registry),
            abi.encodeCall(
                DeploymentRegistry.heartbeat,
                (c.deploymentId, quote, t, 1, _sig(key, s.registry.heartbeatDigest(c.deploymentId, quote, t)))
            )
        );
    }

    function _pay(string memory label, Sys memory s, Ctx memory c, address payer, uint256 amount, bool topUp) internal {
        bytes memory data = topUp
            ? abi.encodeCall(FeeSplitter.topUpFees, (c.deploymentId, c.appId, feeToken, amount, c.usage))
            : abi.encodeCall(FeeSplitter.payFees, (c.deploymentId, c.appId, feeToken, amount, c.usage));
        if (payer == enclave) {
            vm.prank(FUNDER);
            assertTrue(IERC20(feeToken).transfer(enclave, amount));
            vm.prank(enclave);
            assertTrue(IERC20(feeToken).approve(address(s.splitter), amount));
        }
        _step(label, payer, address(s.splitter), data);
    }

    function _sig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encode(abi.encodePacked(r, s, v));
    }

    /// @dev Calls `target` as `actor` and records (success, returndata) under `label`. Returns the record.
    function _step(string memory label, address actor, address target, bytes memory data)
        internal
        returns (bytes memory outcome)
    {
        vm.prank(actor);
        (bool ok, bytes memory ret) = target.call(data);
        outcome = abi.encode(ok, ret);
        _record(label, outcome);
    }

    function _returned(bytes memory outcome) internal pure returns (bytes memory ret) {
        bool ok;
        (ok, ret) = abi.decode(outcome, (bool, bytes));
        require(ok, "step reverted");
    }

    function _record(string memory label, bytes memory outcome) internal {
        _labels.push(label);
        _outcomes.push(outcome);
    }
}

interface OwnerView {
    function owner() external view returns (address);
    function pendingOwner() external view returns (address);
    function VERSION() external view returns (string memory);
}
