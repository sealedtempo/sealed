// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {OracleSignatureVerifier} from "../../src/OracleSignatureVerifier.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {SealedTest} from "../utils/SealedTest.sol";

/// @notice Calls every privileged or party-only function of the five contracts as an account with no role,
///         with the real ids of the fixture (apps, releases, image, deployment, token, signer), so a missing
///         access check cannot hide behind an unknown-id revert. Every call must revert.
contract StrangerHandler is Test {
    AppRegistry internal immutable apps;
    PlatformRegistry internal immutable platform;
    OracleSignatureVerifier internal immutable verifier;
    DeploymentRegistry internal immutable registry;
    FeeSplitter internal immutable splitter;

    struct Ids {
        bytes32 appA;
        bytes32 releaseA;
        bytes32 imageId;
        bytes32 deploymentId;
        bytes32 stackHash;
        bytes32 usageHash;
        address token;
        address oracle;
        address ops;
        address customer;
        address maintainer;
    }

    Ids internal _ids;
    address[] internal _strangers;
    bool public strangerSucceeded;
    string public lastSuccess;
    mapping(uint256 which => uint256) public tried;
    uint256 public constant CALLS = 44;

    constructor(
        AppRegistry apps_,
        PlatformRegistry platform_,
        OracleSignatureVerifier verifier_,
        DeploymentRegistry registry_,
        FeeSplitter splitter_,
        Ids memory ids_,
        address[] memory strangers_
    ) {
        apps = apps_;
        platform = platform_;
        verifier = verifier_;
        registry = registry_;
        splitter = splitter_;
        _ids = ids_;
        _strangers = strangers_;
    }

    function poke(uint256 who, uint256 which, uint256 arg) external {
        which %= CALLS;
        address s = _strangers[who % _strangers.length];
        (address target, bytes memory data) = _call(which, s, arg);
        vm.prank(s);
        (bool ok,) = target.call(data);
        if (ok) {
            strangerSucceeded = true;
            lastSuccess = string.concat("call ", vm.toString(which), " succeeded for a stranger");
        }
        tried[which]++;
    }

    function _call(uint256 w, address s, uint256 arg) internal view returns (address, bytes memory) {
        Ids memory i = _ids;
        bytes32 h = keccak256(abi.encode(arg));
        address a = address(uint160(arg));
        if (w < 15) return (address(apps), _appsCall(w, s, arg, i, h, a));
        if (w < 20) return (address(platform), _platformCall(w, s, i, h));
        if (w < 25) return (address(verifier), _verifierCall(w, s, i));
        if (w < 33) return (address(registry), _registryCall(w, s, arg, i, h));
        return (address(splitter), _splitterCall(w, s, arg, i, h));
    }

    function _appsCall(uint256 w, address s, uint256 arg, Ids memory i, bytes32 h, address a)
        internal
        view
        returns (bytes memory)
    {
        if (w == 0) return abi.encodeCall(AppRegistry.registerApp, (keccak256("x"), "x", "x", "MIT", s, 0, ""));
        if (w == 1) return abi.encodeCall(AppRegistry.setMaintainer, (i.appA, s));
        if (w == 2) return abi.encodeCall(AppRegistry.setMaintainerShare, (i.appA, uint16(arg % 5001)));
        if (w == 3) return abi.encodeCall(AppRegistry.setMetadataURI, (i.appA, "ipfs://stranger"));
        if (w == 4) return abi.encodeCall(AppRegistry.publishRelease, (i.appA, "9.9.9", h, h, h, "", ""));
        if (w == 5) return abi.encodeCall(AppRegistry.deprecateRelease, (i.releaseA));
        if (w == 6) return abi.encodeCall(AppRegistry.revokeRelease, (i.releaseA, "stranger"));
        if (w == 7) return abi.encodeCall(AppRegistry.grantRegistrar, (s));
        if (w == 8) return abi.encodeCall(AppRegistry.revokeRegistrar, (i.ops));
        if (w == 9) return abi.encodeWithSignature("grantRole(bytes32,address)", apps.REGISTRAR_ROLE(), s);
        if (w == 10) return abi.encodeWithSignature("revokeRole(bytes32,address)", apps.REGISTRAR_ROLE(), i.ops);
        if (w == 11) return abi.encodeWithSignature("renounceRole(bytes32,address)", apps.REGISTRAR_ROLE(), i.ops);
        if (w == 12) return abi.encodeWithSignature("grantRole(bytes32,address)", bytes32(0), s);
        if (w == 13) return abi.encodeWithSignature("transferOwnership(address)", a == address(0) ? s : a);
        return abi.encodeWithSignature("acceptOwnership()");
    }

    function _platformCall(uint256 w, address s, Ids memory i, bytes32 h) internal pure returns (bytes memory) {
        if (w == 15) {
            // Truncating to bytes16 is intended: 32 + 16 = 48 bytes, one TDX register.
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes memory m = abi.encodePacked(h, bytes16(h));
            return abi.encodeCall(PlatformRegistry.addImage, (h, "x", "1", m, m, m, m, false, ""));
        }
        if (w == 16) return abi.encodeCall(PlatformRegistry.deprecateImage, (i.imageId));
        if (w == 17) return abi.encodeCall(PlatformRegistry.revokeImage, (i.imageId, "stranger"));
        if (w == 18) return abi.encodeWithSignature("transferOwnership(address)", s);
        return abi.encodeWithSignature("acceptOwnership()");
    }

    function _verifierCall(uint256 w, address s, Ids memory i) internal pure returns (bytes memory) {
        if (w == 20) return abi.encodeCall(OracleSignatureVerifier.addSigner, (s));
        if (w == 21) return abi.encodeCall(OracleSignatureVerifier.removeSigner, (i.oracle));
        if (w == 22) return abi.encodeWithSignature("transferOwnership(address)", s);
        if (w == 23) return abi.encodeWithSignature("acceptOwnership()");
        return abi.encodeWithSignature("renounceOwnership()");
    }

    function _registryCall(uint256 w, address s, uint256 arg, Ids memory i, bytes32 h)
        internal
        view
        returns (bytes memory)
    {
        if (w == 25) return abi.encodeCall(DeploymentRegistry.closeDeployment, (i.deploymentId));
        if (w == 26) return abi.encodeCall(DeploymentRegistry.setVerifier, (uint8(1 + arg % 2), address(this)));
        if (w == 27) return abi.encodeCall(DeploymentRegistry.setMaxAttestationAge, (uint64(1 + arg % 30 days)));
        if (w == 28) return abi.encodeCall(DeploymentRegistry.pause, ());
        if (w == 29) return abi.encodeWithSignature("transferOwnership(address)", s);
        if (w == 30) {
            bytes memory evidence = abi.encode(abi.encodePacked(h, h, uint8(27 + arg % 2)));
            return
                abi.encodeCall(DeploymentRegistry.heartbeat, (i.deploymentId, h, uint64(block.timestamp), 1, evidence));
        }
        if (w == 31) {
            IDeploymentRegistry.Record memory r = IDeploymentRegistry.Record({
                deploymentId: h,
                customer: i.customer,
                stackHash: i.stackHash,
                imageId: i.imageId,
                quoteHash: h,
                eventLogHash: h,
                configHash: h,
                enclaveSigner: s,
                attestedAt: uint64(block.timestamp)
            });
            return abi.encodeCall(
                DeploymentRegistry.registerDeployment, (r, 1, abi.encode(abi.encodePacked(h, h, uint8(27))))
            );
        }
        return abi.encodeWithSignature("acceptOwnership()");
    }

    function _splitterCall(uint256 w, address s, uint256 arg, Ids memory i, bytes32 h)
        internal
        pure
        returns (bytes memory)
    {
        if (w == 33) {
            return abi.encodeCall(FeeSplitter.payFees, (i.deploymentId, i.appA, i.token, 1 + arg % 5e6, h));
        }
        if (w == 34) {
            return abi.encodeCall(FeeSplitter.topUpFees, (i.deploymentId, i.appA, i.token, 2_000_000, i.usageHash));
        }
        if (w == 35) return abi.encodeCall(FeeSplitter.withdraw, (i.token));
        if (w == 36) return abi.encodeCall(FeeSplitter.sweepUnaccounted, (i.token));
        if (w == 37) return abi.encodeCall(FeeSplitter.setToken, (i.token, false, 0, 0));
        if (w == 38) return abi.encodeCall(FeeSplitter.setCaps, (i.token, 1, 1));
        if (w == 39) return abi.encodeCall(FeeSplitter.setTreasury, (s));
        if (w == 40) return abi.encodeCall(FeeSplitter.pause, ());
        if (w == 41) return abi.encodeWithSignature("transferOwnership(address)", s);
        if (w == 42) return abi.encodeWithSignature("acceptOwnership()");
        return abi.encodeCall(FeeSplitter.unpause, ());
    }
}

/// @notice Accounts with no role call every function of all five contracts, both through StrangerHandler (real
///         ids) and with arbitrary calldata straight at the contracts (customer stack approvals excluded: those
///         are the caller's own state). Nothing observable may change. Reverts are the point here, so this
///         campaign does not fail on them.
contract StrangerInvariantTest is SealedTest {
    bytes32 internal deploymentId;
    bytes32 internal initialFingerprint;
    address[] internal strangers;
    StrangerHandler internal handler;

    function setUp() public override {
        super.setUp();
        deploymentId = _deployDefault();
        _fund(customer, 10_000_000);
        vm.prank(customer);
        splitter.payFees(deploymentId, appA, address(token), 1_000_000, keccak256("stranger-usage"));
        _addImage("sealed-os-debug", "1.0.0", true);

        strangers.push(makeAddr("fuzz-stranger-1"));
        strangers.push(makeAddr("fuzz-stranger-2"));
        strangers.push(makeAddr("fuzz-stranger-3"));
        for (uint256 i; i < strangers.length; ++i) {
            targetSender(strangers[i]);
            // Give strangers tokens and allowances, so FeeSplitter's checks (not a missing balance) stop them.
            _fund(strangers[i], 10_000_000);
        }
        handler = new StrangerHandler(
            apps,
            platform,
            oracleVerifier,
            registry,
            splitter,
            StrangerHandler.Ids({
                appA: appA,
                releaseA: releaseA,
                imageId: imageId,
                deploymentId: deploymentId,
                stackHash: stackHash,
                usageHash: keccak256("stranger-usage"),
                token: address(token),
                oracle: oracle,
                ops: ops,
                customer: customer,
                maintainer: maintainer
            }),
            strangers
        );
        targetContract(address(handler));
        targetContract(address(apps));
        targetContract(address(platform));
        targetContract(address(oracleVerifier));
        targetContract(address(registry));
        targetContract(address(splitter));
        bytes4[] memory customerPaths = new bytes4[](2);
        customerPaths[0] = DeploymentRegistry.approveStack.selector;
        customerPaths[1] = DeploymentRegistry.revokeStack.selector;
        excludeSelector(FuzzSelector({addr: address(registry), selectors: customerPaths}));
        initialFingerprint = fingerprint();
    }

    function fingerprint() public view returns (bytes32 h) {
        h = keccak256(
            abi.encode(
                apps.owner(),
                apps.pendingOwner(),
                platform.owner(),
                platform.pendingOwner(),
                oracleVerifier.owner(),
                oracleVerifier.pendingOwner(),
                registry.owner(),
                registry.pendingOwner(),
                splitter.owner(),
                splitter.pendingOwner()
            )
        );
        h = keccak256(
            abi.encode(
                h,
                apps.appCount(),
                apps.releaseCount(appA),
                apps.releaseCount(appB),
                apps.getApp(appA),
                apps.getApp(appB),
                apps.releaseStatus(releaseA),
                apps.releaseStatus(releaseB),
                apps.hasRole(apps.REGISTRAR_ROLE(), ops)
            )
        );
        h = keccak256(abi.encode(h, platform.imageCount(), platform.getImage(imageId)));
        h = keccak256(
            abi.encode(
                h,
                oracleVerifier.signerCount(),
                oracleVerifier.isSigner(oracle),
                registry.verifiers(1),
                registry.verifiers(2),
                registry.maxAttestationAge(),
                registry.paused(),
                registry.deploymentCount(),
                registry.getDeployment(deploymentId),
                registry.isStackApproved(customer, stackHash)
            )
        );
        h = keccak256(
            abi.encode(
                h,
                splitter.paused(),
                splitter.treasury(),
                splitter.tokenConfig(address(token)),
                splitter.totalCredited(address(token)),
                splitter.credited(address(token), maintainer),
                splitter.credited(address(token), treasury),
                splitter.usagePaid(deploymentId, keccak256("stranger-usage"), appA),
                token.balanceOf(address(splitter))
            )
        );
        for (uint256 i; i < strangers.length; ++i) {
            address s = strangers[i];
            h = keccak256(
                abi.encode(
                    h,
                    apps.hasRole(apps.REGISTRAR_ROLE(), s),
                    apps.hasRole(bytes32(0), s),
                    oracleVerifier.isSigner(s),
                    splitter.credited(address(token), s),
                    token.balanceOf(s)
                )
            );
        }
    }

    /// forge-config: default.invariant.fail-on-revert = false
    /// forge-config: ci.invariant.fail-on-revert = false
    /// forge-config: deep.invariant.fail-on-revert = false
    function invariant_strangersChangeNothing() public view {
        assertEq(fingerprint(), initialFingerprint, "a caller without a role changed state");
        assertFalse(handler.strangerSucceeded(), handler.lastSuccess());
    }

    /// @dev Every privileged call of the handler reverts for every stranger, in one fixed pass.
    function test_everyPrivilegedCallRevertsForStrangers() public {
        for (uint256 w; w < handler.CALLS(); ++w) {
            for (uint256 s; s < strangers.length; ++s) {
                handler.poke(s, w, uint256(keccak256(abi.encode(w, s))));
            }
            assertEq(handler.tried(w), strangers.length, "every call tried");
        }
        assertFalse(handler.strangerSucceeded(), handler.lastSuccess());
        assertEq(fingerprint(), initialFingerprint, "a caller without a role changed state");
    }
}
