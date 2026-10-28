// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {DeploymentRegistry} from "../../src/DeploymentRegistry.sol";
import {FeeSplitter} from "../../src/FeeSplitter.sol";
import {OracleSignatureVerifier} from "../../src/OracleSignatureVerifier.sol";
import {PlatformRegistry} from "../../src/PlatformRegistry.sol";
import {IAppRegistry} from "../../src/interfaces/IAppRegistry.sol";
import {IDeploymentRegistry} from "../../src/interfaces/IDeploymentRegistry.sol";
import {IPlatformRegistry} from "../../src/interfaces/IPlatformRegistry.sol";
import {MockERC20} from "../mocks/MockERC20.sol";

/// @notice Shared fixture: deploys the whole system with a mock 6-decimal fee token and offers helpers to build
///         catalogs, approvals, oracle-signed records and heartbeats.
abstract contract SealedTest is Test {
    uint256 internal constant START_TIME = 1_800_000_000;
    uint256 internal constant PER_PAYMENT_CAP = 5_000_000;
    uint256 internal constant DAILY_CAP = 20_000_000;
    uint16 internal constant DEFAULT_SHARE_BPS = 2000;

    address internal owner = makeAddr("owner");
    address internal ops = makeAddr("ops");
    address internal customer;
    uint256 internal customerKey;
    address internal maintainer = makeAddr("maintainer");
    address internal treasury = makeAddr("treasury");
    address internal enclaveSigner;
    uint256 internal enclaveSignerKey;
    address internal stranger = makeAddr("stranger");
    address internal oracle;
    uint256 internal oracleKey;

    PlatformRegistry internal platform;
    AppRegistry internal apps;
    OracleSignatureVerifier internal oracleVerifier;
    DeploymentRegistry internal registry;
    FeeSplitter internal splitter;
    MockERC20 internal token;

    bytes32 internal imageId;
    bytes32 internal appA;
    bytes32 internal appB;
    bytes32 internal releaseA;
    bytes32 internal releaseB;
    bytes32 internal stackHash = keccak256("stack-1");

    function setUp() public virtual {
        vm.warp(START_TIME);
        (oracle, oracleKey) = makeAddrAndKey("oracle");
        (customer, customerKey) = makeAddrAndKey("customer");
        (enclaveSigner, enclaveSignerKey) = makeAddrAndKey("enclaveSigner");

        token = new MockERC20("Path USD (mock)", "pathUSD");
        platform = new PlatformRegistry(owner);
        apps = new AppRegistry(owner);
        oracleVerifier = new OracleSignatureVerifier(owner);
        registry = new DeploymentRegistry(owner, platform, apps);
        splitter = new FeeSplitter(owner, registry, apps, address(token), treasury, PER_PAYMENT_CAP, DAILY_CAP);

        vm.startPrank(owner);
        apps.grantRegistrar(ops);
        oracleVerifier.addSigner(oracle);
        registry.setVerifier(1, address(oracleVerifier));
        vm.stopPrank();

        imageId = _addImage("sealed-os", "1.0.0", false);
        appA = _registerApp("llm-gateway", DEFAULT_SHARE_BPS);
        appB = _registerApp("crm", DEFAULT_SHARE_BPS);
        releaseA = _publish(appA, "1.0.0");
        releaseB = _publish(appB, "1.0.0");
    }

    // ------------------------------------------------------------------------------------------------------
    // Catalog helpers
    // ------------------------------------------------------------------------------------------------------

    function _measurement(uint8 seed) internal pure returns (bytes memory m) {
        m = new bytes(48);
        for (uint256 i; i < 48; ++i) {
            m[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i)))));
        }
    }

    function _measurementsHash() internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_measurement(1), _measurement(2), _measurement(3), _measurement(4)));
    }

    function _imageIdFor(string memory name, string memory version) internal pure returns (bytes32) {
        return keccak256(abi.encode(name, version, _measurementsHash()));
    }

    function _addImage(string memory name, string memory version, bool isDebug) internal returns (bytes32 id) {
        id = _imageIdFor(name, version);
        vm.prank(owner);
        platform.addImage(
            id,
            name,
            version,
            _measurement(1),
            _measurement(2),
            _measurement(3),
            _measurement(4),
            isDebug,
            "https://github.com/sealed/sealed-os"
        );
    }

    function _registerApp(string memory slug, uint16 shareBps) internal returns (bytes32 appId) {
        appId = keccak256(bytes(slug));
        vm.prank(owner);
        apps.registerApp(appId, slug, slug, "Apache-2.0", maintainer, shareBps, string.concat("ipfs://", slug));
    }

    function _publish(bytes32 appId, string memory version) internal returns (bytes32 releaseId) {
        vm.prank(ops);
        releaseId = apps.publishRelease(
            appId,
            version,
            keccak256(abi.encode("bundle", appId, version)),
            keccak256(abi.encode("egress", appId, version)),
            keccak256(abi.encode("sbom", appId, version)),
            "https://example.org/provenance",
            "https://example.org/signature"
        );
    }

    // ------------------------------------------------------------------------------------------------------
    // Approval and deployment helpers
    // ------------------------------------------------------------------------------------------------------

    function _releases2() internal view returns (bytes32[] memory ids) {
        ids = new bytes32[](2);
        ids[0] = releaseA;
        ids[1] = releaseB;
    }

    function _approve(address who, bytes32 stack, bytes32[] memory ids, bytes32 image, uint64 expiry) internal {
        vm.prank(who);
        registry.approveStack(stack, ids, image, expiry);
    }

    function _approveDefault() internal {
        _approve(customer, stackHash, _releases2(), imageId, 0);
    }

    function _deploymentId(address who, bytes32 stack, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(who, stack, salt));
    }

    function _record(bytes32 salt) internal view returns (IDeploymentRegistry.Record memory r) {
        r = IDeploymentRegistry.Record({
            deploymentId: _deploymentId(customer, stackHash, salt),
            customer: customer,
            stackHash: stackHash,
            imageId: imageId,
            quoteHash: keccak256(abi.encode("quote", salt)),
            eventLogHash: keccak256(abi.encode("eventlog", salt)),
            configHash: keccak256(abi.encode("config", salt)),
            enclaveSigner: enclaveSigner,
            attestedAt: uint64(block.timestamp)
        });
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory evidence) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        evidence = abi.encode(abi.encodePacked(r, s, v));
    }

    function _oracleEvidence(IDeploymentRegistry.Record memory r) internal view returns (bytes memory) {
        return _sign(oracleKey, registry.recordDigest(r));
    }

    function _heartbeatEvidence(bytes32 id, bytes32 quoteHash, uint64 attestedAt) internal view returns (bytes memory) {
        return _sign(oracleKey, registry.heartbeatDigest(id, quoteHash, attestedAt));
    }

    function _register(IDeploymentRegistry.Record memory r) internal {
        bytes memory evidence = _oracleEvidence(r);
        vm.prank(ops);
        registry.registerDeployment(r, 1, evidence);
    }

    /// @dev Approves the default stack and registers one deployment; returns its id.
    function _deployDefault() internal returns (bytes32 id) {
        _approveDefault();
        IDeploymentRegistry.Record memory r = _record(bytes32(uint256(1)));
        _register(r);
        id = r.deploymentId;
    }

    function _fund(address who, uint256 amount) internal {
        token.mint(who, amount);
        vm.prank(who);
        token.approve(address(splitter), type(uint256).max);
    }
}
