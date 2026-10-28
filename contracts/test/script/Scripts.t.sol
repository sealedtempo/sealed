// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {IPlatformRegistry} from "../../src/interfaces/IPlatformRegistry.sol";
import {Deploy} from "../../script/Deploy.s.sol";
import {RegisterCatalog} from "../../script/RegisterCatalog.s.sol";
import {AcceptOwnership, TransferOwnership} from "../../script/TransferOwnership.s.sol";

/// @notice Runs the deploy, catalog and ownership scripts in-process (the same code paths as `forge script`).
contract ScriptsTest is Test {
    address internal constant PATH_USD = 0x20C0000000000000000000000000000000000000;

    uint256 internal ownerKey;
    address internal owner;
    address internal ops = makeAddr("ops");
    address internal oracle = makeAddr("oracle");
    address internal treasury = makeAddr("treasury");
    address internal maintainer = makeAddr("maintainer");

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
    }

    function _config(string memory outFile) internal view returns (Deploy.Config memory c) {
        c.ownerKey = ownerKey;
        c.owner = owner;
        c.ops = ops;
        c.oracle = oracle;
        c.treasury = treasury;
        c.feeToken = PATH_USD; // the TIP-20 precompile exists in `network = "tempo"` test mode
        c.perPaymentCap = 5_000_000;
        c.perDeploymentDailyCap = 20_000_000;
        c.network = "test";
        c.outFile = outFile;
    }

    function _deploy(string memory outFile) internal returns (Deploy.Deployed memory d, string memory json) {
        Deploy script = new Deploy();
        Deploy.Config memory c = _config(outFile);
        d = script.deploy(c);
        script.writeDeployment(c, d);
        json = vm.readFile(outFile);
    }

    function test_deploy_wiresAndWritesJson() public {
        string memory file = "deployments/test-deploy.json";
        (Deploy.Deployed memory d, string memory json) = _deploy(file);

        assertEq(d.platformRegistry.owner(), owner);
        assertEq(d.appRegistry.owner(), owner);
        assertEq(d.oracleVerifier.owner(), owner);
        assertEq(d.deploymentRegistry.owner(), owner);
        assertEq(d.feeSplitter.owner(), owner);
        assertTrue(d.appRegistry.hasRole(d.appRegistry.REGISTRAR_ROLE(), ops));
        assertTrue(d.oracleVerifier.isSigner(oracle));
        assertEq(address(d.deploymentRegistry.verifiers(1)), address(d.oracleVerifier));
        assertEq(address(d.deploymentRegistry.verifiers(2)), address(0), "ZK method stays unset");
        assertEq(d.feeSplitter.treasury(), treasury);
        assertEq(d.feeSplitter.FEE_TOKEN(), PATH_USD);
        assertEq(d.feeSplitter.tokenConfig(PATH_USD).perPaymentCap, 5_000_000);
        assertEq(d.feeSplitter.tokenConfig(PATH_USD).perDeploymentDailyCap, 20_000_000);
        assertEq(address(d.deploymentRegistry.platformRegistry()), address(d.platformRegistry));
        assertEq(address(d.feeSplitter.deploymentRegistry()), address(d.deploymentRegistry));

        assertEq(vm.parseJsonUint(json, ".chainId"), block.chainid);
        assertEq(vm.parseJsonAddress(json, ".deployer"), owner);
        assertEq(vm.parseJsonString(json, ".network"), "test");
        assertEq(vm.parseJsonAddress(json, ".contracts.PlatformRegistry.address"), address(d.platformRegistry));
        assertEq(vm.parseJsonAddress(json, ".contracts.AppRegistry.address"), address(d.appRegistry));
        assertEq(vm.parseJsonAddress(json, ".contracts.OracleSignatureVerifier.address"), address(d.oracleVerifier));
        assertEq(vm.parseJsonAddress(json, ".contracts.DeploymentRegistry.address"), address(d.deploymentRegistry));
        assertEq(vm.parseJsonAddress(json, ".contracts.FeeSplitter.address"), address(d.feeSplitter));
        assertEq(
            vm.parseJsonBytes(json, ".contracts.DeploymentRegistry.constructorArgs"),
            abi.encode(owner, address(d.platformRegistry), address(d.appRegistry))
        );
        assertEq(
            vm.parseJsonBytes(json, ".contracts.FeeSplitter.constructorArgs"),
            abi.encode(
                owner,
                address(d.deploymentRegistry),
                address(d.appRegistry),
                PATH_USD,
                treasury,
                uint256(5_000_000),
                uint256(20_000_000)
            )
        );
        assertEq(vm.parseJsonAddress(json, ".config.ops"), ops);
        assertEq(vm.parseJsonAddress(json, ".config.oracleSigner"), oracle);
        assertEq(vm.parseJsonString(json, ".config.perPaymentCap"), "5000000");
        assertEq(vm.parseJsonString(json, ".compiler.solc"), "0.8.38");
        vm.removeFile(file);
    }

    function test_deploy_rejectsBadConfig() public {
        Deploy script = new Deploy();
        Deploy.Config memory c = _config("deployments/test-unused.json");
        c.treasury = address(0);
        vm.expectRevert(abi.encodeWithSelector(Deploy.InvalidConfig.selector, "treasury"));
        script.deploy(c);

        c = _config("deployments/test-unused.json");
        c.feeToken = makeAddr("no-code");
        vm.expectRevert(abi.encodeWithSelector(Deploy.InvalidConfig.selector, "fee token has no code"));
        script.deploy(c);

        c = _config("deployments/test-unused.json");
        c.perDeploymentDailyCap = c.perPaymentCap - 1;
        vm.expectRevert(abi.encodeWithSelector(Deploy.InvalidConfig.selector, "caps"));
        script.deploy(c);
    }

    function test_deploy_defaultNetworkNames() public {
        Deploy script = new Deploy();
        assertEq(script.defaultNetwork(), "local");
        vm.chainId(4217);
        assertEq(script.defaultNetwork(), "tempo-mainnet");
        vm.chainId(42_431);
        assertEq(script.defaultNetwork(), "chain-42431");
    }

    function test_registerCatalog_isIdempotent() public {
        string memory file = "deployments/test-catalog.json";
        (Deploy.Deployed memory d,) = _deploy(file);
        RegisterCatalog script = new RegisterCatalog();
        string memory catalog = vm.readFile("test/fixtures/catalog.example.json");

        (uint256 images, uint256 appsAdded) =
            script.register(catalog, d.appRegistry, d.platformRegistry, ownerKey, maintainer);
        assertEq(images, 1);
        assertEq(appsAdded, 5);
        assertEq(d.appRegistry.appCount(), 5);

        RegisterCatalog.ImageEntry[] memory parsed = script.parseImages(catalog);
        bytes32 mh = keccak256(abi.encodePacked(parsed[0].mrtd, parsed[0].rtmr0, parsed[0].rtmr1, parsed[0].rtmr2));
        assertEq(parsed[0].imageId, keccak256(abi.encode(parsed[0].name, parsed[0].version, mh)));
        IPlatformRegistry.Image memory img = d.platformRegistry.getImage(parsed[0].imageId);
        assertEq(img.measurementsHash, mh);
        assertTrue(d.platformRegistry.isApprovedImage(parsed[0].imageId));

        AppRegistry.App memory crm = d.appRegistry.getApp(keccak256("crm"));
        assertEq(crm.slug, "crm");
        assertEq(crm.licenseSpdx, "AGPL-3.0-only");
        assertEq(crm.maintainer, maintainer);
        assertEq(crm.maintainerShareBps, 2000);

        (images, appsAdded) = script.register(catalog, d.appRegistry, d.platformRegistry, ownerKey, maintainer);
        assertEq(images, 0, "second run adds nothing");
        assertEq(appsAdded, 0);
        vm.removeFile(file);
    }

    function test_registerCatalog_requiresMaintainer() public {
        RegisterCatalog script = new RegisterCatalog();
        string memory catalog = vm.readFile("test/fixtures/catalog.example.json");
        vm.expectRevert(abi.encodeWithSelector(RegisterCatalog.NoMaintainer.selector, "llm-gateway"));
        script.parseApps(catalog, address(0));
    }

    function _oneApp(string memory extra) internal pure returns (string memory) {
        return string.concat(
            '{"images":[],"apps":[{"slug":"crm","name":"CRM","licenseSpdx":"AGPL-3.0-or-later",',
            '"maintainerShareBps":2000,"metadataURI":"https://example.invalid/crm"',
            extra,
            "}]}"
        );
    }

    function test_registerCatalog_checksGivenAppId() public {
        RegisterCatalog script = new RegisterCatalog();
        bytes32 crmId = keccak256("crm");
        RegisterCatalog.AppEntry[] memory list =
            script.parseApps(_oneApp(string.concat(',"appId":"', vm.toString(crmId), '"')), maintainer);
        assertEq(list.length, 1);
        assertEq(list[0].slug, "crm");

        bytes32 wrong = keccak256("scraper");
        vm.expectRevert(abi.encodeWithSelector(RegisterCatalog.AppIdMismatch.selector, "crm", wrong, crmId));
        script.parseApps(_oneApp(string.concat(',"appId":"', vm.toString(wrong), '"')), maintainer);
    }

    function test_registerCatalog_refusesPendingEntryBeforeSending() public {
        string memory file = "deployments/test-catalog-pending.json";
        (Deploy.Deployed memory d,) = _deploy(file);
        RegisterCatalog script = new RegisterCatalog();
        string memory catalog = _oneApp(',"_pending":"license not settled"');

        vm.expectRevert(abi.encodeWithSelector(RegisterCatalog.PendingEntry.selector, "crm"));
        script.register(catalog, d.appRegistry, d.platformRegistry, ownerKey, maintainer);
        assertEq(d.appRegistry.appCount(), 0, "nothing registered");
        vm.removeFile(file);
    }

    function test_transferAndAcceptOwnership() public {
        string memory file = "deployments/test-ownership.json";
        (Deploy.Deployed memory d, string memory json) = _deploy(file);
        (address multisig, uint256 multisigKey) = makeAddrAndKey("multisig");

        new TransferOwnership().start(json, ownerKey, multisig);
        assertEq(d.feeSplitter.pendingOwner(), multisig);
        assertEq(d.feeSplitter.owner(), owner, "owner keeps control until accepted");
        assertEq(d.platformRegistry.pendingOwner(), multisig);

        new AcceptOwnership().accept(json, multisigKey);
        assertEq(d.platformRegistry.owner(), multisig);
        assertEq(d.appRegistry.owner(), multisig);
        assertEq(d.oracleVerifier.owner(), multisig);
        assertEq(d.deploymentRegistry.owner(), multisig);
        assertEq(d.feeSplitter.owner(), multisig);
        assertTrue(d.appRegistry.hasRole(d.appRegistry.REGISTRAR_ROLE(), ops), "registrar unaffected");
        vm.removeFile(file);
    }

    function test_transferOwnership_rejectsZero() public {
        string memory file = "deployments/test-ownership-zero.json";
        (, string memory json) = _deploy(file);
        TransferOwnership script = new TransferOwnership();
        vm.expectRevert(TransferOwnership.ZeroNewOwner.selector);
        script.start(json, ownerKey, address(0));
        vm.removeFile(file);
    }
}
