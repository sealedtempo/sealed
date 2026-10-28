// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {AppRegistry} from "../../src/AppRegistry.sol";
import {Deploy} from "../../script/Deploy.s.sol";
import {RegisterCatalog} from "../../script/RegisterCatalog.s.sol";

/// @notice Pins the contents of catalog/catalog.mainnet.json, the file OWNER registers on Tempo mainnet, and
///         registers it in-process on a fresh deployment. slug, name and licenseSpdx are permanent onchain, so a
///         change to this file must change this test too.
contract CatalogMainnetTest is Test {
    string internal constant CATALOG = "catalog/catalog.mainnet.json";
    address internal constant PATH_USD = 0x20C0000000000000000000000000000000000000;
    /// @dev MAINTAINER_DEFAULT_ADDRESS (STATUS.md wallets table).
    address internal constant MAINTAINER = 0x500A40bAB57E5F58f9c50D33fF70C6EaaAB11Eb2;
    uint16 internal constant SHARE_BPS = 2000;
    string internal constant METADATA_BASE = "https://github.com/sealedtempo/sealed/blob/main/catalog/apps/";

    uint256 internal ownerKey;
    address internal owner;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
    }

    function _expected() internal pure returns (string[3][6] memory e) {
        e[0] = ["llm-gateway", "LLM gateway", "MIT"];
        e[1] = ["scraper", "Scraper", "Apache-2.0"];
        e[2] = ["crm", "CRM (EspoCRM)", "AGPL-3.0-or-later"];
        e[3] = ["coding-agent", "Coding agent", "MIT"];
        e[4] = ["internal-tools", "Internal tools (ToolJet)", "AGPL-3.0-only"];
        e[5] = ["inference-relay", "Inference relay", "Apache-2.0"];
    }

    function test_mainnetCatalog_contents() public {
        RegisterCatalog script = new RegisterCatalog();
        string memory catalog = vm.readFile(CATALOG);

        // No default maintainer: every entry must name its maintainer itself.
        RegisterCatalog.AppEntry[] memory apps = script.parseApps(catalog, address(0));
        string[3][6] memory e = _expected();
        assertEq(apps.length, e.length, "six seed apps");
        for (uint256 i; i < apps.length; ++i) {
            string memory p = string.concat(".apps[", vm.toString(i), "]");
            assertEq(apps[i].slug, e[i][0], "slug");
            assertEq(apps[i].name, e[i][1], "name");
            assertEq(apps[i].licenseSpdx, e[i][2], "licenseSpdx");
            assertEq(apps[i].maintainer, MAINTAINER, "maintainer");
            assertEq(apps[i].maintainerShareBps, SHARE_BPS, "maintainerShareBps");
            assertEq(apps[i].metadataURI, string.concat(METADATA_BASE, e[i][0], "/manifest.yaml"), "metadataURI");
            // parseApps already reverts on a wrong appId; this also requires that every entry states one.
            assertEq(vm.parseJsonBytes32(catalog, string.concat(p, ".appId")), keccak256(bytes(e[i][0])), "appId");
            assertFalse(vm.keyExistsJson(catalog, string.concat(p, "._pending")), "no pending entry");
        }
        assertEq(script.parseImages(catalog).length, 0, "no image until production measurements exist");

        string memory deployments = vm.readFile("deployments/tempo-mainnet.json");
        assertEq(
            vm.parseJsonAddress(catalog, "._network.AppRegistry"),
            vm.parseJsonAddress(deployments, ".contracts.AppRegistry.address")
        );
        assertEq(
            vm.parseJsonAddress(catalog, "._network.PlatformRegistry"),
            vm.parseJsonAddress(deployments, ".contracts.PlatformRegistry.address")
        );
        assertEq(vm.parseJsonUint(catalog, "._network.chainId"), 4217);
    }

    function test_mainnetCatalog_registers() public {
        string memory file = "deployments/test-catalog-mainnet.json";
        Deploy deployer = new Deploy();
        Deploy.Config memory c;
        c.ownerKey = ownerKey;
        c.owner = owner;
        c.ops = makeAddr("ops");
        c.oracle = makeAddr("oracle");
        c.treasury = makeAddr("treasury");
        c.feeToken = PATH_USD;
        c.perPaymentCap = 5_000_000;
        c.perDeploymentDailyCap = 20_000_000;
        c.network = "test";
        c.outFile = file;
        Deploy.Deployed memory d = deployer.deploy(c);

        RegisterCatalog script = new RegisterCatalog();
        string memory catalog = vm.readFile(CATALOG);
        (uint256 images, uint256 added) =
            script.register(catalog, d.appRegistry, d.platformRegistry, ownerKey, address(0));
        assertEq(images, 0);
        assertEq(added, 6);
        assertEq(d.appRegistry.appCount(), 6);

        string[3][6] memory e = _expected();
        for (uint256 i; i < e.length; ++i) {
            bytes32 appId = keccak256(bytes(e[i][0]));
            assertEq(d.appRegistry.appAt(i), appId, "registration order");
            AppRegistry.App memory app = d.appRegistry.getApp(appId);
            assertEq(app.slug, e[i][0]);
            assertEq(app.name, e[i][1]);
            assertEq(app.licenseSpdx, e[i][2]);
            assertEq(app.maintainer, MAINTAINER);
            assertEq(app.maintainerShareBps, SHARE_BPS);
            assertEq(app.metadataURI, string.concat(METADATA_BASE, e[i][0], "/manifest.yaml"));
            assertGt(app.registeredAt, 0);
        }

        (images, added) = script.register(catalog, d.appRegistry, d.platformRegistry, ownerKey, address(0));
        assertEq(added, 0, "re-run registers nothing");
    }
}
