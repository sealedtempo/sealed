// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";

import {Deploy} from "../../script/Deploy.s.sol";
import {RegisterCatalog} from "../../script/RegisterCatalog.s.sol";

/// @notice RegisterCatalog.s.sol without a private key (OWNER_ADDRESS, for a hardware wallet or a fork that
///         impersonates the owner), its owner check, and image entries whose measurements are already registered
///         (one measurement file per machine shape, D-078). Found by the mainnet fork rehearsal.
contract RegisterCatalogOwnerTest is Test {
    address internal constant PATH_USD = 0x20C0000000000000000000000000000000000000;

    uint256 internal ownerKey;
    address internal owner;
    address internal maintainer = makeAddr("maintainer");

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
    }

    function _deploy(string memory outFile) internal returns (Deploy.Deployed memory d) {
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
        c.outFile = outFile;
        d = new Deploy().deploy(c);
    }

    /// @dev A 48-byte placeholder measurement.
    function _mr(string memory label) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(bytes(label)), bytes16(keccak256(bytes(string.concat(label, " b")))));
    }

    function _image(string memory version, string memory rtmr0Label) internal pure returns (string memory) {
        return string.concat(
            '{"name":"sealed-dstack-os","version":"',
            version,
            '","mrtd":"',
            vm.toString(_mr("mrtd")),
            '","rtmr0":"',
            vm.toString(_mr(rtmr0Label)),
            '","rtmr1":"',
            vm.toString(_mr("rtmr1")),
            '","rtmr2":"',
            vm.toString(_mr("rtmr2")),
            '","isDebug":false,"sourceURI":"https://example.invalid/os.tar.gz#sha256=00"}'
        );
    }

    function _catalog(string memory images) internal pure returns (string memory) {
        return string.concat('{"images":[', images, '],"apps":[]}');
    }

    function test_resolveOwner() public {
        RegisterCatalog script = new RegisterCatalog();
        assertEq(script.resolveOwner(ownerKey, address(0)), owner, "key only");
        assertEq(script.resolveOwner(0, owner), owner, "address only: no key needed");
        assertEq(script.resolveOwner(ownerKey, owner), owner, "both, same account");

        address other = makeAddr("other");
        vm.expectRevert(abi.encodeWithSelector(RegisterCatalog.OwnerMismatch.selector, other, owner));
        script.resolveOwner(ownerKey, other);
        vm.expectRevert(RegisterCatalog.NoOwner.selector);
        script.resolveOwner(0, address(0));
    }

    function test_registerAs_ownerAddressWithoutKey() public {
        string memory file = "deployments/test-catalog-owner-address.json";
        Deploy.Deployed memory d = _deploy(file);
        RegisterCatalog script = new RegisterCatalog();
        string memory catalog = vm.readFile("test/fixtures/catalog.example.json");

        (uint256 images, uint256 added) =
            script.registerAs(catalog, d.appRegistry, d.platformRegistry, owner, maintainer);
        assertEq(images, 1);
        assertEq(added, 5);
        assertEq(d.appRegistry.appCount(), 5);
        assertEq(d.platformRegistry.imageCount(), 1);

        (images, added) = script.registerAs(catalog, d.appRegistry, d.platformRegistry, owner, maintainer);
        assertEq(images + added, 0, "re-run registers nothing");
    }

    function test_registerAs_refusesNonOwnerBeforeSending() public {
        string memory file = "deployments/test-catalog-not-owner.json";
        Deploy.Deployed memory d = _deploy(file);
        RegisterCatalog script = new RegisterCatalog();
        string memory catalog = vm.readFile("test/fixtures/catalog.example.json");
        address other = makeAddr("other");

        vm.expectRevert(abi.encodeWithSelector(RegisterCatalog.NotOwner.selector, other, owner, owner));
        script.registerAs(catalog, d.appRegistry, d.platformRegistry, other, maintainer);
        assertEq(d.appRegistry.appCount(), 0);
        assertEq(d.platformRegistry.imageCount(), 0);
    }

    /// @notice Two shapes that measured the same values: the first entry is added, the second one is skipped
    ///         instead of reverting the whole run with MeasurementsAlreadyRegistered.
    function test_register_skipsMeasurementsRegisteredUnderAnotherImageId() public {
        string memory file = "deployments/test-catalog-shapes.json";
        Deploy.Deployed memory d = _deploy(file);
        RegisterCatalog script = new RegisterCatalog();

        string memory both = _catalog(
            string.concat(
                _image("0.6.1-s1+c3-standard-4", "rtmr0 same"), ",", _image("0.6.1-s1+c3-standard-8", "rtmr0 same")
            )
        );
        (uint256 images,) = script.register(both, d.appRegistry, d.platformRegistry, ownerKey, maintainer);
        assertEq(images, 1, "one image per measurement set");
        RegisterCatalog.ImageEntry[] memory parsed = script.parseImages(both);
        assertTrue(d.platformRegistry.isApprovedImage(parsed[0].imageId));
        bytes32 mh = keccak256(abi.encodePacked(parsed[1].mrtd, parsed[1].rtmr0, parsed[1].rtmr1, parsed[1].rtmr2));
        assertEq(d.platformRegistry.imageByMeasurements(mh), parsed[0].imageId, "the shapes share the first imageId");

        // A later file for a shape with its own RTMR0 is added; one that repeats a registered set is skipped.
        string memory later = _catalog(
            string.concat(
                _image("0.6.1-s1+c3-standard-8.later", "rtmr0 same"),
                ",",
                _image("0.6.1-s1+c3-highcpu-8", "rtmr0 other")
            )
        );
        (images,) = script.register(later, d.appRegistry, d.platformRegistry, ownerKey, maintainer);
        assertEq(images, 1);
        assertEq(d.platformRegistry.imageCount(), 2);
    }
}
