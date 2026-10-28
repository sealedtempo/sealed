// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {PlatformRegistry} from "../src/PlatformRegistry.sol";
import {IPlatformRegistry} from "../src/interfaces/IPlatformRegistry.sol";
import {OwnableNoRenounce} from "../src/utils/OwnableNoRenounce.sol";
import {SealedTest} from "./utils/SealedTest.sol";

contract PlatformRegistryTest is SealedTest {
    event ImageAdded(
        bytes32 indexed imageId,
        bytes32 indexed measurementsHash,
        string name,
        string version,
        bytes mrtd,
        bytes rtmr0,
        bytes rtmr1,
        bytes rtmr2,
        bool isDebug,
        string sourceURI
    );
    event ImageDeprecated(bytes32 indexed imageId);
    event ImageRevoked(bytes32 indexed imageId, IPlatformRegistry.ImageStatus previousStatus, string reason);

    bytes32 internal newId = keccak256("image-2");

    function _add(bytes32 id, bool isDebug) internal {
        vm.prank(owner);
        platform.addImage(
            id, "sealed-os", "2.0.0", _measurement(1), _measurement(2), _measurement(3), _measurement(4), isDebug, "uri"
        );
    }

    function test_metadata() public view {
        assertEq(platform.VERSION(), "1.0.0");
        assertEq(platform.MEASUREMENT_LENGTH(), 48);
        assertEq(platform.owner(), owner);
        assertEq(platform.imageCount(), 1);
    }

    function test_renounceOwnership_disabled() public {
        vm.prank(owner);
        vm.expectRevert(OwnableNoRenounce.RenounceOwnershipDisabled.selector);
        platform.renounceOwnership();
    }

    // ------------------------------------------------------------------------------------------------------
    // addImage
    // ------------------------------------------------------------------------------------------------------

    function test_addImage_storesAndEmitsRawMeasurements() public {
        bytes32 expectedHash =
            keccak256(abi.encodePacked(_measurement(1), _measurement(2), _measurement(3), _measurement(4)));
        vm.expectEmit(address(platform));
        emit ImageAdded(
            newId,
            expectedHash,
            "sealed-os",
            "2.0.0",
            _measurement(1),
            _measurement(2),
            _measurement(3),
            _measurement(4),
            false,
            "uri"
        );
        vm.prank(owner);
        bytes32 returned = platform.addImage(
            newId,
            "sealed-os",
            "2.0.0",
            _measurement(1),
            _measurement(2),
            _measurement(3),
            _measurement(4),
            false,
            "uri"
        );
        assertEq(returned, expectedHash);

        IPlatformRegistry.Image memory img = platform.getImage(newId);
        assertEq(img.measurementsHash, expectedHash);
        assertEq(img.name, "sealed-os");
        assertEq(img.version, "2.0.0");
        assertEq(img.sourceURI, "uri");
        assertFalse(img.isDebug);
        assertEq(uint8(img.status), uint8(IPlatformRegistry.ImageStatus.Active));
        assertEq(img.addedAt, block.timestamp);
        assertEq(platform.imageCount(), 2);
        assertTrue(platform.isApprovedImage(newId));
        assertEq(uint8(platform.imageStatus(newId)), uint8(IPlatformRegistry.ImageStatus.Active));
    }

    function test_addImage_debugImageIsNeverApproved() public {
        _add(newId, true);
        assertTrue(platform.getImage(newId).isDebug);
        assertFalse(platform.isApprovedImage(newId));
    }

    function test_addImage_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        platform.addImage(
            newId, "n", "v", _measurement(1), _measurement(2), _measurement(3), _measurement(4), false, ""
        );
    }

    function test_addImage_revertsOnZeroId() public {
        vm.prank(owner);
        vm.expectRevert(PlatformRegistry.ZeroImageId.selector);
        platform.addImage(
            bytes32(0), "n", "v", _measurement(1), _measurement(2), _measurement(3), _measurement(4), false, ""
        );
    }

    function test_addImage_revertsOnDuplicate() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.ImageAlreadyExists.selector, imageId));
        platform.addImage(
            imageId, "n", "v", _measurement(1), _measurement(2), _measurement(3), _measurement(4), false, ""
        );
    }

    function test_addImage_revertsOnDuplicateEvenAfterRevoke() public {
        vm.prank(owner);
        platform.revokeImage(imageId, "bad");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.ImageAlreadyExists.selector, imageId));
        platform.addImage(
            imageId, "n", "v", _measurement(1), _measurement(2), _measurement(3), _measurement(4), false, ""
        );
    }

    /// @dev Review fix (logic-F5): one image per measurement set, whatever the earlier image's status.
    function test_addImage_revertsOnDuplicateMeasurements() public {
        _add(newId, false);
        bytes32 mh = platform.getImage(newId).measurementsHash;
        assertEq(platform.imageByMeasurements(mh), newId);
        bytes32 third = keccak256("image-3");
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.MeasurementsAlreadyRegistered.selector, mh, newId));
        platform.addImage(
            third, "sealed-os", "2.0.1", _measurement(1), _measurement(2), _measurement(3), _measurement(4), true, ""
        );
        platform.deprecateImage(newId);
        platform.revokeImage(newId, "CVE");
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.MeasurementsAlreadyRegistered.selector, mh, newId));
        platform.addImage(
            third, "sealed-os", "2.0.1", _measurement(1), _measurement(2), _measurement(3), _measurement(4), false, ""
        );
        vm.stopPrank();
        assertEq(uint8(platform.imageStatus(third)), uint8(IPlatformRegistry.ImageStatus.None));
        assertEq(platform.imageByMeasurements(keccak256("none")), bytes32(0));
    }

    function test_addImage_revertsOnEmptyName() public {
        vm.prank(owner);
        vm.expectRevert(PlatformRegistry.EmptyField.selector);
        platform.addImage(newId, "", "v", _measurement(1), _measurement(2), _measurement(3), _measurement(4), false, "");
    }

    function test_addImage_revertsOnEmptyVersion() public {
        vm.prank(owner);
        vm.expectRevert(PlatformRegistry.EmptyField.selector);
        platform.addImage(newId, "n", "", _measurement(1), _measurement(2), _measurement(3), _measurement(4), false, "");
    }

    function test_addImage_revertsOnShortMrtd() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.InvalidMeasurementLength.selector, 0, 47));
        platform.addImage(newId, "n", "v", new bytes(47), _measurement(2), _measurement(3), _measurement(4), false, "");
    }

    function test_addImage_revertsOnLongRtmr0() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.InvalidMeasurementLength.selector, 1, 49));
        platform.addImage(newId, "n", "v", _measurement(1), new bytes(49), _measurement(3), _measurement(4), false, "");
    }

    function test_addImage_revertsOnEmptyRtmr1() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.InvalidMeasurementLength.selector, 2, 0));
        platform.addImage(newId, "n", "v", _measurement(1), _measurement(2), "", _measurement(4), false, "");
    }

    function test_addImage_revertsOnShaLengthRtmr2() public {
        // 32 bytes (a SHA-256 digest) is not a valid TDX register value.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.InvalidMeasurementLength.selector, 3, 32));
        platform.addImage(
            newId, "n", "v", _measurement(1), _measurement(2), _measurement(3), abi.encode(bytes32(0)), false, ""
        );
    }

    function testFuzz_computeMeasurementsHash(
        bytes32 a1,
        bytes16 a2,
        bytes32 b1,
        bytes16 b2,
        bytes32 c1,
        bytes16 c2,
        bytes32 d1,
        bytes16 d2
    ) public view {
        bytes memory m = abi.encodePacked(a1, a2);
        bytes memory r0 = abi.encodePacked(b1, b2);
        bytes memory r1 = abi.encodePacked(c1, c2);
        bytes memory r2 = abi.encodePacked(d1, d2);
        assertEq(platform.computeMeasurementsHash(m, r0, r1, r2), keccak256(abi.encodePacked(m, r0, r1, r2)));
        assertEq(
            platform.computeMeasurementsHash(m, r0, r1, r2), keccak256(abi.encodePacked(a1, a2, b1, b2, c1, c2, d1, d2))
        );
    }

    function testFuzz_computeMeasurementsHash_rejectsWrongLength(uint8 len) public {
        vm.assume(len != 48);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.InvalidMeasurementLength.selector, 0, uint256(len)));
        platform.computeMeasurementsHash(new bytes(len), _measurement(2), _measurement(3), _measurement(4));
    }

    // ------------------------------------------------------------------------------------------------------
    // deprecateImage
    // ------------------------------------------------------------------------------------------------------

    function test_deprecateImage() public {
        vm.expectEmit(address(platform));
        emit ImageDeprecated(imageId);
        vm.prank(owner);
        platform.deprecateImage(imageId);
        assertEq(uint8(platform.getImage(imageId).status), uint8(IPlatformRegistry.ImageStatus.Deprecated));
        assertFalse(platform.isApprovedImage(imageId));
    }

    function test_deprecateImage_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        platform.deprecateImage(imageId);
    }

    function test_deprecateImage_revertsWhenUnknown() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.ImageNotFound.selector, newId));
        platform.deprecateImage(newId);
    }

    function test_deprecateImage_revertsWhenDeprecated() public {
        vm.startPrank(owner);
        platform.deprecateImage(imageId);
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformRegistry.InvalidImageStatus.selector, imageId, IPlatformRegistry.ImageStatus.Deprecated
            )
        );
        platform.deprecateImage(imageId);
        vm.stopPrank();
    }

    function test_deprecateImage_revertsWhenRevoked() public {
        vm.startPrank(owner);
        platform.revokeImage(imageId, "bad");
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformRegistry.InvalidImageStatus.selector, imageId, IPlatformRegistry.ImageStatus.Revoked
            )
        );
        platform.deprecateImage(imageId);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------------------------------------------
    // revokeImage
    // ------------------------------------------------------------------------------------------------------

    function test_revokeImage_fromActive() public {
        vm.expectEmit(address(platform));
        emit ImageRevoked(imageId, IPlatformRegistry.ImageStatus.Active, "CVE-1");
        vm.prank(owner);
        platform.revokeImage(imageId, "CVE-1");
        assertEq(uint8(platform.getImage(imageId).status), uint8(IPlatformRegistry.ImageStatus.Revoked));
        assertFalse(platform.isApprovedImage(imageId));
    }

    function test_revokeImage_fromDeprecated() public {
        vm.startPrank(owner);
        platform.deprecateImage(imageId);
        vm.expectEmit(address(platform));
        emit ImageRevoked(imageId, IPlatformRegistry.ImageStatus.Deprecated, "eol");
        platform.revokeImage(imageId, "eol");
        vm.stopPrank();
        assertEq(uint8(platform.getImage(imageId).status), uint8(IPlatformRegistry.ImageStatus.Revoked));
    }

    function test_revokeImage_revertsForNonOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        platform.revokeImage(imageId, "x");
    }

    function test_revokeImage_revertsWhenUnknown() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.ImageNotFound.selector, newId));
        platform.revokeImage(newId, "x");
    }

    function test_revokeImage_isTerminal() public {
        vm.startPrank(owner);
        platform.revokeImage(imageId, "x");
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformRegistry.InvalidImageStatus.selector, imageId, IPlatformRegistry.ImageStatus.Revoked
            )
        );
        platform.revokeImage(imageId, "again");
        vm.stopPrank();
    }

    // ------------------------------------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------------------------------------

    function test_getImage_revertsWhenUnknown() public {
        vm.expectRevert(abi.encodeWithSelector(PlatformRegistry.ImageNotFound.selector, newId));
        platform.getImage(newId);
    }

    function test_isApprovedImage_unknownIsFalse() public view {
        assertFalse(platform.isApprovedImage(newId));
        assertEq(uint8(platform.imageStatus(newId)), uint8(IPlatformRegistry.ImageStatus.None));
    }
}
