// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {IPlatformRegistry} from "./interfaces/IPlatformRegistry.sol";
import {OwnableNoRenounce} from "./utils/OwnableNoRenounce.sol";

/// @title PlatformRegistry
/// @notice Registry of measured platform (guest OS) images. The key broker and `sealed verify` compare a TDX quote's
///         MRTD and RTMR0-2 against `measurementsHash`, and DeploymentRegistry only accepts approved images.
/// @dev D-007: addImage takes the raw 48-byte measurements, computes measurementsHash onchain and emits both, so the
///      event can never disagree with the stored hash. Status: None -> Active -> Deprecated -> Revoked, or
///      Active -> Revoked. Revoked is terminal.
///      Each measurement set is registered once (contract review): a revoked image's MRTD/RTMRs cannot come back
///      under a new imageId, and imageByMeasurements maps a quote's measurements to its one image.
contract PlatformRegistry is IPlatformRegistry, OwnableNoRenounce {
    /// @notice Contract version.
    string public constant VERSION = "1.0.0";

    /// @notice Length in bytes of each TDX measurement register (SHA-384).
    uint256 public constant MEASUREMENT_LENGTH = 48;

    mapping(bytes32 imageId => Image image) private _images;

    /// @notice The image registered with a measurementsHash (bytes32(0) when none). Never cleared.
    mapping(bytes32 measurementsHash => bytes32 imageId) public imageByMeasurements;

    /// @notice Number of images ever added.
    uint256 public imageCount;

    /// @notice Emitted by addImage with the raw measurements and their hash.
    /// @param imageId The image id.
    /// @param measurementsHash keccak256(abi.encodePacked(mrtd, rtmr0, rtmr1, rtmr2)).
    /// @param name Image name.
    /// @param version Image version.
    /// @param mrtd Raw MRTD (48 bytes).
    /// @param rtmr0 Raw RTMR0 (48 bytes).
    /// @param rtmr1 Raw RTMR1 (48 bytes).
    /// @param rtmr2 Raw RTMR2 (48 bytes).
    /// @param isDebug Whether the image is a debug image.
    /// @param sourceURI Source and build recipe location.
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

    /// @notice Emitted when an Active image is deprecated.
    /// @param imageId The image id.
    event ImageDeprecated(bytes32 indexed imageId);

    /// @notice Emitted when an image is revoked (terminal).
    /// @param imageId The image id.
    /// @param previousStatus Status before revocation (Active or Deprecated).
    /// @param reason Human-readable reason.
    event ImageRevoked(bytes32 indexed imageId, ImageStatus previousStatus, string reason);

    /// @notice imageId was zero.
    error ZeroImageId();
    /// @notice An image with this id already exists.
    error ImageAlreadyExists(bytes32 imageId);
    /// @notice These measurements are already registered (in any status) under `imageId`.
    error MeasurementsAlreadyRegistered(bytes32 measurementsHash, bytes32 imageId);
    /// @notice No image with this id exists.
    error ImageNotFound(bytes32 imageId);
    /// @notice A measurement was not exactly 48 bytes. `index` is 0 for MRTD and 1..3 for RTMR0..RTMR2.
    error InvalidMeasurementLength(uint256 index, uint256 length);
    /// @notice name or version was empty.
    error EmptyField();
    /// @notice The image's status does not allow this transition.
    error InvalidImageStatus(bytes32 imageId, ImageStatus status);

    /// @param initialOwner The owner (OWNER).
    constructor(address initialOwner) OwnableNoRenounce(initialOwner) {}

    /// @notice Adds an Active image. Owner only.
    /// @dev imageId is computed offchain (keccak256(abi.encode(name, version, measurementsHash))); any unique non-zero
    ///      id is accepted. The measurements must not belong to any earlier image, whatever its status.
    /// @param imageId Unique non-zero image id.
    /// @param name Image name (non-empty).
    /// @param version Image version (non-empty).
    /// @param mrtd MRTD, exactly 48 bytes.
    /// @param rtmr0 RTMR0, exactly 48 bytes.
    /// @param rtmr1 RTMR1, exactly 48 bytes.
    /// @param rtmr2 RTMR2, exactly 48 bytes.
    /// @param isDebug True for debug images (stored, but never approved).
    /// @param sourceURI Source and build recipe location.
    /// @return measurementsHash The computed keccak256(mrtd || rtmr0 || rtmr1 || rtmr2).
    /// @dev Parameters are `memory` (not `calldata`) to stay within the legacy codegen stack limit.
    function addImage(
        bytes32 imageId,
        string memory name,
        string memory version,
        bytes memory mrtd,
        bytes memory rtmr0,
        bytes memory rtmr1,
        bytes memory rtmr2,
        bool isDebug,
        string memory sourceURI
    ) external onlyOwner returns (bytes32 measurementsHash) {
        if (imageId == bytes32(0)) revert ZeroImageId();
        if (_images[imageId].status != ImageStatus.None) revert ImageAlreadyExists(imageId);
        if (bytes(name).length == 0 || bytes(version).length == 0) revert EmptyField();
        measurementsHash = computeMeasurementsHash(mrtd, rtmr0, rtmr1, rtmr2);
        bytes32 existing = imageByMeasurements[measurementsHash];
        if (existing != bytes32(0)) revert MeasurementsAlreadyRegistered(measurementsHash, existing);
        imageByMeasurements[measurementsHash] = imageId;

        Image storage image = _images[imageId];
        image.measurementsHash = measurementsHash;
        image.isDebug = isDebug;
        image.status = ImageStatus.Active;
        image.addedAt = uint64(block.timestamp);
        image.name = name;
        image.version = version;
        image.sourceURI = sourceURI;
        unchecked {
            ++imageCount;
        }

        emit ImageAdded(imageId, measurementsHash, name, version, mrtd, rtmr0, rtmr1, rtmr2, isDebug, sourceURI);
    }

    /// @notice Deprecates an Active image. Owner only. Deprecated images are no longer approved: like revokeImage,
    ///         this stops registrations and heartbeats of every stack on the image at once (D-013 keeps images
    ///         literal), and the measurements cannot be registered again.
    /// @param imageId The image id.
    function deprecateImage(bytes32 imageId) external onlyOwner {
        Image storage image = _images[imageId];
        if (image.status == ImageStatus.None) revert ImageNotFound(imageId);
        if (image.status != ImageStatus.Active) revert InvalidImageStatus(imageId, image.status);
        image.status = ImageStatus.Deprecated;
        emit ImageDeprecated(imageId);
    }

    /// @notice Revokes an Active or Deprecated image. Owner only. Terminal.
    /// @param imageId The image id.
    /// @param reason Human-readable reason (emitted, not stored).
    function revokeImage(bytes32 imageId, string calldata reason) external onlyOwner {
        Image storage image = _images[imageId];
        ImageStatus previous = image.status;
        if (previous == ImageStatus.None) revert ImageNotFound(imageId);
        if (previous == ImageStatus.Revoked) revert InvalidImageStatus(imageId, previous);
        image.status = ImageStatus.Revoked;
        emit ImageRevoked(imageId, previous, reason);
    }

    /// @inheritdoc IPlatformRegistry
    function isApprovedImage(bytes32 imageId) external view returns (bool) {
        Image storage image = _images[imageId];
        return image.status == ImageStatus.Active && !image.isDebug;
    }

    /// @inheritdoc IPlatformRegistry
    function getImage(bytes32 imageId) external view returns (Image memory) {
        Image storage image = _images[imageId];
        if (image.status == ImageStatus.None) revert ImageNotFound(imageId);
        return image;
    }

    /// @notice Status of an image (None for unknown ids). Never reverts.
    /// @param imageId The image id.
    /// @return status The image status.
    function imageStatus(bytes32 imageId) external view returns (ImageStatus status) {
        return _images[imageId].status;
    }

    /// @notice keccak256(abi.encodePacked(mrtd, rtmr0, rtmr1, rtmr2)), requiring each to be exactly 48 bytes.
    /// @param mrtd MRTD.
    /// @param rtmr0 RTMR0.
    /// @param rtmr1 RTMR1.
    /// @param rtmr2 RTMR2.
    /// @return The measurements hash.
    function computeMeasurementsHash(bytes memory mrtd, bytes memory rtmr0, bytes memory rtmr1, bytes memory rtmr2)
        public
        pure
        returns (bytes32)
    {
        if (mrtd.length != MEASUREMENT_LENGTH) revert InvalidMeasurementLength(0, mrtd.length);
        if (rtmr0.length != MEASUREMENT_LENGTH) revert InvalidMeasurementLength(1, rtmr0.length);
        if (rtmr1.length != MEASUREMENT_LENGTH) revert InvalidMeasurementLength(2, rtmr1.length);
        if (rtmr2.length != MEASUREMENT_LENGTH) revert InvalidMeasurementLength(3, rtmr2.length);
        return keccak256(abi.encodePacked(mrtd, rtmr0, rtmr1, rtmr2));
    }
}
