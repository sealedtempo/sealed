// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

/// @title IPlatformRegistry
/// @notice Read interface of the platform image registry, used by DeploymentRegistry and offchain components.
interface IPlatformRegistry {
    /// @notice Lifecycle of a platform image. Revoked is terminal.
    enum ImageStatus {
        None,
        Active,
        Deprecated,
        Revoked
    }

    /// @notice A measured platform (guest OS) image.
    /// @param measurementsHash keccak256(abi.encodePacked(mrtd, rtmr0, rtmr1, rtmr2)), each 48 bytes.
    /// @param isDebug True for debug images, which are never approved.
    /// @param status Current lifecycle status.
    /// @param addedAt Block timestamp of addImage.
    /// @param name Image name.
    /// @param version Image version.
    /// @param sourceURI Where the image source and build recipe live.
    struct Image {
        bytes32 measurementsHash;
        bool isDebug;
        ImageStatus status;
        uint64 addedAt;
        string name;
        string version;
        string sourceURI;
    }

    /// @notice True only when the image is Active and not a debug image.
    /// @param imageId The image id.
    /// @return approved Whether new and existing stacks may use the image.
    function isApprovedImage(bytes32 imageId) external view returns (bool approved);

    /// @notice Returns an image. Reverts for unknown ids.
    /// @param imageId The image id.
    /// @return image The stored image.
    function getImage(bytes32 imageId) external view returns (Image memory image);
}
