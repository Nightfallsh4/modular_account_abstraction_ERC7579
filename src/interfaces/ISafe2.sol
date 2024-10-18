// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.26;

import { ISafe } from "safe7579/src/interfaces/ISafe.sol";

interface ISafe2 is ISafe {
    function checkNSignatures(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures,
        uint256 requiredSignatures
    )
        external
        view;

    function getThreshold() external view returns (uint256);

    function isOwner(address owner) external view returns (bool);

    /**
     * @notice Replaces the owner `oldOwner` in the Safe with `newOwner`. from the Owner Manager Contract inherited by safe
     * @dev This can only be done via a Safe transaction.
     * @param prevOwner Owner that pointed to the owner to be replaced in the linked list
     * @param oldOwner Owner address to be replaced.
     * @param newOwner New owner address.
     */
    function swapOwner(address prevOwner, address oldOwner, address newOwner) external;

    // function getGuard() internal view returns (address guard);
}
