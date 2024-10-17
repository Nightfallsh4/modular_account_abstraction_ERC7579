// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";
import { PackedUserOperation } from "module-bases/external/ERC4337.sol";
import { ITokenshieldKernal } from "src/interfaces/ITokenshieldKernal.sol";

contract PasskeyValidator is IValidator {
    type Validation is uint256;

    ITokenshieldKernal immutable kernal;

    Validation internal constant VALIDATION_SUCCESS = Validation.wrap(0);
    Validation internal constant VALIDATION_FAILED = Validation.wrap(1);

    constructor(address _kernal) {
        kernal = ITokenshieldKernal(_kernal);
    }

    /**
     * @dev called by ERC7579 account during install
     * @param data contains the data needed to install this validator
     */
    function onInstall(bytes calldata data) external override {
        // Check if installed already

        // If not, deploy SafePasskeySignerProxy x and y coordinates

        // If
    }

    function onUninstall(bytes calldata data) external override { }

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) { }

    function isInitialized(address smartAccount) external view override returns (bool) { }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (uint256)
    { }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    { }
}
