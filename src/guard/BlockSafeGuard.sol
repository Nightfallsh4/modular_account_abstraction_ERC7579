// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.26;

import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { Guard } from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import { IBlockSafeGuard } from "../interfaces/IBlockSafeGuard.sol";
import "@safe-global/safe-contracts/contracts/interfaces/IERC165.sol";

contract BlockSafeGuard is IBlockSafeGuard {
    error Tokenshield_SafeGuardRevert();

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(Guard).interfaceId // 0xe6d7a83a
            || interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }

    function checkTransaction(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    )
        external
        pure
        override
    {
        revert Tokenshield_SafeGuardRevert();
    }

    function checkAfterExecution(bytes32, bool) external pure override {
        revert Tokenshield_SafeGuardRevert();
    }
}
