// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.26;

import { Guard } from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";
import "@safe-global/safe-contracts/contracts/common/Enum.sol";

interface IBlockSafeGuard is Guard {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    )
        external;

    function checkAfterExecution(bytes32 txHash, bool success) external;
}
