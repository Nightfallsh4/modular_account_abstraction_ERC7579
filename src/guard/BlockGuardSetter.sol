// SPDX-License-Identifier: GPL-3
pragma solidity 0.8.26;

import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { Guard } from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";

contract BlockGuardSetter {
    event ChangedGuard(address indexed guard);

    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    address internal constant ZERO_ADDRESS = address(0);
    /**
     * @dev Set a guard that checks transactions before execution
     *      This can only be done via a Safe transaction.
     *      ⚠️ IMPORTANT: Since a guard has full power to block Safe transaction execution,
     *        a broken guard can cause a denial of service for the Safe. Make sure to carefully
     *        audit the guard code and design recovery mechanisms.
     * @notice Set Transaction Guard `guard` for the Safe. Make sure you trust the guard.
     * @param guard The address of the guard to be used or the 0 address to disable the guard
     */

    function setGuard(address guard) external {
        if (guard != address(0)) {
            require(Guard(guard).supportsInterface(type(Guard).interfaceId), "GS300");
        }
        bytes32 slot = GUARD_STORAGE_SLOT;

        assembly {
            sstore(slot, guard)
        }
        emit ChangedGuard(guard);
    }

    /**
     * @dev Should only be called by delegateCall from the Safe Proxy through the TokenshieldSafe7579 module
     * Should not be callable anytime other than when removing.
     * ------------- BlockSafeGuardJustSkip while temporary and only when permanent do this
     */
    function removeGuard() external {
        bytes32 slot = GUARD_STORAGE_SLOT;
        address zeroAddress = ZERO_ADDRESS;

        assembly {
            sstore(slot, zeroAddress)
        }
        emit ChangedGuard(ZERO_ADDRESS);
    }
}
