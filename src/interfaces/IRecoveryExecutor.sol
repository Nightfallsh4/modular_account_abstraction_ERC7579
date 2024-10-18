// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.26;

interface IRecoveryExecutor {
    function isRecovering(address account) external view returns (bool);
}
