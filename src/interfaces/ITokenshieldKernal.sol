// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.26;

interface ITokenshieldKernal {
    function isApprovedGuardian(address guardian) external view returns (bool);

    function getRoleMember(bytes32 role, uint256 index) external view returns (address);
}
