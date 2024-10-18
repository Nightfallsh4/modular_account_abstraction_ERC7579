// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.26;

interface IPasskeySigner {
    function isValidSignature(bytes memory data, bytes calldata signature) external view returns (bytes4 magicValue);

    function isValidSignature(bytes32 message, bytes calldata signature) external view returns (bytes4 magicValue);
}
