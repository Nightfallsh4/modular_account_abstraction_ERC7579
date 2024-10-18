// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.26;

struct UnsignedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
}
