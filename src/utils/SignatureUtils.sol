// SPDX-License-Identifier: GPL-v3
pragma solidity 0.8.26;

import { UnsignedUserOperation } from "src/utils/DataTypes.sol";
import "safe7579/src/DataTypes.sol";
import "safe7579/test/dependencies/EntryPoint.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


abstract contract SignatureUtils {

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    string domainName = "TokenShield";
    string domainVersion = "1";


    function getDigest(PackedUserOperation memory _userOp, address guardianValidator) internal returns (bytes32 digest) {
        UnsignedUserOperation memory unsignedUserOp = getUnsignedUserOp(_userOp);
        // // Get the EIP712 Hash
        bytes32 transactionHash = getTransactionHash(unsignedUserOp);
        digest = getTransactionHashWithDomainSeperator(transactionHash, address(guardianValidator));
    }

    function getTransactionHash(UnsignedUserOperation memory _unsignedUserOp) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "UnsignedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)"
                ),
                _unsignedUserOp.sender,
                _unsignedUserOp.nonce,
                keccak256(bytes(_unsignedUserOp.initCode)),
                keccak256(bytes(_unsignedUserOp.callData)),
                _unsignedUserOp.accountGasLimits,
                _unsignedUserOp.preVerificationGas,
                _unsignedUserOp.gasFees
            )
        );
        // keccak256(bytes(_unsignedUserOp.paymasterAndData))
    }

    function domainSeparator(address verifyingContract) internal view returns (bytes32 domainSeperator) {
        domainSeperator = getDomainHash(
            EIP712Domain({
                name: domainName,
                version: domainVersion,
                chainId: block.chainid,
                verifyingContract: verifyingContract
            })
        );
    }

    function getDomainHash(EIP712Domain memory domain) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(domain.name)),
                keccak256(bytes(domain.version)),
                domain.chainId,
                domain.verifyingContract
            )
        );
    }

    function getTransactionHashWithDomainSeperator(
        bytes32 transactionHash,
        address verifyingContract
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(verifyingContract), transactionHash));
        return digest;
    }

    function getUnsignedUserOp(PackedUserOperation memory _userOp)
        internal
        pure
        returns (UnsignedUserOperation memory unsignedUserOp)
    {
        // // Create unsigned UserOp
        unsignedUserOp = UnsignedUserOperation({
            sender: _userOp.sender,
            nonce: _userOp.nonce,
            initCode: _userOp.initCode,
            callData: _userOp.callData,
            accountGasLimits: _userOp.accountGasLimits,
            preVerificationGas: _userOp.preVerificationGas,
            gasFees: _userOp.gasFees,
            paymasterAndData: _userOp.paymasterAndData
        });
    }
}
