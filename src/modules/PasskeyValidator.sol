// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";
import { PackedUserOperation } from "module-bases/external/ERC4337.sol";
import { ITokenshieldKernal } from "src/interfaces/ITokenshieldKernal.sol";
import { SafeWebAuthnSignerProxy } from
    "@safe-global/safe-modules/modules/passkey/contracts/SafeWebAuthnSignerProxy.sol";
import { SafeWebAuthnSignerFactory } from
    "@safe-global/safe-modules/modules/passkey/contracts/SafeWebAuthnSignerFactory.sol";
import { P256 } from "@safe-global/safe-modules/modules/passkey/contracts/libraries/P256.sol";
import { UnsignedUserOperation } from "../utils/DataTypes.sol";
import { IPasskeySigner } from "src/interfaces/IPasskeySigner.sol";
import { SignatureUtils } from "src/utils/SignatureUtils.sol";

contract PasskeyValidator is IValidator, SignatureUtils {
    type Validation is uint256;

    ITokenshieldKernal immutable kernal;
    SafeWebAuthnSignerFactory immutable signerFactory;

    Validation internal constant VALIDATION_SUCCESS = Validation.wrap(0);
    Validation internal constant VALIDATION_FAILED = Validation.wrap(1);

    mapping(address account => IPasskeySigner passkeySigner) public accountToPasskeySigner;

    constructor(address _kernal, address _signerFactory) {
        kernal = ITokenshieldKernal(_kernal);
        signerFactory = SafeWebAuthnSignerFactory(_signerFactory);
    }

    /**
     * @dev called by ERC7579 account during install
     * @param data contains the data needed to install this validator
     */
    function onInstall(bytes calldata data) external override {
        // Check if installed already
        SafeWebAuthnSignerProxy passkeyVerifier = accountToPasskeySigner[msg.sender];
        (uint256 x, uint256 y, P256.Verifiers verifiers) = abi.decode(data, (uint256, uint256, P256.Verifiers));

        if (address(passkeyVerifier) == address(0)) {
            accountToPasskeySigner[msg.sender] =
                IPasskeySigner(signerFactory.createSigner(x, y, verifiers));
        }
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
    {
        return Validation.unwrap(VALIDATION_SUCCESS);
    }

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

    function checkSignature(PackedUserOperation calldata _userOp) public view returns (address signer) {

        // // Get the EIP712 Hash
        bytes32 digest = getDigest(_userOp, address(this));
        // (bytes32 r1, bytes32 s1, uint8 v1, bytes32 r2, bytes32 s2, uint8 v2) =
        //     abi.decode(_userOp.signature, (bytes32, bytes32, uint8, bytes32, bytes32, uint8));
        (uint8 v1, bytes32 r1, bytes32 s1) = signatureSplit(_userOp.signature, 0);
        (uint8 v2, bytes32 r2, bytes32 s2) = signatureSplit(_userOp.signature, 1);

        (signer,,) = ECDSA.tryRecover(digest, v1, r1, s1);
        (address guardianSigner,,) = ECDSA.tryRecover(digest, v2, r2, s2);
        // console.logBytes32(transactionHash);
        // console.logBytes32(digest);
        // console.logBytes32(r1);
        // console.logBytes32(s1);
        // console.logUint(v1);

        // console.logBytes32(r2);
        // console.logBytes32(s2);
        // console.logUint(v2);

        if (signer == address(0) || guardianSigner == address(0)) {
            // console.log(signer);
            // console.log(guardianSigner);
            revert Tokenshield_InvalidSignature(signer, guardianSigner);
        }
        if (!kernal.isApprovedGuardian(guardianSigner)) revert Tokenshield_InvalidGuardian();
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
}
