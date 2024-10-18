// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.26;

import { PackedUserOperation } from "module-bases/external/ERC4337.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ISafe2 as ISafe } from "../interfaces/ISafe2.sol";
import { UnsignedUserOperation } from "../utils/DataTypes.sol";
import "../utils/Errors.sol";
import "src/utils/Roles.sol";
import { ITokenshieldKernal } from "src/interfaces/ITokenshieldKernal.sol";
import { IRecoveryExecutor } from "src/interfaces/IRecoveryExecutor.sol";
import { SignatureDecoder } from "@safe-global/safe-contracts/contracts/common/SignatureDecoder.sol";
// import { console } from "forge-std/console.sol";

contract GuardianValidator is IValidator, EIP712, SignatureDecoder {
    // using ECDSA for bytes32;

    type Validation is uint256;

    enum AccountInitialization {
        NotInitialized,
        Initializing,
        Initialized
    }

    ITokenshieldKernal immutable kernal;

    mapping(address account => AccountInitialization initStatus) accountStatus;

    Validation internal constant VALIDATION_SUCCESS = Validation.wrap(0);
    Validation internal constant VALIDATION_FAILED = Validation.wrap(1);

    constructor(address _kernal) EIP712("TokenShield", "1") {
        kernal = ITokenshieldKernal(_kernal);
    }

    modifier whenNotPaused() {
        bool isPaused = isAccountPaused(msg.sender);
        if (isPaused == true) {
            revert Tokenshield_Account_Paused();
        }
        _;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (
            /**
             * userOpHash
             */
            uint256
        )
    {
        return verifySignatureOfUserOp(userOp, userOpHash);
    }

    function onInstall(bytes calldata data) external override {
        address owner = abi.decode(data, (address));
        address account = msg.sender;

        if (owner == address(0)) revert Tokenshield_ZeroAddress();

        if (account.code.length == 0) revert Tokenshield_EoaNotSupported();

        bytes32 hashLocation = keccak256(abi.encodePacked(account));
        accountStatus[account] = AccountInitialization.Initializing;
        assembly {
            // priorOwner := tload(hashLocation)

            tstore(hashLocation, owner) //@follow-up what if they deploy the account without doing the transaction?
        }
    }

    function onUninstall(bytes calldata data) external override { }

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) { }

    function isInitialized(address smartAccount) external view override returns (bool) { }

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

    function verifySignatureOfUserOp(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash
    )
        internal
        whenNotPaused
        returns (uint256)
    {
        address owner;
        AccountInitialization currentAccountStatus = accountStatus[_userOp.sender];

        if (currentAccountStatus == AccountInitialization.NotInitialized) {
            revert Tokenshield_Validator_Guardian_AccountNotInitialized();
        } else if (currentAccountStatus == AccountInitialization.Initializing) {
            bytes32 ownerLocation = keccak256(abi.encodePacked(_userOp.sender));
            assembly {
                owner := tload(ownerLocation)
                tstore(ownerLocation, 0)
            }

            accountStatus[_userOp.sender] = AccountInitialization.Initialized;
            address signer = checkSignature(_userOp);
            if (signer != owner) {
                revert Tokenshield_NotValidOwner();
            }
        } else if (currentAccountStatus == AccountInitialization.Initialized) {
            // Check Threshold is one
            ISafe account = ISafe(_userOp.sender);
            uint256 threshold = account.getThreshold();

            if (threshold != 1) {
                revert Tokenshield_Validator_Guardian_InValidThreshold(1, threshold);
            }

            address signer = checkSignature(_userOp);
            if (!account.isOwner(signer)) {
                revert Tokenshield_NotValidOwner();
            }
        }

        return Validation.unwrap(VALIDATION_SUCCESS);
    }

    function checkSignature(PackedUserOperation calldata _userOp) public view returns (address signer) {
        // // Create unsigned UserOp
        UnsignedUserOperation memory unsignedUserOp = UnsignedUserOperation({
            sender: _userOp.sender,
            nonce: _userOp.nonce,
            initCode: _userOp.initCode,
            callData: _userOp.callData,
            accountGasLimits: _userOp.accountGasLimits,
            preVerificationGas: _userOp.preVerificationGas,
            gasFees: _userOp.gasFees,
            paymasterAndData: _userOp.paymasterAndData
        });
        // // Get the EIP712 Hash
        bytes32 transactionHash = getTransactionHash(unsignedUserOp);
        bytes32 digest = _hashTypedDataV4(transactionHash);
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

    function isAccountPaused(address account) internal view returns (bool isPaused) {
        address recoveryExecutorAddress = kernal.getRoleMember(TOKENSHIELD_RECOVERY_EXECUTOR, 0);
        isPaused = IRecoveryExecutor(recoveryExecutorAddress).isRecovering(account);
    }
}
