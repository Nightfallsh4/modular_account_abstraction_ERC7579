// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.26;

import { IExecutor } from "erc7579/interfaces/IERC7579Module.sol";
import "erc7579/interfaces/IERC7579Module.sol";
import "src/utils/Errors.sol";
import "src/utils/Roles.sol";
import "src/utils/Events.sol";
import { ITokenshieldSafe7579 } from "src/interfaces/ITokenshieldSafe7579.sol";

import { ITokenshieldKernal } from "src/interfaces/ITokenshieldKernal.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureDecoder } from "@safe-global/safe-contracts/contracts/common/SignatureDecoder.sol";

import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ISafe2 as ISafe } from "../interfaces/ISafe2.sol";

import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";

contract RecoveryModule is IExecutor, EIP712, SignatureDecoder {
    using SignatureChecker for address;
    using ECDSA for bytes32;

    struct AccountStatus {
        address nominee;
        uint64 recoveryEndTime;
        address newOwner;
        address oldOwner;
        bool isInitialized;
    }
    // bool isRecoverying;

    address internal constant SENTINEL_OWNERS = address(0x1);
    ITokenshieldKernal immutable kernal;

    mapping(address account => AccountStatus status) private accountStatus;

    constructor(address _kernal) EIP712("Tokenshield Recovery", "1") {
        kernal = ITokenshieldKernal(_kernal);
    }

    modifier onlyInitialised(address account) {
        if (!getAccountStatus(account).isInitialized) {
            revert Tokenshield_Executor_Recovery_AccountNotInitialized();
        }
        _;
    }

    modifier whenNotRecoverying(address account) {
        if (isRecovering(account)) {
            revert Tokenshield_Account_Already_Recoverying();
        }
        _;
    }

    modifier whenRecoverying(address account) {
        if (!isRecovering(account)) {
            revert Tokenshield_Account_Not_Recoverying();
        }
        _;
    }

    /**
     * @dev This function is called by the smart account during installation of the module
     *  arbitrary data that may be required on the module during `onInstall`
     * initialization
     *
     * MUST revert on error (i.e. if module is already enabled)
     */
    function onInstall(bytes calldata data) external {// @note @follow-up nominee can be set as the owner itself which'll break recovery
        address initialNominee = abi.decode(data, (address));
        if (initialNominee == address(0)) {
            revert Tokenshield_ZeroAddress();
        }
        if (initialNominee == msg.sender) {
            revert Tokenshield_Recovery_AccountCantBeOwnNominee();
        }
        accountStatus[msg.sender].nominee = initialNominee;
        accountStatus[msg.sender].isInitialized = true;
    }

    /**
     * @dev This function is called by the smart account during uninstallation of the module
     * @param data arbitrary data that may be required on the module during `onUninstall`
     * de-initialization
     *
     * MUST revert on error
     */
    function onUninstall(bytes calldata data) external { }

    /**
     * @dev Returns boolean value if module is a certain type
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     *
     * MUST return true if the module is of the given type and false otherwise
     */
    function isModuleType(uint256 moduleTypeId) external view returns (bool) {
        if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev This function is used to start the recovery process
     */
    function startRecovery(
        address account,
        address newOwner,
        address oldOwner,
        uint64 recoveryEndTime,
        bytes memory signatures
    )
        external
        onlyInitialised(account)
        whenNotRecoverying(account)
    {
        if (account == address(0) || newOwner == address(0) || oldOwner == address(0)) {
            revert Tokenshield_ZeroAddress();
        }
        if (newOwner == getAccountStatus(account).nominee) {
            revert Tokenshield_OwnerCantBeNominee();
        }
        if (newOwner == account || newOwner == oldOwner) {
            revert Tokenshield_New_Owner_Not_Valid();
        }

        if (!ISafe(account).isOwner(oldOwner)) {
            revert Tokenshield_NotValidOwner();
        }

        if (recoveryEndTime < uint64(block.timestamp) + 3 days) {
            revert Tokenshield_Recovery_Time_NotValid();
        }

        checkSignaturesForRecovery(account, newOwner, recoveryEndTime, signatures);

        // accountStatus[account].isRecoverying = true;
        accountStatus[account].newOwner = newOwner;
        accountStatus[account].oldOwner = oldOwner;
        accountStatus[account].recoveryEndTime = recoveryEndTime;

        emit Tokenshield_RecoveryStarted(account, newOwner, recoveryEndTime);
    }

    function stopRecovery(address account, bytes memory signatures) external whenRecoverying(account) {
        checkSignaturesForRecovery(account, signatures);

        accountStatus[account].newOwner = address(0);
        accountStatus[account].oldOwner = address(0);
        accountStatus[account].recoveryEndTime = 0;
    }

    function completeRecovery(address account) external onlyInitialised(account) whenNotRecoverying(account) {
        // Check if recovery period over
        AccountStatus memory _accountStatus = getAccountStatus(account);

        if (_accountStatus.newOwner == address(0)) {
            revert Tokenshield_New_Owner_Not_Set();
        }
        accountStatus[account].newOwner = address(0);
        accountStatus[account].oldOwner = address(0);
        accountStatus[account].recoveryEndTime = 0;

        // Change Owner to new owner in safe

        // Create calldata for the account to execute
        bytes memory targetCalldata =
            abi.encodeCall(ISafe.swapOwner, (SENTINEL_OWNERS, _accountStatus.oldOwner, _accountStatus.newOwner));

        // Encode the call into the calldata
        bytes memory executeCalldata = abi.encodeCall(
            IERC7579Account.executeFromExecutor,
            (ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(account, uint256(0), targetCalldata))
        );
        (bool success, ) = address(account).call(executeCalldata);

        if (!success) {
            revert Tokenshield_RecoveryNotSuccess();
        }
    }

    /**
     * @dev Function to change the nominee of the account. SHould be called
     * @param account The smart account whose nominee is being changed
     * @param newNominee The address of the new nominee to be set
     * @param signatures  The signature of the account owner and the guardianValidator
     */
    function changeNominee(
        address account,
        address newNominee,
        bytes memory signatures
    )
        external
        onlyInitialised(account)
    { }

    /**
     * @dev Returns if the module was already initialized for a provided smartaccount
     */
    function getAccountStatus(address account) public view returns (AccountStatus memory) {
        return accountStatus[account];
    }

    function isInitialized(address account) external view override returns (bool) {
        return accountStatus[account].isInitialized;
    }

    function isRecovering(address account) public view returns (bool) {
        return accountStatus[account].recoveryEndTime > block.timestamp;
    }

    function checkSignaturesForRecovery(
        address account,
        address newOwner,
        uint64 recoveryEndTime,
        bytes memory signatures
    )
        internal
        view
    {
        // Get the EIP712 Hash
        bytes32 recoveryHash = getRecoveryHash(account, newOwner, recoveryEndTime);
        bytes32 digest = _hashTypedDataV4(recoveryHash);

        // Split the Signature
        (uint8 v1, bytes32 r1, bytes32 s1) = signatureSplit(signatures, 0);
        (uint8 v2, bytes32 r2, bytes32 s2) = signatureSplit(signatures, 1);

        ////// Verify signature
        //// Check nominee signature and then tokenshield signature
        address nominee = getAccountStatus(account).nominee;

        if (nominee == address(0)) {
            revert Tokenshield_ZeroAddress();
        }

        // Nominee can be either EOA or Smart Account
        bool isNominee = nominee.isValidSignatureNow(digest, abi.encodePacked(r1, s1, v1));

        // Guardian Signer can only be EOA
        (address guardianSigner,,) = digest.tryRecover(v2, r2, s2);

        if (!isNominee) {
            revert Tokenshield_NotValidNominee();
        }

        if (guardianSigner == address(0)) {
            revert Tokenshield_InvalidGuardian();
        }
        if (!kernal.isApprovedGuardian(guardianSigner)) revert Tokenshield_InvalidGuardian();
    }

    function checkSignaturesForRecovery(address account, bytes memory signatures) internal view {
        AccountStatus memory _accountStatus = getAccountStatus(account);
        // Get the EIP712 Hash
        bytes32 recoveryHash = getRecoveryHash(account, _accountStatus.newOwner, _accountStatus.recoveryEndTime);
        bytes32 digest = _hashTypedDataV4(recoveryHash);

        // Split the Signature
        (uint8 v1, bytes32 r1, bytes32 s1) = signatureSplit(signatures, 0);
        (uint8 v2, bytes32 r2, bytes32 s2) = signatureSplit(signatures, 1);

        ////// Verify signature
        //// Check owner signature and then tokenshield signature
        // Owner Signer can only be EOA
        (address ownerSigner,,) = digest.tryRecover(v1, r1, s1);

        // Guardian Signer can only be EOA
        (address guardianSigner,,) = digest.tryRecover(v2, r2, s2);

        if (ownerSigner == address(0) || guardianSigner == address(0)) {
            revert Tokenshield_InvalidSignature(ownerSigner, guardianSigner);
        }
        if (guardianSigner == address(0)) {
            revert Tokenshield_InvalidGuardian();
        }
        if (!kernal.isApprovedGuardian(guardianSigner)) revert Tokenshield_InvalidGuardian();
        ISafe _account = ISafe(account);

        if (!_account.isOwner(ownerSigner)) {
            revert Tokenshield_NotValidOwner();
        }
    }

    function getRecoveryHash(address account, address newOwner, uint64 recoveryEndTime) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("Recovery(address account,address newOwner,uint64 recoveryNonce)"),
                account,
                newOwner,
                recoveryEndTime
            )
        );
    }
}
