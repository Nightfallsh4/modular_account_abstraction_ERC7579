// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.26;

error Tokenshield_Validator_Guardian_InValidThreshold(uint256 expectedThreshold, uint256 actualThreshold);
error Tokenshield_ZeroAddress();
error Tokenshield_EoaNotSupported();
error Tokenshield_Validator_Guardian_AccountNotInitialized();
error Tokenshield_InvalidGuardian();
error Tokenshield_GuardianValidator_LengthMismatch();
error Tokenshield_NotValidOwner();
error Tokenshield_InvalidSignature(address signer, address guardian);
error Tokenshield_Executor_Recovery_AccountNotInitialized();
error Tokenshield_Account_Already_Recoverying();
error Tokenshield_Only_Recovery_Executor();
error Tokenshield_Account_Paused();
error Tokenshield_Recovery_Time_NotValid();
error Tokenshield_NotValidNominee();
error Tokenshield_Account_Not_Recoverying();
error Tokenshield_New_Owner_Not_Set();
error Tokenshield_RecoveryNotSuccess();
error Tokenshield_Recovery_AccountCantBeOwnNominee();
error Tokenshield_OwnerCantBeNominee();
error Tokenshield_New_Owner_Not_Valid();
