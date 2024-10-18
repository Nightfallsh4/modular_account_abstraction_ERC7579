// SPDX-License-Identifier: GPL3
pragma solidity 0.8.26;

bytes32 constant MFA_SETTER = keccak256("TOKENSHIELD_MFA_SETTER_ROLE"); // @note Sets the guardian for the accounts
bytes32 constant MFA_SETTER_ADMIN = keccak256("TOKENSHIELD_MFA_SETTER_ROLE_ADMIN"); // @note Admin for the MFA_Setter
    // and used to overrdie it if it gets compromised
bytes32 constant TOKENSHIELD_GUARDIAN_VALIDATOR = keccak256("TOKENSHIELD_GUARDIAN_VALIDATOR"); // @note holds the
    // current validator module in the 0 index of the address of this role
bytes32 constant TOKENSHIELD_RECOVERY_EXECUTOR = keccak256("TOKENSHIELD_RECOVERY_EXECUTOR"); // @note holds the current
    // recovery module in the 0 index of the address list of this role
bytes32 constant MODULE_SETTER = keccak256("MODULE_SETTER"); // @note Admin for the TOKENSHIELD_RECOVERY_EXECUTOR and
    // TOKENSHIELD_GUARDIAN_VALIDATOR roles.
