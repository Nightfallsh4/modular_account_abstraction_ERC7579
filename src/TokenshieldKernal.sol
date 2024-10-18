// SPDX-License-Identifier: GPL3
pragma solidity 0.8.26;

import { AccessControlEnumerable } from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import "src/utils/Events.sol";
import "src/utils/Errors.sol";
import "src/utils/Roles.sol";

contract TokenshieldKernal is AccessControlEnumerable {
    mapping(address guardian => bool isEnabled) internal isGuardianEnabled;

    constructor(address defaultAdminRole, address mfaSetterRoleAdmin, address moduleSetter) {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdminRole);
        _grantRole(MFA_SETTER_ADMIN, mfaSetterRoleAdmin);
        _setRoleAdmin(MFA_SETTER, MFA_SETTER_ADMIN);
        _grantRole(MODULE_SETTER, moduleSetter);
        _setRoleAdmin(TOKENSHIELD_GUARDIAN_VALIDATOR, MODULE_SETTER); // Only one address for the Guardian Validator
            // Role is
            // expected to be set at a time
        _setRoleAdmin(TOKENSHIELD_RECOVERY_EXECUTOR, MODULE_SETTER); //  Only one address for the Recovery Exectuor Role
            // is
            // expected to be set at a time
    }

    function setGuardian(address[] calldata _guardian, bool[] calldata _isEnabled) external onlyRole(MFA_SETTER) {
        if (_guardian.length != _isEnabled.length) {
            revert Tokenshield_GuardianValidator_LengthMismatch();
        }
        for (uint256 i = 0; i < _guardian.length; i++) {
            isGuardianEnabled[_guardian[i]] = _isEnabled[i];
            emit Tokenshield_Guardian_Changed(_guardian[i], _isEnabled[i]);
        }
    }

    function isApprovedGuardian(address guardian) external view returns (bool) {
        return isGuardianEnabled[guardian];
    }
}
