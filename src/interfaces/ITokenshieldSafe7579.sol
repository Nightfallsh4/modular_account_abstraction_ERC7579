// SPDX-License-Identifier: GPL3
pragma solidity 0.8.26;

import { ModeCode } from "safe7579/src/lib/ModeLib.sol";

interface ITokenshieldSafe7579 {
    /**
     * @dev checks if a Module is installed in account
     */
    function isModuleInstalled(
        uint256 moduleType,
        address module,
        bytes calldata additionalContext
    )
        external
        view
        returns (bool);

    function executeFromExecutor(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        returns (bytes[] memory returnDatas);
}
