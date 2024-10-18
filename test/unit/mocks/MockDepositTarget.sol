// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockDepositTarget {
    mapping(address account => uint256 depositedAmount) public depositedAmount;

    function deposit(address tokenToDeposit, address account, uint256 amountToDeposit) external {
        IERC20(tokenToDeposit).transferFrom(account, address(this), amountToDeposit);
        depositedAmount[account] += amountToDeposit;
    }
}
