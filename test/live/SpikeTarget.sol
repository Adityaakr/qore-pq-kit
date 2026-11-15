// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title SpikeTarget
/// @notice Throwaway target for spike S2 (`MsgExecuteEVM` with a linked key and
///         a spending rule): one allowlisted function shaped like an auction's
///         `commitBid`, and one that is not allowlisted. Records who called.
contract SpikeTarget {
    event Committed(address indexed from, uint256 x, uint256 value);
    event Other(address indexed from, uint256 x);

    mapping(address => uint256) public commits;

    function commitBid(uint256 x) external payable {
        commits[msg.sender] += 1;
        emit Committed(msg.sender, x, msg.value);
    }

    function other(uint256 x) external {
        emit Other(msg.sender, x);
    }
}
