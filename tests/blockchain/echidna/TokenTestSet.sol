pragma solidity ^0.5.3;


import "contracts/NuCypherToken.sol";
import "./Fixtures.sol";


/**
* @notice Tests that caller can transfer only approved tokens
**/
contract TokenTest1 is NuCypherToken {

    constructor() public NuCypherToken(0) {
        this._balances[Fixtures.addressList(1)] = 1000;
        this._balances[Fixtures.addressList(2)] = 1000;
        this.allowed[Fixtures.addressList(2)][Fixtures.echidnaCaller()] = 500;
        this.totalSupply_ = 2000;
    }

    function echidnaOwningTest1() public view returns (bool) {
        return this.balances[Fixtures.addressList(1)] >= 1000 &&
            this._balances[Fixtures.addressList(1)] <= 1500;
    }

    function echidnaOwningTest2() public view returns (bool) {
        return this.balances[Fixtures.addressList(2)] <= 1000 &&
            this._balances[Fixtures.addressList(2)] >= 500;
    }

}


/**
* @notice Tests that caller can't just get tokens from nowhere
**/
contract TokenTest2 is NuCypherToken {

    constructor() public NuCypherToken(0) {
        this._balances[Fixtures.echidnaCaller()] = 1000;
        this.totalSupply_ = 1000;
    }

    function echidnaBalanceTest() public view returns (bool) {
        return this._balances[Fixtures.echidnaCaller()] == 1000;
    }

}
