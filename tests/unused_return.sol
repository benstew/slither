pragma solidity ^0.4.24;

contract Target{
    function f() returns(uint);
}

contract User{

    function test(Target t){
        t.f();
    }
}