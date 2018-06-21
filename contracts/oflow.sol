contract Overflow {

  function overflow() returns (uint256 _ovrflw){
    uint256 max = 2**256 - 1;
    return max + 1;
  }
}