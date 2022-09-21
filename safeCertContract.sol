// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;

contract safeCerts{

    address public admin;
    mapping (address => bool) public approvedHealthCenters;

    // time that represents the quarantine period
    uint public time;

    // event for certificate issuance
    event certExchange(address from_addr, address to,bytes cert_hash, bytes personel_signature) ;

    // event for certificate suspension
    event suspend(address from_addr, address to, bytes cert_hash, string user_signature, bytes personel_signature, uint time);

    // event for certificate revokation
    event revoke(address from_addr, address to, bytes cert_hash);

    constructor() {
       admin = msg.sender;
    }

    // Admin functions ------------

    function setHealthCenter(address _HealthCenter) public adminOnly() {
        approvedHealthCenters[_HealthCenter] = true ;

    }

    function setTime( uint _time) public adminOnly() {
        time = _time;
     }

    function revokeCert(address _User, bytes memory _Hash) public adminOnly(){
        emit revoke(_User, msg.sender, _Hash);
    }

    // Healthcare center functions -----------

    function issueCert(address  _User,bytes memory _Hash, bytes memory personel_Signature) public IamHealthCenter() {
        emit certExchange( msg.sender, _User, _Hash, personel_Signature);
    }

    function suspendCert(address _User, bytes memory _Hash , string memory user_Signarure, bytes memory personel_Signature) public IamHealthCenter() {
        emit suspend( _User, msg.sender, _Hash,  user_Signarure, personel_Signature, time);
    }

    function unSuspendCert(address  _User,bytes memory _Hash, bytes memory personel_Signature, uint timeOfSuspension) public IamHealthCenter() {
        if ( timeOfSuspension + time > block.timestamp) {
            emit certExchange( msg.sender, _User, _Hash, personel_Signature);
        }
    }

      function ecr(bytes32 msgHash, uint8 v, bytes32 r, bytes32 s) public pure returns (address sender) {
          return ecrecover(msgHash, v, r, s);
  }

    // Validation on Flask, validators are not required to have addresses. Validation can be done by everyone. Validation utilezes event logs

    // Modifiers

    modifier adminOnly() {
        require (msg.sender == admin,'You are not the Admin');
        _;
    }

    modifier IamHealthCenter() {
        require (approvedHealthCenters[msg.sender] == true , "You are not an approved Healthcare Center");
        _;
    }

}