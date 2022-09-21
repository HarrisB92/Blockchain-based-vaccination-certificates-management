from web3 import Web3, HTTPProvider

from solcx import compile_standard, install_solc
import json

install_solc("0.8.7")

# Connect to the local Ganache blockchain

web3 = Web3(HTTPProvider('http://127.0.0.1:8545'))

with open("./safeCertContract.sol","r") as file:
    safe_certs_file = file.read()
    print(safe_certs_file)

    # Compile our solidity
    compiled_sol = compile_standard(
        {   "language": "Solidity",
             "sources": {"safeCertContract.sol": {"content": safe_certs_file}},
             "settings": {
                 "outputSelection":{
                     "*": {"*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap" ]}
                 }
             },
         },
        solc_version = "0.8.7"
    )


    with open("compiled_code.json", "w") as file:
        json.dump(compiled_sol, file)

    # get bytecode
    bytecode = compiled_sol['contracts']['safeCertContract.sol']['safeCerts']['evm']['bytecode']['object']

    # get abi
    abi = compiled_sol['contracts']['safeCertContract.sol']['safeCerts']['abi']

    print(abi)

    StorageContract = web3.eth.contract(abi=abi, bytecode=bytecode)

    # create a new admin account
    admin_account = web3.geth.personal.new_account('admin') # the passphrase for the admin account is "admin"
    web3.eth.send_transaction({
        'to': admin_account,
        'from': web3.eth.accounts[0],
        'value': 10000000000000000000 # 10 ether
    })
    web3.geth.personal.lock_account(admin_account)
    web3.geth.personal.unlock_account(admin_account,'admin')

    # set pre-funded account 'admin' as sender
    web3.eth.defaultAccount = web3.eth.accounts[-1]

    # Submit the transaction that deploys the contract (from 'admin' account), and get the hash of the transaction
    tx_hash = StorageContract.constructor().transact()

    # Wait for the transaction to be mined, and get the transaction receipt
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)

    # create an object to interact with the smart-contract
    contract_object = web3.eth.contract(address= tx_receipt.contractAddress, abi = abi)
    print('this is the contract address:', contract_object.address)

