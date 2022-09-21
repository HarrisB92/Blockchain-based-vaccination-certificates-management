from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from  wtforms import StringField, SelectField, IntegerField, DateTimeField, validators
from wtforms import DateTimeLocalField
from wtforms.validators import InputRequired , Length, AnyOf
from hexbytes import HexBytes
import hashlib
import schedule
import time
from web3.auto import w3
from deploy_contract import contract_object, web3, admin_account
import re
from eth_account import Account
import secrets
from web3 import Web3, HTTPProvider
from datetime import datetime
import math
import calendar
from eth_account.messages import encode_defunct, _hash_eip191_message
import qrcode

class RegisterHealthCenter(FlaskForm):
    ethaddress = StringField("Ethereum Address", [InputRequired()])
    details = StringField("Healthcare center name", [InputRequired()])

class setTime(FlaskForm):
    time = IntegerField("Set the suspention time", [InputRequired()])

class HealthCenterList(FlaskForm):
    ethaddress = SelectField('Approved Health Centers', choices = [])

class passphrase(FlaskForm):
    newpass = StringField('Set a passphrase', [InputRequired()])
    
class emitCert(FlaskForm):
    address_from = StringField("From Ethereum Address", [InputRequired()]) #, AnyOf(values=[], message='Passwords must match')])
    address_to = StringField("To Ethereum Address ",[InputRequired()]) #, AnyOf(values=[], message='Passwords must match')])
    cert_hash = StringField("Certificate Hash", [InputRequired(), Length(min= 64, max=64, message='SHA256 should be used')])
    personel_signature = StringField("Signature of operator",[InputRequired()] )
    passphrase = StringField("Your passphrase", [InputRequired()])#, AnyOf(values=[111], message='Passwords must match')])

class suspendCert(FlaskForm):
    user_address_from = StringField("From: User Address", [InputRequired()])
    healthcare_address_to = StringField("To Health center Address ",[InputRequired()])
    cert_hash = StringField("Certificate Hash", [InputRequired(), Length(min= 64, max=64, message='SHA256 should be used')])
    user_signature = StringField("User's signature (hexadecimal)", [InputRequired()])
    personel_signature = StringField("Signature of operator", [InputRequired()])
    passphrase = StringField("Your passphrase", [InputRequired()])
    hash_of_signed_message = StringField('The hash of the signed by the user message', [InputRequired()])

class user_details(FlaskForm):
    user_name = StringField("Name", [InputRequired()])
    eth_address = StringField("Ethereum address", [InputRequired()])
    vaccine_type = StringField("Vaccine", [InputRequired()])
    date = StringField("Date of vaccination", [InputRequired()])
    health_center = StringField("Health center", [InputRequired()])
    operator = StringField("Name of operator", [InputRequired()])
    cert_id = StringField("Unique Certifecate ID", [InputRequired()])

class validate(FlaskForm):
    hash_to_validate = StringField('Hash to be validated', [InputRequired()])

class revokeCert(FlaskForm):
    revocation_date = DateTimeLocalField("Revoke certificates befole", format='%Y-%m-%d %H:%M:%S')

class sign_message(FlaskForm):
    user_address = StringField('Your address is', [InputRequired()])
    user_passphrase = StringField('Your passphrase', [InputRequired()])


t1 = False
#create a new accounts, generate new private-public keys
priv = secrets.token_hex(32)
private_key = "0x" + priv
print("SAVE BUT DO NOT SHARE THIS:", private_key)
account = Account.from_key(private_key)
# to see the private key
priv_kay = account.privateKey
# acc = web3.geth.personal.newAccount('kalamaris')


# FUNCTIONS

# get timestamps for sorting
def block_num(event):
    tx_hash = event.transactionHash
    block_number = web3.eth.getTransaction(tx_hash).blockNumber
    block_time = web3.eth.get_block(block_number).timestamp
    return block_time

# a function to generate new ethereum accounts
def generate_address(passphrase):
    newAccount = web3.geth.personal.newAccount(passphrase)
    return newAccount

def check_if_cert_exists(hash):
    unique = False
    # set filters
    issue_cert_event_filter = contract_object.events.certExchange.createFilter(fromBlock=0, argument_filters={'cert_hash': hash})
    suspend_cert_event_filter = contract_object.events.suspend.createFilter(fromBlock=0, argument_filters={'cert_hash': hash})
    revoke_cert_event_filter = contract_object.events.revoke.createFilter(fromBlock=0, argument_filters={'cert_hash': hash})
    # get events
    eventList_issue = issue_cert_event_filter.get_all_entries()
    eventList_suspend = suspend_cert_event_filter.get_all_entries()
    eventList_revoke = revoke_cert_event_filter.get_all_entries()
    # concatenate event lists
    eventList_total = eventList_issue + eventList_suspend + eventList_revoke
    if len(eventList_total) == 0:
        unique = True
    return  unique

def check_cert_ownership(hash, address):
    ownership_correct = False
    # set filters
    issue_cert_event_filter = contract_object.events.certExchange.createFilter(fromBlock=0, argument_filters={'cert_hash': hash})
    suspend_cert_event_filter = contract_object.events.suspend.createFilter(fromBlock=0, argument_filters={'cert_hash': hash})
    revoke_cert_event_filter = contract_object.events.revoke.createFilter(fromBlock=0, argument_filters={'cert_hash': hash})
    # get events
    eventList_issue = issue_cert_event_filter.get_all_entries()
    eventList_suspend = suspend_cert_event_filter.get_all_entries()
    eventList_revoke = revoke_cert_event_filter.get_all_entries()
    # concatenate event lists
    eventList_total = eventList_issue + eventList_suspend + eventList_revoke
    # sort by event timestamp
    eventList_total.sort(key=block_num)
    owner = eventList_total[-1].args.to
    if owner == address:
        ownership_correct = True
    return ownership_correct

def evaluate_sig_timestamp(_hash):
    sig_is_valid = False
    current_block = web3.eth.get_block('latest')
    current_block_number = current_block.number
    for i in range(10):
        block = web3.eth.get_block(current_block_number-i)
        timestamp_int = block.timestamp
        timestamp = str(timestamp_int)
        timestamp = timestamp.encode()
        hex_timestamp = web3.toHex(timestamp)
        timestamp_encoded = encode_defunct(hexstr = hex_timestamp)
        timestamp_hash = _hash_eip191_message(timestamp_encoded)
        hex_timestamp_hash = web3.toHex(timestamp_hash)
        print(hex_timestamp_hash)
        if hex_timestamp_hash == _hash :
            sig_is_valid = True
            break
    return sig_is_valid

n = -1 # this is the count to fil the choices[]
r = True # initially True, when classes are instatiated it becomes False
#-----------------------------------------
app = Flask(__name__)

# config key for CSRF (CSRF token)
csrf_token = secrets.token_hex(32)
app.config['SECRET_KEY'] = csrf_token

@app.route("/", methods=["GET"])
def index():
    global r
    def instantiateClasses():
        global form, form1, form2, form3, form4, form5, form6, form7, form8, form9
        form = RegisterHealthCenter()
        form1 = HealthCenterList()
        form2 = passphrase()
        form3 = emitCert()
        form4 = validate()
        form5 = suspendCert()
        form6 = setTime()
        form7 = user_details()
        form8 = revokeCert()
        form9 = sign_message()
        return  form, form1, form2, form3, form4, form5, form6, form7, form8, form9
    # check if r==True to instantiate the classes only once
    if r :
        instantiateClasses()
        r = False
    return render_template(
        'home.html',
        contractaddress = contract_object.address,
        registerform1 = form1,
        registerform2 = form2,
        registerform3 = form3
        )

@app.route("/Admin", methods = ["GET", "POST"])
def admin():
    global n, new_time

    # Give permission to a Health center
    if request.method == 'POST' and ('ethaddress' in request.form) and ('details' in request.form):
        healthcenter_address = request.form['ethaddress']
        healthcenter_details = request.form['details']
        healthcenter_address = healthcenter_address.strip()
        print(web3.fromWei(web3.eth.getBalance(admin_account), 'ether'), 'Health center registration')
        tx_hash = contract_object.functions.setHealthCenter(healthcenter_address).transact()
        print(web3.fromWei(web3.eth.getBalance(admin_account), 'ether'), 'after Health center registration')
        web3.eth.send_transaction({
            'to': healthcenter_address,
            'from': admin_account,
            'value': 1000000000000000000 # 1 ether
            })
        n = n + 1
        form1.ethaddress.choices += [(n, healthcenter_address)]
        return render_template(
            'Admin.html',
            registerform = form,
            registerform6=form6,
            registerform8=form8,
            adminaccount = admin_account,
            healthcareaccount = healthcenter_address,
            t1 = True
            )

    # Set a suspension period
    if request.method == 'POST' and 'time' in request.form:
        new_time = int(request.form['time'])
        print(web3.fromWei(web3.eth.getBalance(admin_account), 'ether'), 'before setting time')
        tx_setTime_hash = contract_object.functions.setTime(new_time).transact()
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_setTime_hash)
        print(tx_receipt.cumulativeGasUsed)
        print(web3.fromWei(web3.eth.getBalance(admin_account), 'ether'), 'after setting time')
        return render_template(
            'Admin.html',
            contractaddress=contract_object.address,
            registerform=form,
            registerform6=form6,
            registerform8=form8,
            adminaccount=admin_account,
            suspention_time = True
        )
    # Rovoke certificates
    if request.method == 'POST' and 'revocation_date' in request.form:
        try:
            revocation_date = request.form['revocation_date'].strip()
            print(revocation_date)
            unix_time = calendar.timegm(time.strptime(revocation_date, '%Y-%m-%dT%H:%M'))
            unix_time = unix_time - 10800

            # filter events
            issue_cert_event_filter = contract_object.events.certExchange.createFilter(fromBlock=0)
            # get event results
            eventList_issue = issue_cert_event_filter.get_all_entries()



            # iterate through event results and delete the ones issued before the revocation date
            count = 0
            eventList_issue.sort(key = block_num)
            new_list = []
            hash_list = []
            if len(eventList_issue) > 0:
                for i in eventList_issue:
                    _hash = i.args.cert_hash
                    if _hash not in hash_list:
                        hash_list.append(_hash)
                        new_list.append(i)

                events_num = range(len(new_list))
                for i in events_num:
                    _tx_hash = new_list[i].transactionHash
                    _block_num = web3.eth.getTransaction(_tx_hash).blockNumber
                    _time = web3.eth.get_block(_block_num).timestamp
                    if _time < unix_time:
                        user_address_from = new_list[i].args.to
                        _hash = new_list[i].args.cert_hash
                        tx = contract_object.functions.revokeCert(user_address_from, _hash).transact()
                        count += 1


            return render_template(
                'Admin.html',
                contractaddress=contract_object.address,
                registerform=form,
                adminaccount=admin_account,
                registerform6=form6,
                registerform8=form8,
                date = datetime.fromtimestamp(unix_time),
                count = count,
                t9 = True
            )
        except:
            return render_template(
                'Admin.html',
                contractaddress=contract_object.address,
                registerform=form,
                adminaccount=admin_account,
                registerform6=form6,
                registerform8=form8,
                t10 = True
            )

    else:
        return render_template(
            'Admin.html',
            contractaddress = contract_object.address,
            registerform = form,
            adminaccount = admin_account,
            registerform6 = form6,
            registerform8 = form8
            )


@app.route("/Health-center", methods = ["GET", "POST"])
def Healthcare():
    global healthcare_address_to, user_address_from, cert_hash, personel_signature
    global unsuspend
    # Create a new Healthcare-center account
    if request.method == "POST" and "newpass" in request.form:
        phrase = request.form['newpass']
        newAccount = generate_address(phrase)

        return render_template(
            'Health-center.html',
            contractaddress=contract_object.address,
            newaccount = newAccount,
            registerform1= form1,
            registerform2 = form2,
            registerform3 = form3,
            registerform5= form5,
            t4 = True
            )
    # Issue a certificate
    if request.method == "POST"  and (('address_from' in request.form) and ( 'address_to' in request.form) and ('cert_hash' in request.form) and ('personel_signature' in request.form)):
        address_from = request.form['address_from'].strip()
        address_to = request.form['address_to'].strip()
        cert_hash = request.form['cert_hash'].strip().encode()
        personel_signature = request.form['personel_signature'].strip().encode()
        passphrase = request.form['passphrase'].strip()
        print(web3.eth.getBalance(address_from))
        isappreved = contract_object.functions.approvedHealthCenters(address_from).call()
        print(isappreved)
        if not isappreved:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                notapproved = True
                )

        try:
            web3.geth.personal.unlock_account(address_from, passphrase)
        except:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                t2 = True
                )

        # check if the hash already exists in the blockchain
        is_unique = check_if_cert_exists(cert_hash)
        print('it is unique')
        if is_unique == True:

            # call issue function
            print(web3.fromWei(web3.eth.getBalance(address_from), 'ether'), 'before issuance')
            issue_cert = contract_object.functions.issueCert(address_to,cert_hash,personel_signature).transact({'from': address_from})
            print(web3.fromWei(web3.eth.getBalance(address_from), 'ether'),'after issuance')

            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1= form1,
                registerform2 = form2,
                registerform3 = form3,
                registerform5=form5,
                t3 = True
                )
        else:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                not_unique = True
            )

    # suspend certificate
    if request.method == "POST" and (('user_address_from' in request.form) and ('healthcare_address_to' in request.form) and ('cert_hash' in request.form) and ('user_signature' in request.form) and ('personel_signature' in request.form) and ('passphrase' in request.form)):
        user_address_from = request.form['user_address_from'].strip()
        healthcare_address_to = request.form['healthcare_address_to'].strip()
        cert_hash = request.form['cert_hash'].strip().encode()
        user_signature = request.form['user_signature'].strip()
        personel_signature = request.form['personel_signature'].strip().encode()
        passphrase = request.form['passphrase'].strip()
        hex_message_hash = request.form['hash_of_signed_message'].strip()

        # check if serspension time is set
        try:
            print(new_time)
        except:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                suspension_time_not_set=True
            )

        # check if the sender is an authorized Health center
        isappreved = contract_object.functions.approvedHealthCenters(healthcare_address_to).call()
        print(isappreved)
        if not isappreved:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                notapproved2=True
            )

        # check if the health-center's passphrase is correct
        try:
            web3.geth.personal.unlock_account(healthcare_address_to, passphrase)
        except:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                t5 = True,
                )

        # check if the cert already exists. If not there is no meaning in suspending it
        is_unique = check_if_cert_exists(cert_hash)
        if is_unique:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                is_unique = is_unique,
            )

        #check if the signature is a recent one. For a signature to be valid, it should have been created at most 2 minutes ago.
        is_recent = evaluate_sig_timestamp(hex_message_hash)
        if not is_recent:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                old_sig = True,
            )

        # check if the current owner of the certificate is the 'from' address. If this is false suspension cannot continue
        ownership = check_cert_ownership(cert_hash, user_address_from)
        if ownership:

            print(user_signature)
            print(hex_message_hash)
            sig = Web3.toBytes(hexstr=user_signature)

            v, hex_r, hex_s = Web3.toInt(sig[-1]), Web3.toHex(sig[:32]), Web3.toHex(sig[32:64])
            ec_recover_args = (hex_message_hash, v+27, hex_r, hex_s)
            print(ec_recover_args)
            recover_address = contract_object.functions.ecr(hex_message_hash, v+27, hex_r, hex_s).call()

            if recover_address == user_address_from:

                # call suspend function
                print(web3.fromWei(web3.eth.getBalance(healthcare_address_to), 'ether'),'before suspention')
                suspend_cert = contract_object.functions.suspendCert(user_address_from, cert_hash, user_signature, personel_signature,).transact({'from': healthcare_address_to})
                print(web3.fromWei(web3.eth.getBalance(healthcare_address_to), 'ether'),'after suspention')

                time_of_issuance = time.time()
                time_of_issuance = math.floor(time_of_issuance)

                def unsuspend():
                    print(web3.fromWei(web3.eth.getBalance(healthcare_address_to), 'ether'), 'before issuance')
                    unSuspend_cert = contract_object.functions.unSuspendCert(user_address_from, cert_hash, personel_signature, time_of_issuance ).transact({'from': healthcare_address_to})
                    print(web3.fromWei(web3.eth.getBalance(healthcare_address_to), 'ether'), 'after issuance')
                    return schedule.CancelJob

                schedule.every(30).seconds.do(unsuspend)
                while True:
                    schedule.run_pending()
                    time.sleep(1)

                return render_template(
                    'Health-center.html',
                    contractaddress=contract_object.address,
                    registerform1=form1,
                    registerform2=form2,
                    registerform3=form3,
                    registerform5=form5,
                    t6 = True
                    )
            else:
                return render_template(
                    'Health-center.html',
                    contractaddress=contract_object.address,
                    registerform1=form1,
                    registerform2=form2,
                    registerform3=form3,
                    registerform5=form5,
                    invalid_signature=True
                )
        else:
            return render_template(
                'Health-center.html',
                contractaddress=contract_object.address,
                registerform1=form1,
                registerform2=form2,
                registerform3=form3,
                registerform5=form5,
                false_awnership = True
            )

    else:
        return render_template(
            'Health-center.html',
            contractaddress = contract_object.address,
            registerform1 = form1,
            registerform2 = form2,
            registerform3= form3,
            registerform5 = form5
            )


@app.route("/User", methods = ["GET", "POST"])
def user():
    if request.method == 'POST':
        user_address = request.form['user_address'].strip()
        user_passphrase = request.form['user_passphrase'].strip()

        try:
            web3.geth.personal.unlock_account(user_address, user_passphrase)
        except:
            return render_template(
                'User.html',
                contractaddress=contract_object.address,
                registerform9=form9,
                t11 = True
            )

        # the user signes the timestamp of the latest block
        message = web3.eth.get_block('latest').timestamp
        message = str(message)
        message = message.encode()
        hex_message = web3.toHex(message)
        signed_message = web3.eth.sign(user_address, hexstr=hex_message)
        hex_signature = web3.toHex(signed_message)
        # - encode the message
        message_encoded = encode_defunct(hexstr=hex_message)
        # - hash the message explicitly
        message_hash = _hash_eip191_message(message_encoded)
        hex_message_hash = Web3.toHex(message_hash)

        sig = Web3.toBytes(hexstr=hex_signature)

        return render_template(
            'User.html',
            contractaddress=contract_object.address,
            registerform9=form9,
            sig_ok=True,
            signature = hex_signature,
            hex_message_hash = hex_message_hash

        )

    else:
        return render_template(
            'User.html',
            contractaddress = contract_object.address,
            registerform9 = form9
        )

@app.route("/Validator", methods = ["GET", "POST"])
def validator():
    global  details, block_num
    # calculate certificate hash
    if request.method == 'POST' and 'vaccine_type' in request.form:
        user_name = request.form['user_name'].strip()
        eth_address = request.form['eth_address'].strip()
        vaccine_type = request.form['vaccine_type'].strip()
        date = request.form['date'].strip()
        health_center = request.form['health_center'].strip()
        operator = request.form['operator'].strip()
        cert_id = request.form['cert_id'].strip()

        details = f'{user_name}\n' \
                  f'{eth_address}\n' \
                  f'{vaccine_type}\n' \
                  f'{date}\n' \
                  f'{health_center}\n' \
                  f'{operator}\n' \
                  f'{cert_id}'

        # calculate hash
        cert_hash = hashlib.sha256(details.encode()).hexdigest()
        # generate QR-code
        qr = qrcode.make(details)
        qr.save('testQR.png')

        return render_template(
            'Validator.html',
            contractaddress=contract_object.address,
            registerform4=form4,
            registerform7=form7,
            calc_hash = True,
            cert_hash = cert_hash
        )

    # validate certificate
    if request.method == 'POST':
        hash_to_validate = request.form['hash_to_validate'].strip().encode()
        # Event Filter: looks for a specific events with specific args
        issue_cert_event_filter = contract_object.events.certExchange.createFilter(fromBlock=0, argument_filters={'cert_hash': hash_to_validate})
        suspend_cert_event_filter = contract_object.events.suspend.createFilter(fromBlock=0, argument_filters={'cert_hash': hash_to_validate})
        revoke_cert_event_filter = contract_object.events.revoke.createFilter(fromBlock=0, argument_filters={'cert_hash': hash_to_validate})
        
        try:
            eventList_issue = issue_cert_event_filter.get_all_entries()
            eventList_suspend = suspend_cert_event_filter.get_all_entries()
            eventList_revoke = revoke_cert_event_filter.get_all_entries()

            print(eventList_issue)
            print(eventList_suspend)
            print(eventList_revoke)
            eventList_total = eventList_issue + eventList_suspend + eventList_revoke


            # sort event list according to the timespamp of the block that were included
            eventList_total.sort(key = block_num)
            events_num = range(len(eventList_total))
            time_list = []
            address_from_list = []
            address_to_list = []
            for i in events_num:
                tx_hash = eventList_total[i].transactionHash
                block_number = web3.eth.getTransaction(tx_hash).blockNumber
                time = web3.eth.get_block(block_number).timestamp
                time = datetime.fromtimestamp(time)
                time_list.append(time)
                from_addr = eventList_total[i].args.from_addr
                address_from_list.append(from_addr)
                to_addr = eventList_total[i].args.to
                address_to_list.append(to_addr)
            # ------------- use regular expressions to find the name of the file ------------------------------------------
            file_patern = re.compile(r'(0x.+)\n')
            file = file_patern.search((details))
            file = file.group(1)

            if eventList_total[-1].args.to == file:
                return render_template(
                    'Validator.html',
                    contractaddress=contract_object.address,
                    registerform4=form4,
                    registerform7=form7,
                    time_list=time_list,
                    address_from_list=address_from_list,
                    address_to_list=address_to_list,
                    events_num=events_num,
                    t3=True,
                    valid = True
                )

            else:
                return render_template(
                    'Validator.html',
                    contractaddress=contract_object.address,
                    registerform4 = form4,
                    registerform7=form7,
                    time_list = time_list,
                    address_from_list = address_from_list,
                    address_to_list = address_to_list,
                    events_num = events_num,
                    t3 = True,
                    invalid = True
            )
        except:
            return render_template(
                'Validator.html',
                contractaddress=contract_object.address,
                registerform4=form4,
                registerform7=form7,
                hashNotExists = True
            )
    else:
        return render_template(
            'Validator.html',
            contractaddress=contract_object.address,
            registerform4 = form4,
            registerform7 = form7
        )

print(web3.eth.accounts)
print(admin_account)
print(web3.eth.getBalance(web3.eth.accounts[0]), 'charged address 0')
print(web3.eth.accounts[-1], 'admins address')
print(web3.fromWei(web3.eth.getBalance(web3.eth.accounts[-1]),'ether'), 'admin\'s balance')
cost = 10000000000000000000 - web3.eth.getBalance(web3.eth.accounts[-1])
print('the contract costs:',web3.fromWei(cost,'ether'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5555,debug=True, use_reloader=False)