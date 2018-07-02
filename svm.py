import sys
from laser.ethereum import svm
import re
from ethereum.utils import sha3 as sha3n
import binascii
import sha3
from ecdsa import SigningKey, SECP256k1
from modules.fallbackDelegate import fallbackExecute
from modules.integer import integerExecute
from ops import get_variable, SStore, Call, VarType
import copy
from mythril.ether.ethcontract import ETHContract
from mythril.ether.util import get_solc_json
from laser.ethereum import helper
from repis import Bericht

contract = []


class Vulidity:

    def __init__(self):
        print("Vulidity started!")
        self.modules = []

    def who(self):
        print("WRONG parameter!")
        print("Brought to you by chrisbsd from\n\n")
        print("   __                _")
        print(" / __|___  ___  __ _| |___\n" +
              "| (_ / _ \/ _ \/ _` |   -_)\n" +
              " \___\___/\___/\__, |_\___|\n" +
              "               |___/\n\n")

    def checkAddress(self, address):
        if not re.match(r'0x[a-fA-F0-9]{40}', address):
            print("Invalid contract address. Expected format is '0x...'.")
        else:
            print("Address {} is valid!".format(address))

    # Calculates the method selector and calldata for params e.g.
    # calcFuncInfo("eineFunktion(uint256)")

    def calcFuncInfo(self, name):
        # sha3("setA(uint256)").hex()
        hash = sha3n(name).hex()
        print("\n\nThe method selector for {} is {}\nThe calldata is {}\n\n".format(name, hash[0:8], hash))

    # Calculates the Address of a Key-Value Mapping in the EVM with related values e.g.
    # calcAddr(0xAAAA, 0, 0xAAAA)
    # calcAddr(0xBBBB, 1, 0xBBBB)

    def calcAddr(self, key, position, val=0):
        addr = keccak256(bytes32(key) + bytes32(position))
        if val == 0:
            print("The address of the key is {}".format(addr))
        else:
            print("The address of the key is {} with the value "
                  "{}".format(addr, bytes32(val)))

    # Simple Tool to create a valid ETH Address. Returns a dictionary with private/public key and
    # ETH address as keys

    def createEthAdr(self):
        ethMap = {}

        private_key = SigningKey.generate(curve=SECP256k1)
        assert (len(private_key.to_string().hex()) == 64)
        ethMap["private"] = private_key.to_string().hex()
        print("Private key:\n"
              "{}".format(private_key.to_string().hex()))

        public_key = private_key.get_verifying_key().to_string()
        ethMap["public"] = public_key.hex()
        print("Public key:\n{}".format(public_key.hex()))

        eth_address = sha3.keccak_256(public_key).hexdigest()[24:]
        ethMap["address"] = eth_address
        print("Ethereum address:\n0x{}".format(eth_address))

        return ethMap

    def executeModule(self, contractPath,  instructionList, countAdr=1, moduleName=None, addr = ""):
        print("Nearly a googol calculations will take place in order to analyse your SmartContract! Try who() if you are curious!\n\n")
        vulstate = Stateenv(contractPath,  instructionList, countAdr, addr)

        #ret = self.pickModule(svm, module_name)
        if moduleName is "integer":
            ret = integerExecute(vulstate)
        elif moduleName is "fallbackDelegate":
            ret = fallbackExecute(vulstate)
        else:
            return

        if ret:
            contract = solCon(contractPath)
            for elem in ret:
                elem.addCodeInfo(contract)
            rep = Bericht()
            for issue in ret:
                rep.issueAnfuegen(issue)
            print(rep.ausgabe())
        else:
            print("Keine Funde vorhanden!")

def bytes32(num):
    return binascii.unhexlify('%064x' % num)

def keccak256(arr):
    return sha3.keccak_256(arr).hexdigest()


class Stateenv:
    def __init__(self, contractPath, instructionList, countAdr = 1, addr = ""):
        self.accounts = {}
        self.contractcode = []
        self.sstors = {}
        self.calls = []
        self.nodes = {}
        self.edges = []
        contract = solCon(contractPath)
        self.contractcode = contract.disassembly.instruction_list
        if self.contractcode:
            if instructionList:
                for elem in self.contractcode:
                    print(elem)
            if addr:
                address = addr
            else:
                address = "0x000000000000000000000000000000000000000{}".format(countAdr)

            account = svm.Account(address, contract.disassembly)

            self.accounts = {address: account}
            laser = svm.LaserEVM(self.accounts)

            laser.sym_exec(address)
            self.nodes = laser.nodes
            self.edges = laser.edges
            print("Nodes:\n{}".format(self.nodes))
            print("Edges:\n{}".format(self.edges))
            for key in self.nodes:
                stateIndex = 0
                for state in self.nodes[key].states:
                    currInstruction = state.get_current_instruction()
                    currOpcode = currInstruction['opcode']
                    if currOpcode in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
                        stack = state.mstate.stack
                        if currOpcode in ('CALL', 'CALLCODE'):
                            gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                                get_variable(stack[-1]), get_variable(stack[-2]), get_variable(stack[-3]), get_variable(
                                    stack[-4]), get_variable(stack[-5]), get_variable(stack[-6]), get_variable(
                                    stack[-7])
                            if to.type == VarType.CONCRETE and to.val < 5:
                                # ignore prebuilts
                                continue

                            if (meminstart.type == VarType.CONCRETE and meminsz.type == VarType.CONCRETE):
                                self.calls.append(Call(self.nodes[key], state, stateIndex, currOpcode, to, gas, value,
                                                       state.mstate.memory[meminstart.val:meminsz.val * 4]))
                            else:
                                self.calls.append(Call(self.nodes[key], state, stateIndex, currOpcode, to, gas, value))
                        else:
                            gas, to, meminstart, meminsz, memoutstart, memoutsz = \
                                get_variable(stack[-1]), get_variable(stack[-2]), get_variable(stack[-3]), get_variable(
                                    stack[-4]), get_variable(stack[-5]), get_variable(stack[-6])

                            self.calls.append(Call(self.nodes[key], state, stateIndex, currOpcode, to, gas))

                    elif currOpcode == 'SSTORE':
                        stack = copy.deepcopy(state.mstate.stack)
                        address = state.environment.active_account.address

                        index, value = stack.pop(), stack.pop()

                        try:
                            self.sstors[address]
                        except KeyError:
                            self.sstors[address] = {}

                        try:
                            self.sstors[address][str(index)].append(SStore(self.nodes[key], state, stateIndex, value))
                        except KeyError:
                            self.sstors[address][str(index)] = [SStore(self.nodes[key], state, stateIndex, value)]

                    stateIndex += 1




class SourceMapping:

    def __init__(self, solidityFileIdx, offset, length, lineno):
        self.solidityFileIdx = solidityFileIdx
        self.offset = offset
        self.length = length
        self.lineno = lineno


class SolidityFile:

    def __init__(self, filename, data):
        self.filename = filename
        self.data = data


class SourceCodeInfo:

    def __init__(self, filename, lineno, code):
        self.filename = filename
        self.lineno = lineno
        self.code = code


class solCon(ETHContract):

    def __init__(self, inputFile, name=None, solcArgs=None):

        try:
            data = get_solc_json(inputFile, solc_args=solcArgs)
            self.solidityFiles = []
            for filename in data['sourceList']:
                with open(filename, 'r') as file:
                    code = file.read()
                    self.solidityFiles.append(SolidityFile(filename, code))
        except Exception as exi:
            print("Fehler beim Einlesen. Error:\n{}".format(exi))

        try:
            for key, contract in data['contracts'].items():
                filename, name = key.split(":")
                name = name
                code = contract['bin-runtime']
                creation_code = contract['bin']
                srcmap = contract['srcmap-runtime'].split(";")
        except Exception as exi:
            print("Kein legitimer SmartContract wurde gefunden. Error:\n{}".format(exi))

        try:
            self.mappings = []
            for item in srcmap:
                mapping = item.split(":")

                if len(mapping) > 0 and len(mapping[0]) > 0:
                    offset = int(mapping[0])

                if len(mapping) > 1 and len(mapping[1]) > 0:
                    length = int(mapping[1])

                if len(mapping) > 2 and len(mapping[2]) > 0:
                    idx = int(mapping[2])

                lineNumber = self.solidityFiles[idx].data[0:offset].count('\n') + 1
                self.mappings.append(SourceMapping(idx, offset, length, lineNumber))
        except Exception as exci:
            print("Something went wrong in srcmap analysis: {}".format(exci))

        super().__init__(code, creation_code, name=name)

    def getSourceInfo(self, address):

        index = helper.get_instruction_index(self.disassembly.instruction_list, address)

        solidity_file = self.solidityFiles[self.mappings[index].solidityFileIdx]

        filename = solidity_file.filename

        offset = self.mappings[index].offset
        length = self.mappings[index].length

        code = solidity_file.data[offset:offset + length]
        lineno = self.mappings[index].lineno

        return SourceCodeInfo(filename, lineno, code)

if __name__ == "__main__":

    vul = Vulidity()
    if len(sys.argv) > 1:
        if sys.argv[1] == "demo1":
            vul.executeModule("/Users/davebsd/pyeth/contracts/oflow.sol", False, 1, "integer")
        elif sys.argv[1] == "demo2":
            vul.executeModule("/Users/davebsd/vulidity/contracts/deldemo.sol", False, 1, "fallbackDelegate")
        elif sys.argv[1] == "demo3":
            vul.calcFuncInfo("balanceOf(address)")
            vul.executeModule("/Users/davebsd/pyeth/contracts/underflow.sol", True, 1, "integer")
        elif sys.argv[1] == "demo4":
            vul.executeModule("/Users/davebsd/pyeth/contracts/delegatecall.sol", False, 1, "fallbackDelegate")
        else:
            vul.who()
    else:
        vul.who()

