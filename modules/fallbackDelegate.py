import re
from mythril.analysis.ops import get_variable
from repis import Fund

def fallbackExecute(statespace):
    analayseFunde = []
    for call in statespace.calls:
        if call.type is not "DELEGATECALL" or call.node.function_name is not "fallback":
            continue
        state = call.state
        address = state.get_current_instruction()['address']
        meminstart = get_variable(state.mstate.stack[-3])
        if not re.search(r'calldata.*_0', str(state.mstate.memory[meminstart.val])):
            return []
        tmpDescription = "In der Fallback Methode dieses SmartContract befindet sich ein DELEGATECALL. Damit kann eine" \
                         " dritte Person Code im Kontext dieses SmartContracts ausfuehren und sogar auf den Speicher " \
                         "zugreifen!"
        aktFund = setIssue(address, "DELEGATECALL in Fallback", "Blockchainaspekte", tmpDescription)
        analayseFunde += [aktFund]
        
    return analayseFunde


def setIssue(instructionAdress, issueType, Schwachstellenkat, issueDescription):
    issue = Fund(instructionAdress, issueType, Schwachstellenkat)
    issue.description = issueDescription
    return issue