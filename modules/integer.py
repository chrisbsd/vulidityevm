from z3 import *
import execZ3 as solver
from ops import *
import copy
import logging
from repis import Fund


def integerExecute(stateenv):
    analayseFunde = []

    for key in stateenv.nodes:
        node = stateenv.nodes[key]
        for state in node.states:
            analayseFunde += checkUnderflow(state, node)
            analayseFunde += checkOverflow(state, node)

    return analayseFunde


def checkOverflow(state, node):
    aktFunde = []
    instruction = state.get_current_instruction()
    if instruction['opcode'] not in ("ADD", "MUL"):
        return aktFunde
    elif instruction['opcode'] == "ADD":
        ovInstruction = 1
    else:
        ovInstruction = 2
    op0, op1 = state.mstate.stack[-1], state.mstate.stack[-2]

    # Zu einem Bitvektorwert umwandeln mit BitVecVal von z3. Beschreibung der Funktion BitVecVal() aus z3.py:
    # Return a bit-vector value with the given number of bits. If `ctx=None`, then the global context is used.
    if type(op0) is int:
        op0 = BitVecVal(op0, 256)
    if type(op1) is int:
        op1 = BitVecVal(op1, 256)
    if ovInstruction == 1:
        aktuelleOperation = op0 + op1
    elif ovInstruction == 2:
        aktuelleOperation = op1 * op0
    else:
        print("Etwas ist katastrophal schiefgelaufen!")
        return aktFunde

    constraint = Or(ULT(aktuelleOperation, op0), ULT(aktuelleOperation, op1))
    constraints = copy.deepcopy(node.constraints)
    for const in [constraint]:
        constraints.append(copy.deepcopy(const))
    try:
        model = solver.model(constraints)
    except:
        model = None

    if model is None:
        return aktFunde

    tmpDescription = []
    tmpDescription.append("Ein Integer Ueberlauf ist moeglich! Es wurden Additionen und Multiplikationen geprueft, "
                          "ob diese das maximale einer Integer Datenstruktur uebersteigen.")
    iDescription = "".join(tmpDescription)
    aktFund = setIssue(instruction['address'], "Integer Overflow", "Logische Fehler", iDescription, model)
    aktFunde.append(aktFund)

    return aktFunde

def setIssue(instructionAdress, issueType, Schwachstellenkat, issueDescription, modelN):
    issue = Fund(instructionAdress, issueType, Schwachstellenkat)
    issue.description = issueDescription
    issue.debug = solver.ppModel(modelN)
    return issue

def checkUnderflow(state, node):
    aktFunde = []
    instruction = state.get_current_instruction()

    if instruction['opcode'] == "SUB":

        op0, op1 = state.mstate.stack[-1], state.mstate.stack[-2]
        constraints = copy.deepcopy(node.constraints)

        if type(op0) == int and type(op1) == int:
            return aktFunde

        constraints.append(UGT(op1, op0))

        try:
            model = solver.model(constraints)
            tmpDescription = []
            tmpDescription.append("Ein Integer Unterlauf ist moeglich! Es wurden Subtraktionen geprueft, ob deren "
                                  "Ergebnis einen Wert unter Null annehmen kann.")
            iDescription = "".join(tmpDescription)
            aktFund = setIssue(instruction['address'], "Integer Underflow", "Logische Fehler", iDescription, model)
            aktFunde.append(aktFund)
        except:
            logging.debug("Fuer Integer Unterlauf wurde kein Model gefunden!")
    return aktFunde
