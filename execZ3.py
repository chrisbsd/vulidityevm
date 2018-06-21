from z3 import Solver, simplify, sat


def model(constraints):
    s = Solver()
    s.set("timeout", 2000)

    for constraint in constraints:
        s.add(constraint)

    if s.check() == sat:
        return s.model()


def ppModel(model):
    ret = ""

    for elem in model.decls():
        try:
            condition = "0x%x" % model[elem].as_long()
        except:
            condition = str(simplify(model[elem]))
        ret += ("%s: %s\n" % (elem.name(), condition))

    return ret