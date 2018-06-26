from random import randint
import time

class Fund:

    def __init__(self, pc, title, _type, description=""):

        self.title = title
        self.pc = pc
        self.description = description
        self.type = _type
        self.filename = None
        self.code = None
        self.lineno = None

    def addCodeInfo(self, contract):
        if self.pc:
            codeinfo = contract.getSourceInfo(self.pc)
            self.filename = codeinfo.filename
            self.code = codeinfo.code
            self.lineno = codeinfo.lineno

class Bericht:

    def __init__(self):
        self.issues = {}
        pass

    def issueAnfuegen(self, issue):
        self.issues[(str(time.time() + randint(0, 100)) + issue.title)] = issue

    def ausgabe(self):
        snippet = []

        for key, issue in self.issues.items():

            snippet.append("\n\n####################\nSchwachstellentyp: {}\n".format(issue.title))
            snippet.append("Kategorie: {}\n".format(issue.type))
            snippet.append("Beschreibung: {}\n####################\n".format(issue.description))

            if issue.filename and issue.lineno and issue.code:
                snippet.append("In der Datei {} Zeile {} wurde das Muster von {} detektiert bei folgendem Code:\n\n"
                               "{}\n\n".format(issue.filename, str(issue.lineno),issue.title, issue.code))

        return "".join(snippet)