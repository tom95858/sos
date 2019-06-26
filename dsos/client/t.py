#!/usr/bin/env python
import os
import string
from re import *
from collections import OrderedDict
from random import *
from subprocess import *

dsos_cmd = "/opt/rob/SOS/bin/dsos_cmd"

class Test:
    allchar = string.ascii_letters + string.digits

    def __init__(self, _name, _schema):
        self.name     = _name
        self.schema   = _schema
        self.contnm   = "/tmp/cont-%%.sos"
        self.num_recs = 10
        self.template = ",".join(n+":"+t for n,t in self.schema.items())

    def cont(self, _contnm):
        self.contnm = _contnm

    def numRecs(self, _num_recs):
        self.num_recs = _num_recs

    def doTest(self):
        print "testing schema {}: {}".format(self.name,self.template)
        self.doSchema()
        self.doCsv()
        self.doImport()
        self.doIter()
        self.doFind()

    def doCont(self):
        print [dsos_cmd, "cont", "--delete", self.contnm]
        check_call([dsos_cmd, "cont", "--delete", self.contnm],
                   stderr=STDOUT)
        print [dsos_cmd, "cont", "--create", self.contnm, "755", "ROOT"]
        check_call([dsos_cmd, "cont", "--create", self.contnm, "755", "ROOT"],
                   stderr=STDOUT)

    def doSchema(self):
        check_call([dsos_cmd, "schema", "--cont", self.contnm, "--schema", self.name, "--add", "--template", self.template],
                   stderr=STDOUT)
        out = check_output([dsos_cmd, "schema", "--cont", self.contnm, "--schema", self.name, "--dump"],
                           stderr=STDOUT).strip()
        if out != self.template:
            raise Exception("dumped schema incorrect: expected ", self.template, " got ", out)

    def doCsv(self):
        print "creating csv file with", self.num_recs, "records"
        vals = OrderedDict()
        f = open("csv", "w")
        for i in range(0, self.num_recs):
            for n,t in self.schema.items():
                m = match("(\w+)\[(\d+)\]", t)
                if m:
                    base = m.group(1)
                    sz   = int(m.group(2))
                    if (base == "char"):
                        vals[n] = "".join(choice(self.allchar) for x in range(randint(1, sz-1)))
                if (t == "int16") or (t == "int32") or (t == "int64") or \
                   (t == "uint16") or (t == "uint32") or (t == "uint64"):
                    if n in vals:
                        vals[n] = str(int(vals[n]) + 1)
                    else:
                        vals[n] = str(randint(0,1000000))
            f.write(",".join(vals.values()) + "\n")
        del vals
        f.close()

    def doImport(self):
        print "importing csv"
        print [dsos_cmd, "import", "--cont", self.contnm, "--schema", self.name, "csv"]
        check_call([dsos_cmd, "import", "--cont", self.contnm, "--schema", self.name, "csv"],
                   stderr=STDOUT)

    def doIter(self):
        i = 1
        for n,t in self.schema.items():
            if n[0] == '*':
                n = n.replace('*','')
                print "testing iteration on attribute", n
                f = open("out", "w");
                print [dsos_cmd, "iter", "--cont", self.contnm, "--schema", self.name, "--attr", n]
                check_call([dsos_cmd, "iter", "--cont", self.contnm, "--schema", self.name, "--attr", n],
                           stdout=f)
                f.close()
                f = open("csv-sorted", "w");
                check_call(["sort", "-n", "-t,", "--key="+str(i)+","+str(i), "csv"], stdout=f)
                f.close()
                check_call(["diff", "csv-sorted", "out"], stderr=STDOUT)
                i += 1

    def doFind(self):
        f = open("csv", "r");
        recs = f.readlines()
        f.close()
        i = 0
        for n,t in self.schema.items():
            if n[0] != '*':
                continue
            n = n.replace('*','')
            print "testing object finds for attribute", n
            for rec in recs:
                rec = rec.strip()
                val = rec.split(",")[i]
                print [dsos_cmd, "find", "--cont", self.contnm, "--schema", self.name, n+"="+val ]
                out = check_output([dsos_cmd, "find", "--cont", self.contnm, "--schema", self.name, n+"="+val ],
                                   stderr=STDOUT).strip()
                if out != rec:
                    raise Exception("could not find object: attr ", n, " val ", val, "\nwant: ", rec, "\ngot: ", out)
            i += 1
        del recs

if __name__ == "__main__":
    try:
        if "DSOS_CONFIG" not in os.environ:
            raise Exception("must set $DSOS_CONFIG")

        for sz in range(16,9000):
            t = Test("test{}".format(sz), OrderedDict([ ("*seq","uint64"),
                                                        ("*int1","uint64"),
                                                        ("*int2","uint64"),
                                                        ("*int3","uint64"),
                                                        ("data","char[{}]".format(sz)) ]))
            t.numRecs(100)
            t.cont("/tmp/cont-py-%%.sos")
            t.doCont()
            t.doSchema()
            t.doCsv()
            t.doImport()
            while True:
                t.doIter()
#            t.doTest()
            del t

    except CalledProcessError as e:
        print "Command " + " ".join(e.cmd) + " failed with status " + str(e.returncode) + ":"
        print e.output
    except Exception as inst:
        print inst.args
