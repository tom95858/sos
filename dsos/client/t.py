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
        self.num_recs = 10
        self.template = ",".join(n+":"+t for n,t in self.schema.items())
        self.doTest()

    def doTest(self):
        print "testing schema {}: {}".format(self.name,self.template)
        self.doCont()
        self.doSchema()
        self.doImport()
        self.doIter()
        self.doFind()

    def doCont(self):
        check_call([dsos_cmd, "cont", "--delete", "/tmp/cont.sos"],
                   stderr=STDOUT)
        check_call([dsos_cmd, "cont", "--create", "/tmp/cont.sos", "755", "ROOT"],
                   stderr=STDOUT)

    def doSchema(self):
        check_call([dsos_cmd, "schema", "--cont", "/tmp/cont.sos", "--schema", self.name, "--add", "--template", self.template],
                   stderr=STDOUT)
        out = check_output([dsos_cmd, "schema", "--cont", "/tmp/cont.sos", "--schema", self.name, "--dump"],
                           stderr=STDOUT).strip()
        if out != self.template:
            raise Exception(["dumped schema incorrect: expected", self.template, "got", out])

    def doImport(self):
        print "creating csv file with", self.num_recs, "records"
        vals = {}
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
        print "importing csv"
        print [dsos_cmd, "import", "--cont", "/tmp/cont.sos", "--schema", self.name, "csv"]
        check_call([dsos_cmd, "import", "--cont", "/tmp/cont.sos", "--schema", self.name, "csv"],
                   stderr=STDOUT)

    def doIter(self):
        i = 1
        for n,t in self.schema.items():
            if n[0] == '*':
                n = n.replace('*','')
                print "testing iteration on attribute", n
                f = open("out", "w");
                print [dsos_cmd, "iter", "--cont", "/tmp/cont.sos", "--schema", self.name, "--attr", n]
                check_call([dsos_cmd, "iter", "--cont", "/tmp/cont.sos", "--schema", self.name, "--attr", n],
                           stdout=f, stderr=f)
                f.close()
                f = open("csv-sorted", "w");
                check_call(["sort", "-t,", "--key="+str(i), "csv"], stdout=f, stderr=f)
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
                print [dsos_cmd, "find", "--cont", "/tmp/cont.sos", "--schema", self.name, n+"="+val ]
                out = check_output([dsos_cmd, "find", "--cont", "/tmp/cont.sos", "--schema", self.name, n+"="+val ],
                                   stderr=STDOUT).strip()
                if out != rec:
                    raise Exception(["could not find object: attr", n, "val", val, "\nwant:", rec, "\ngot: ", out])
            i += 1
        del recs

if __name__ == "__main__":
    try:
        if "DSOS_CONFIG" not in os.environ:
            raise Exception("must set $DSOS_CONFIG")

        for sz in range(1024,1500):
            Test("test{}".format(sz), OrderedDict([ ("*seq","uint64"),
                                                    ("*int1","uint64"),
                                                    ("*int2","uint64"),
                                                    ("data","char[{}]".format(sz)) ]))

    except CalledProcessError as e:
        print "Command " + " ".join(e.cmd) + " failed with status " + str(e.returncode) + ":"
        print e.output
    except Exception as inst:
        print " ".join(inst.args[0])
