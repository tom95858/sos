#!/usr/bin/env python
from past.builtins import execfile
from builtins import next
from builtins import range
import unittest
import shutil
import logging
import os
import random
from sosdb import Sos
from sosunittest import SosTestCase

logger = logging.getLogger(__name__)

class ArrayTest(SosTestCase):
    @classmethod
    def setUpClass(cls):
        cls.setUpDb("array_test_cont")
        cls.schema = Sos.Schema()
        cls.schema.from_template('array_test', [
            { "name" : "byte_array", "type" : "byte_array", "size" : 32 },
            { "name" : "char_array", "type" : "char_array", "index": {}, "size" : 32 },
            { "name" : "int16_array", "type" : "int16_array", "size" : 32 },
            { "name" : "int32_array", "type" : "int32_array", "size" : 32 },
            { "name" : "int64_array", "type" : "int64_array", "size" : 32 },
            { "name" : "uint16_array", "type" : "uint16_array", "size" : 32 },
            { "name" : "uint32_array", "type" : "uint32_array", "size" : 32 },
            { "name" : "uint64_array", "type" : "uint64_array", "size" : 32 },
            { "name" : "float_array", "type" : "float_array", "size" : 32 },
            { "name" : "double_array", "type" : "double_array", "size" : 32 },
            { "name" : "long_double_array", "type" : "long_double_array", "size" : 32 }
        ])
        cls.schema.add(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownDb()
        pass

    def test_00_add_data(self):
        a = [ ]
        for i in range(0, self.schema.attr_count()):
            if i == 0:
                v = bytearray(self.schema[i].name(), encoding='utf-8')
            elif i == 1:
                v = self.schema[i].name()
            else:
                v = list(range(0, 16))
            a.append(v)
        for i in range(0, 10):
            o = self.schema.alloc()
            o[:] = a
            o.index_add()

    def test_01_get_data(self):
        attr = self.schema['char_array']
        f = attr.filter()
        o = f.begin()
        while o:
            for i in range(0, self.schema.attr_count()):
                if i == 0:
                    a = bytearray(self.schema[i].name(), encoding='utf-8')
                elif i == 1:
                    a = self.schema[i].name()
                else:
                    a = list(range(0, 16))
                for j in range(0, len(a)):
                    b = o[i]
                    self.assertEqual(a[j], b[j])
            o = next(f)

    def test_02_set_data(self):
        attr = self.schema['char_array']
        f = attr.filter()
        o = f.begin()
        while o:
            v = []
            for i in range(0, self.schema.attr_count()):
                if i == 0:
                    a = bytearray("new_" + self.schema[i].name(), encoding='utf-8')
                elif i == 1:
                    a = "new_" + self.schema[i].name()
                else:
                    a = list(range(16, 32))
                v.append(a)
            o[:] = v
            o = next(f)

    def test_03_get_data(self):
        attr = self.schema['char_array']
        f = attr.filter()
        o = f.begin()
        while o:
            for i in range(0, self.schema.attr_count()):
                if i == 0:
                    a = bytearray("new_"+self.schema[i].name(), encoding='utf-8')
                elif i == 1:
                    a = "new_"+self.schema[i].name()
                else:
                    a = list(range(16, 32))
                for j in range(0, len(a)):
                    b = o[i]
                    self.assertEqual(a[j], b[j])
            o = next(f)

    def test_04_too_big(self):
        attr = self.schema['char_array']
        f = attr.filter()
        o = f.begin()
        v = "1234567890123456789012345678901234567890"
        try:
            o['char_array'] = v
        except:
            pass
            return
        raise ValueError("The {0} array can only accomodate "
                         "{1} members, {2} were provided".\
                         format(attr.name(), attr.count(), len(v)))
        self.assertEqual("", "The value is too big and should have thrown an exception")

if __name__ == "__main__":
    LOGFMT = '%(asctime)s %(name)s %(levelname)s: %(message)s'
    logging.basicConfig(format=LOGFMT)
    logger.setLevel(logging.INFO)
    _pystart = os.environ.get("PYTHONSTARTUP")
    if _pystart:
        execfile(_pystart)
    unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
