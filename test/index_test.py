#!/usr/bin/env python
import unittest
import shutil
import logging
import os
from sosdb import Sos
from sosunittest import SosTestCase, Dprint
import random
import numpy as np
import numpy.random as nprnd
import datetime as dt
class Debug(object): pass

logger = logging.getLogger(__name__)
data = []

class IndexTest(SosTestCase):
    @classmethod
    def setUpClass(cls):
        cls.setUpDb("index_test_cont")
        cls.uint16_idx = Sos.Index()
        cls.uint32_idx = Sos.Index()
        cls.uint64_idx = Sos.Index()
        cls.int16_idx = Sos.Index()
        cls.int32_idx = Sos.Index()
        cls.int64_idx = Sos.Index()
        cls.float_idx = Sos.Index()
        cls.double_idx = Sos.Index()
        cls.long_double_idx = Sos.Index()
        cls.string_idx = Sos.Index()

    @classmethod
    def tearDownClass(cls):
        cls.tearDownDb()

    def __generate_data(self):
        for i in range(0, 1024):
            data.append(random.randint(1, 16383))

    def test_00_create_indices(self):
        self.uint16_idx.create(self.db, "uint16", Sos.TYPE_UINT16)
        self.uint16_idx.open(self.db, "uint16")
        self.assertEqual(self.uint16_idx.key_type(), Sos.TYPE_UINT16)

        self.uint32_idx.create(self.db, "uint32", Sos.TYPE_UINT32)
        self.uint32_idx.open(self.db, "uint32")
        self.assertEqual(self.uint32_idx.key_type(), Sos.TYPE_UINT32)

        self.uint64_idx.create(self.db, "uint64", Sos.TYPE_UINT64)
        self.uint64_idx.open(self.db, "uint64")
        self.assertEqual(self.uint64_idx.key_type(), Sos.TYPE_UINT64)

        self.int16_idx.create(self.db, "int16", Sos.TYPE_INT16)
        self.int16_idx.open(self.db, "int16")
        self.assertEqual(self.int16_idx.key_type(), Sos.TYPE_INT16)

        self.int32_idx.create(self.db, "int32", Sos.TYPE_INT32)
        self.int32_idx.open(self.db, "int32")
        self.assertEqual(self.int32_idx.key_type(), Sos.TYPE_INT32)

        self.int64_idx.create(self.db, "int64", Sos.TYPE_INT64)
        self.int64_idx.open(self.db, "int64")
        self.assertEqual(self.int64_idx.key_type(), Sos.TYPE_INT64)

        self.float_idx.create(self.db, "float", Sos.TYPE_FLOAT)
        self.float_idx.open(self.db, "float")
        self.assertEqual(self.float_idx.key_type(), Sos.TYPE_FLOAT)

        self.double_idx.create(self.db, "double", Sos.TYPE_DOUBLE)
        self.double_idx.open(self.db, "double")
        self.assertEqual(self.double_idx.key_type(), Sos.TYPE_DOUBLE)

        self.string_idx.create(self.db, "string", Sos.TYPE_STRING)
        self.string_idx.open(self.db, "string")
        self.assertEqual(self.string_idx.key_type(), Sos.TYPE_STRING)

    def test_01_add_uint16_data(self):
        global data
        self.__generate_data()

        k = Sos.Key(sos_type=Sos.TYPE_UINT16)
        for t in data:
            k.set_value(t)
            self.uint16_idx.insert_ref(k, ( 16, t ))

    def test_02_check_uint16_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_UINT16)
        for t in data:
            k.set_value(t)
            ( a, b ) = self.uint16_idx.find_ref(k)
            self.assertEqual(16, a)
            self.assertEqual(t, b)

    def test_03_add_uint32_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_UINT32)
        for t in data:
            k.set_value(t)
            self.uint32_idx.insert_ref(k, ( 32, t ))

    def test_04_check_uint32_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_UINT32)
        for t in data:
            k.set_value(t)
            ( a, b ) = self.uint32_idx.find_ref(k)
            self.assertEqual(32, a)
            self.assertEqual(t, b)

    def test_05_add_uint64_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_UINT64)
        for t in data:
            k.set_value(t)
            self.uint64_idx.insert_ref(k, ( 64, t ))

    def test_06_check_uint64_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_UINT64)
        for t in data:
            k.set_value(t)
            ( a, b ) = self.uint64_idx.find_ref(k)
            self.assertEqual(64, a)
            self.assertEqual(t, b)

    def test_07_add_int16_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_INT16)
        for t in data:
            k.set_value(-t)
            self.int16_idx.insert_ref(k, ( 16, t ))

    def test_08_check_int16_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_INT16)
        for t in data:
            k.set_value(-t)
            ( a, b ) = self.int16_idx.find_ref(k)
            self.assertEqual(16, a)
            self.assertEqual(t, b)

    def test_09_add_int32_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_INT32)
        for t in data:
            k.set_value(-t)
            self.int32_idx.insert_ref(k, ( 32, t ))

    def test_10_check_int32_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_INT32)
        for t in data:
            k.set_value(-t)
            ( a, b ) = self.int32_idx.find_ref(k)
            self.assertEqual(32, a)
            self.assertEqual(t, b)

    def test_11_add_int64_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_INT64)
        for t in data:
            k.set_value(-t)
            self.int64_idx.insert_ref(k, (64, t))

    def test_12_check_int64_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_INT64)
        for t in data:
            k.set_value(-t)
            ( a, b ) = self.int64_idx.find_ref(k)
            self.assertEqual(64, a)
            self.assertEqual(t, b)

    def test_13_add_float_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_FLOAT)
        for t in data:
            k.set_value(float(t))
            self.float_idx.insert_ref(k, (64, t))

    def test_14_check_float_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_FLOAT)
        for t in data:
            k.set_value(float(t))
            ( a, b ) = self.float_idx.find_ref(k)
            self.assertEqual(64, a)
            self.assertEqual(t, b)

    def test_15_add_double_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_DOUBLE)
        for t in data:
            k.set_value(float(t))
            self.double_idx.insert_ref(k, (64, t))

    def test_16_check_double_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_DOUBLE)
        for t in data:
            k.set_value(float(t))
            ( a, b ) = self.double_idx.find_ref(k)
            self.assertEqual(64, a)
            self.assertEqual(t, b)

    def test_17_add_string_data(self):
        global data

        k = Sos.Key(sos_type=Sos.TYPE_STRING, count=32)
        for t in data:
            k.set_value(str(t))
            self.string_idx.insert_ref(k, (64, t))

    def test_18_check_string_data(self):
        global data
        k = Sos.Key(sos_type=Sos.TYPE_STRING, count=32)
        for t in data:
            k.set_value(str(t))
            ( a, b ) = self.string_idx.find_ref(k)
            self.assertEqual(64, a)
            self.assertEqual(t, b)

    def test_19_check_min_uint16_data(self):
        global data

        k, r = self.uint16_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_UINT16)
        j.set_value(min(data));
        self.assertTrue(k == j)

        k, r = self.uint16_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_UINT16)
        j.set_value(max(data));
        self.assertTrue(k == j)

    def test_20_check_min_uint32_data(self):
        global data

        k, r = self.uint32_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_UINT32)
        j.set_value(min(data));
        self.assertTrue(k == j)

        k, r = self.uint32_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_UINT32)
        j.set_value(max(data));
        self.assertTrue(k == j)

    def test_21_check_min_uint64_data(self):
        global data

        k, r = self.uint64_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_UINT64)
        j.set_value(min(data));
        self.assertTrue(k == j)

        k, r = self.uint64_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_UINT64)
        j.set_value(max(data));
        self.assertTrue(k == j)

    def test_22_check_min_int16_data(self):
        global data

        k, r = self.int16_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_INT16)
        j.set_value(-max(data));
        self.assertTrue(k == j)

        k, r = self.int16_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_INT16)
        j.set_value(-min(data));
        self.assertTrue(k == j)

    def test_23_check_min_int32_data(self):
        global data

        k, r = self.int32_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_INT32)
        j.set_value(-max(data));
        self.assertTrue(k == j)

        k, r = self.int32_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_INT32)
        j.set_value(-min(data));
        self.assertTrue(k == j)

    def test_24_check_min_int64_data(self):
        global data

        k, r = self.int64_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_INT64)
        j.set_value(-max(data));
        self.assertTrue(k == j)

        k, r = self.int64_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_INT64)
        j.set_value(-min(data));
        self.assertTrue(k == j)

    def test_25_check_min_float_data(self):
        global data

        k, r = self.float_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_FLOAT)
        j.set_value(min(data));
        self.assertTrue(k == j)

        k, r = self.float_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_FLOAT)
        j.set_value(max(data));
        self.assertTrue(k == j)

    def test_26_check_min_double_data(self):
        global data

        k, r = self.double_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_DOUBLE)
        j.set_value(min(data));
        self.assertTrue(k == j)

        k, r = self.double_idx.find_max_ref()
        j = Sos.Key(sos_type=Sos.TYPE_DOUBLE)
        j.set_value(max(data));
        self.assertTrue(k == j)

    def test_27_check_min_max_string_data(self):
        global data
        key_data = [ str(d) for d in data ]

        minval = min(key_data)
        k, r = self.string_idx.find_min_ref()
        j = Sos.Key(sos_type=Sos.TYPE_STRING, count=32)
        j.set_value(minval);
        self.assertTrue(k == j)

        maxval = max(key_data)
        k, r = self.string_idx.find_max_ref()
        j.set_value(maxval);
        self.assertTrue(k == j)

if __name__ == "__main__":
    LOGFMT = '%(asctime)s %(name)s %(levelname)s: %(message)s'
    logging.basicConfig(format=LOGFMT)
    logger.setLevel(logging.INFO)
    _pystart = os.environ.get("PYTHONSTARTUP")
    if _pystart:
        execfile(_pystart)
    unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
