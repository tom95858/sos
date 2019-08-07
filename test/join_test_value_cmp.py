#!/usr/bin/env python
import unittest
import shutil
import logging
import os
from sosdb import Sos
from sosunittest import SosTestCase

class Debug(object): pass

logger = logging.getLogger(__name__)

col_1_arg = ("A-two", "B-three", "C-four", "D-five")

class JoinTestValueCmp(SosTestCase):
    @classmethod
    def setUpClass(cls):
        cls.setUpDb("join_test_value_cmp_cont")
        cls.schema = Sos.Schema()
        cls.schema.from_template('test_join_value_cmp',
                             [ { "name" : "a_1", "type" : "uint32" },
                               { "name" : "a_2", "type" : "string", "size" : 32 },
                               { "name" : "a_3", "type" : "uint32" },
                               { "name" : "a_join", "type" : "join",
                                 "join_attrs" : [ "a_1", "a_2", "a_3" ],
                                 "index" : {}}
                           ])
        cls.schema.add(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownDb()

    def test_00_add_objects(self):
        # Make the input data such that each component of the key is exercised in the compare
        data = [ (1, "A-two", 3), (2, "B-three", 4), (2, "B-four", 5), (2, "B-four", 6) ]
        objs = []
        for seq in data:
            o = self.schema.alloc()
            objs.append(o)
            o[:] = seq
            o.index_add()

    def test_01_join_value_lt(self):
        a_join = self.schema.attr_by_name('a_join')

        f = a_join.filter()
        o = f.begin()
        pv = Sos.Value(a_join, obj=o)
        while o:
            o = f.next()
            if o:
                nv = Sos.Value(a_join, obj=o)
                self.assertTrue( pv < nv )
                pv = nv
        del f

    def test_02_join_value_gt(self):
        a_join = self.schema.attr_by_name('a_join')

        f = a_join.filter()
        o = f.begin()
        pv = Sos.Value(a_join, obj=o)
        while o:
            o = f.next()
            if o:
                nv = Sos.Value(a_join, obj=o)
                self.assertTrue( nv > pv )
                pv = nv
        del f

    def test_03_join_value_le(self):
        a_join = self.schema.attr_by_name('a_join')

        f = a_join.filter()
        o = f.begin()
        pv = Sos.Value(a_join, obj=o)
        while o:
            o = f.next()
            if o:
                nv = Sos.Value(a_join, obj=o)
                self.assertTrue( pv <= nv )
                pv = nv
        del f

    def test_04_join_value_ge(self):
        a_join = self.schema.attr_by_name('a_join')

        f = a_join.filter()
        o = f.begin()
        pv = Sos.Value(a_join, obj=o)
        while o:
            o = f.next()
            if o:
                nv = Sos.Value(a_join, obj=o)
                self.assertTrue( nv >= pv )
                pv = nv
        del f

    def test_05_join_value_eq(self):
        a_join = self.schema.attr_by_name('a_join')

        f = a_join.filter()
        o = f.begin()
        while o:
            pv = Sos.Value(a_join, obj=o)
            nv = Sos.Value(a_join, obj=o)
            self.assertTrue( pv == nv )
            o = f.next()
        del f

    def test_06_join_value_ne(self):
        a_join = self.schema.attr_by_name('a_join')

        f = a_join.filter()
        o = f.begin()
        pv = Sos.Value(a_join, obj=o)
        while o:
            o = f.next()
            if o:
                nv = Sos.Value(a_join, obj=o)
                self.assertTrue( nv != pv )
                pv = nv
        del f

if __name__ == "__main__":
    LOGFMT = '%(asctime)s %(name)s %(levelname)s: %(message)s'
    logging.basicConfig(format=LOGFMT)
    logger.setLevel(logging.INFO)
    _pystart = os.environ.get("PYTHONSTARTUP")
    if _pystart:
        execfile(_pystart)
    unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
