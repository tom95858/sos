#!/usr/bin/env python
import unittest
import shutil
import logging
import os
import sys
from sosdb import Sos
from cunittest import C_UnitTest

class Debug(object): pass

logger = logging.getLogger(__name__)

class ObjMallocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.getenv("TEST_DATA_DIR")
        if path is None:
            path = "."
        res = cls.initialize_tests(path)
        if res != 0:
            raise ValueError("The tests could not be initialized")

    @classmethod
    def tearDownClass(cls):
        res = cls.finalize_tests()

if __name__ == "__main__":

    c_tests = C_UnitTest(ObjMallocTest, "obj_malloc_test")

    LOGFMT = '%(asctime)s %(name)s %(levelname)s: %(message)s'
    logging.basicConfig(format=LOGFMT)
    logger.setLevel(logging.INFO)
    _pystart = os.environ.get("PYTHONSTARTUP")
    if _pystart:
        execfile(_pystart)
    unittest.TestLoader.testMethodPrefix = "test_"
    unittest.main()
