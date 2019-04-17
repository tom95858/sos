# cunittest.py
import ctypes
import os

def run_test(self, name):
    res = self.c_tests.test_dict[name]()
    self.assertEqual(res, 0)

def make_lambda(name):
    return lambda self : run_test(self, name)

class C_UnitTest: # (unittest.TestCase):
    def __init__(self, test_class, test_name):
        self.name = test_name + ".so"
        self.lib = ctypes.cdll.LoadLibrary(os.getcwd() + '/' + self.name)

        setattr( test_class, 'c_tests', self )

        self.initialize_tests = self.lib.initialize_tests
        self.initialize_tests.argtypes = [ ctypes.c_char_p ]
        self.initialize_tests.restype = ctypes.c_int
        setattr( test_class, 'initialize_tests', self.initialize_tests )

        self.finalize_tests = self.lib.finalize_tests
        self.finalize_tests.restype = ctypes.c_int
        setattr( test_class, 'finalize_tests', self.finalize_tests )

        self.cleanup_path = self.lib.cleanup_path
        self.cleanup_path.restype = ctypes.c_char_p
        setattr( test_class, 'cleanup_path', self.cleanup_path )

        self.test_count = self.lib.test_count
        self.test_count.restype = ctypes.c_int

        self.test_name = self.lib.test_name
        self.test_name.argtypes = [ ctypes.c_int ]
        self.test_name.restype = ctypes.c_char_p

        self.test_dict = {}
        for i in range(0, self.test_count()):
            name = self.test_name(i)
            self.test_dict[name] = self.lib[name]

        for name in self.test_dict:
            setattr( test_class, name, make_lambda(name) )
