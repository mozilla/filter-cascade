import unittest
import filtercascade

class MockFile(object):
    def __init__(self):
        self.data = b""
    def __len__(self):
        return len(self.data)
    def __getitem__(self, idx):
        return self.data[idx]

    def write(self, s):
        self.data = self.data + s
    def read(self):
        return self.data
    def flush(self):
        pass


class TestFilterCascade(unittest.TestCase):
    def assertBloomerEqual(self, b1, b2):
        self.assertEqual(b1.nHashFuncs, b2.nHashFuncs)
        self.assertEqual(b1.size, b2.size)
        self.assertEqual(b1.level, b2.level)
        self.assertEqual(b1.hashAlg, b2.hashAlg)
        self.assertEqual(b1.bitarray, b2.bitarray)

    def test_bloomer_serial_deserial(self):
        b1 = filtercascade.Bloomer(size=32, nHashFuncs=6, level=1)

        h = MockFile()
        b1.tofile(h)
        (buf, b2) = filtercascade.Bloomer.from_buf(h)
        self.assertEqual(len(buf), 0)
        self.assertBloomerEqual(b1, b2)

    def test_fc_serial_deserial(self):
        f1 = filtercascade.FilterCascade([])
        f1.initialize(include=["A", "B", "C"], exclude=["D"])

        h = MockFile()
        f1.tofile(h)

        f2 = filtercascade.FilterCascade.from_buf(h)

        for i in range(0, len(f1.filters)):
            self.assertBloomerEqual(f1.filters[i], f2.filters[i])


if __name__ == '__main__':
    unittest.main()