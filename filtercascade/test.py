import filtercascade
import hashlib
import unittest
from itertools import islice


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


class SimpleToByteClass(object):
    def __init__(self, ordinal):
        self.o = ordinal
        self.method_called = False

    def to_bytes(self):
        self.method_called = True
        return self.o.to_bytes(1, "little")


def predictable_serial_gen(end):
    counter = 0
    while counter < end:
        counter += 1
        m = hashlib.sha256()
        m.update(counter.to_bytes(4, byteorder="big"))
        yield m.hexdigest()


def get_serial_sets(*, num_revoked, num_valid):
    valid = predictable_serial_gen(num_revoked + num_valid)
    # revocations must be disjoint from the main set, so
    # slice off a set and re-use the remainder
    revoked = set(islice(valid, num_revoked))
    return (valid, revoked)


class TestFilterCascade(unittest.TestCase):
    def assertBloomerEqual(self, b1, b2):
        self.assertEqual(b1.nHashFuncs, b2.nHashFuncs)
        self.assertEqual(b1.size, b2.size)
        self.assertEqual(b1.level, b2.level)
        self.assertEqual(b1.hashAlg, b2.hashAlg)
        self.assertEqual(b1.bitarray, b2.bitarray)

    def assertFilterCascadeEqual(self, f1, f2):
        self.assertEqual(len(f1.filters), len(f2.filters))
        for i in range(0, len(f1.filters)):
            self.assertBloomerEqual(f1.filters[i], f2.filters[i])
        self.assertEqual(f1.salt, f2.salt)

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
        self.assertFilterCascadeEqual(f1, f2)

    def test_fc_input_types(self):
        f1 = filtercascade.FilterCascade([])
        f1.initialize(include=["A"], exclude=["D"])

        f2 = filtercascade.FilterCascade([])
        f2.initialize(include=[b"A"], exclude=[b"D"])

        incClass = SimpleToByteClass(ord("A"))
        excClass = SimpleToByteClass(ord("D"))
        f3 = filtercascade.FilterCascade([])
        f3.initialize(include=[incClass], exclude=[excClass])

        self.assertTrue(incClass.method_called)
        self.assertTrue(excClass.method_called)

        self.assertFilterCascadeEqual(f1, f2)
        self.assertFilterCascadeEqual(f1, f3)

    def test_fc_include_not_list(self):
        f = filtercascade.FilterCascade([])
        with self.assertRaises(TypeError):
            f.initialize(
                include=predictable_serial_gen(1), exclude=predictable_serial_gen(1)
            )

    def test_fc_exclude_must_be_iterable(self):
        f = filtercascade.FilterCascade([])
        with self.assertRaises(TypeError):
            f.initialize(include=[], exclude=list(1))

    def test_fc_iterable(self):
        f = filtercascade.FilterCascade([])

        valid, revoked = get_serial_sets(num_valid=500_000, num_revoked=3_000)
        f.initialize(include=revoked, exclude=valid)

        self.assertEqual(len(f.filters), 3)
        self.assertEqual(f.filters[0].size, 81272)
        self.assertEqual(f.filters[1].size, 14400)
        self.assertEqual(f.filters[2].size, 14400)

    def test_verify_failure(self):
        """
        This test cheats, changing the corpus of data out from under the Bloom
        filter. Not every such change would raise an AssertionError,
        particularly on these small data-sets.
        """
        fc = filtercascade.FilterCascade([])

        valid, revoked = get_serial_sets(num_valid=10, num_revoked=1)
        fc.initialize(include=revoked, exclude=valid)

        with self.assertRaises(AssertionError):
            valid2, revoked2 = get_serial_sets(num_valid=10, num_revoked=2)
            fc.verify(include=revoked2, exclude=valid2)

    def test_fc_load_version_1(self):
        fc = filtercascade.FilterCascade([], version=1)
        valid, revoked = get_serial_sets(num_valid=10, num_revoked=1)
        fc.initialize(include=revoked, exclude=valid)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_load_version_2(self):
        fc = filtercascade.FilterCascade([], version=2)
        valid, revoked = get_serial_sets(num_valid=10, num_revoked=1)
        fc.initialize(include=revoked, exclude=valid)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_load_version_2_with_salt(self):
        fc = filtercascade.FilterCascade(
            [], version=2, salt=b"nacl", hashAlg=filtercascade.HashAlgorithm.SHA256
        )
        valid, revoked = get_serial_sets(num_valid=10, num_revoked=1)
        fc.initialize(include=revoked, exclude=valid)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)


class TestFilterCascadeSalts(unittest.TestCase):
    def test_non_byte_salt(self):
        with self.assertRaises(ValueError):
            filtercascade.FilterCascade(
                [], hashAlg=filtercascade.HashAlgorithm.SHA256, salt=64
            )

    def test_murmur_with_salt(self):
        with self.assertRaises(ValueError):
            filtercascade.FilterCascade(
                [], hashAlg=filtercascade.HashAlgorithm.MURMUR3, salt=b"happiness"
            )

    def test_sha256_with_salt(self):
        fc = filtercascade.FilterCascade(
            [], hashAlg=filtercascade.HashAlgorithm.SHA256, salt=b"happiness"
        )

        valid, revoked = get_serial_sets(num_valid=10, num_revoked=1)
        fc.initialize(include=revoked, exclude=valid)

        self.assertEqual(len(fc.filters), 1)
        self.assertEqual(fc.bitCount(), 81272)

        f = MockFile()
        fc.tofile(f)
        self.assertEqual(len(f.data), 10183)

    def test_fc_version_1_with_salt(self):
        with self.assertRaises(ValueError):
            filtercascade.FilterCascade(
                [],
                hashAlg=filtercascade.HashAlgorithm.SHA256,
                salt=b"happiness",
                version=1,
            )


class TestFilterCascadeAlgorithms(unittest.TestCase):
    def verify_minimum_sets(self, *, hashAlg):
        fc = filtercascade.FilterCascade([], hashAlg=hashAlg)

        valid, revoked = get_serial_sets(num_valid=10, num_revoked=1)
        fc.initialize(include=revoked, exclude=valid)

        self.assertEqual(len(fc.filters), 1)
        self.assertEqual(fc.bitCount(), 81272)

        f = MockFile()
        fc.tofile(f)
        self.assertEqual(len(f.data), 10174)

        fc2 = filtercascade.FilterCascade.from_buf(f)
        valid2, revoked2 = get_serial_sets(num_valid=10, num_revoked=1)
        fc2.verify(include=revoked2, exclude=valid2)

    def test_murmurhash3(self):
        self.verify_minimum_sets(hashAlg=filtercascade.HashAlgorithm.MURMUR3)

    def test_sha256(self):
        self.verify_minimum_sets(hashAlg=filtercascade.HashAlgorithm.SHA256)


if __name__ == "__main__":
    unittest.main()
