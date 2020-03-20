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


def get_serial_iterator_and_set(*, num_set, num_iterator):
    iterator_data = predictable_serial_gen(num_iterator + num_set)
    # revocations must be disjoint from the main set, so
    # slice off a set and re-use the remainder
    set_data = set(islice(iterator_data, num_set))
    return (iterator_data, set_data)


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
        self.assertEqual(f1.hashAlg, f2.hashAlg)

    def test_bloomer_serial_deserial(self):
        b1 = filtercascade.Bloomer(size=32, nHashFuncs=6, level=1)

        h = MockFile()
        b1.tofile(h)
        (buf, b2) = filtercascade.Bloomer.from_buf(h)
        self.assertEqual(len(buf), 0)
        self.assertBloomerEqual(b1, b2)

    def test_fc_serial_deserial(self):
        f1 = filtercascade.FilterCascade([])
        f1.initialize(exclude=["A", "B", "C"], include=["D"])

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

        iterator, small_set = get_serial_iterator_and_set(
            num_iterator=500_000, num_set=3_000
        )
        f.initialize(include=small_set, exclude=iterator)
        self.assertFalse(f.invertedLogic)

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

        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        with self.assertRaises(AssertionError):
            iterator2, small_set2 = get_serial_iterator_and_set(
                num_iterator=10, num_set=2
            )
            fc.verify(include=small_set2, exclude=iterator2)

    def test_fc_load_version_1(self):
        fc = filtercascade.FilterCascade([], version=1)
        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_load_version_2(self):
        fc = filtercascade.FilterCascade([], version=2)
        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_load_version_2_with_salt(self):
        fc = filtercascade.FilterCascade(
            [], version=2, salt=b"nacl", hashAlg=filtercascade.HashAlgorithm.SHA256
        )
        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)
        self.assertFalse(fc.invertedLogic)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_inverted_logic_iterators(self):
        fc = filtercascade.FilterCascade([])
        self.assertFalse(fc.invertedLogic)

        iterator, huge_set = get_serial_iterator_and_set(
            num_iterator=100, num_set=50_000
        )
        with self.assertRaises(filtercascade.InvertedLogicException):
            fc.initialize(include=huge_set, exclude=iterator)

    def test_fc_inverted_logic_automatic(self):
        fc = filtercascade.FilterCascade([])
        self.assertEqual(None, fc.invertedLogic)

        iterator, huge_set = get_serial_iterator_and_set(
            num_iterator=100, num_set=50_000
        )

        # Should automatically invert the logic
        fc.initialize(include=huge_set, exclude=set(iterator))
        self.assertTrue(fc.invertedLogic)

        iterator, huge_set = get_serial_iterator_and_set(
            num_iterator=100, num_set=50_000
        )
        fc.verify(include=huge_set, exclude=iterator)

        h = MockFile()
        fc.tofile(h)
        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

        iterator, huge_set = get_serial_iterator_and_set(
            num_iterator=100, num_set=50_000
        )
        fc2.verify(include=huge_set, exclude=iterator)

    def test_fc_inverted_logic_explicit(self):
        fc = filtercascade.FilterCascade([], invertedLogic=True)
        iterator, small_set = get_serial_iterator_and_set(num_iterator=2, num_set=2)
        fc.initialize(include=small_set, exclude=set(iterator))
        self.assertTrue(fc.invertedLogic)

        iterator, small_set = get_serial_iterator_and_set(num_iterator=2, num_set=2)
        fc.verify(include=small_set, exclude=iterator)


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

        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

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

        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        self.assertEqual(len(fc.filters), 1)
        self.assertEqual(fc.bitCount(), 81272)

        f = MockFile()
        fc.tofile(f)
        self.assertEqual(len(f.data), 10174)

        fc2 = filtercascade.FilterCascade.from_buf(f)
        iterator2, small_set2 = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc2.verify(include=small_set2, exclude=iterator2)

    def test_murmurhash3(self):
        self.verify_minimum_sets(hashAlg=filtercascade.HashAlgorithm.MURMUR3)

    def test_sha256(self):
        self.verify_minimum_sets(hashAlg=filtercascade.HashAlgorithm.SHA256)


if __name__ == "__main__":
    unittest.main()
