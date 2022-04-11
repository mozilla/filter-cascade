import filtercascade
import hashlib
import math
import unittest
import warnings
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
        self.assertEqual(len(b1.bitarray), len(b2.bitarray))
        self.assertEqual(b1.bitarray, b2.bitarray)

    def assertFilterCascadeEqual(self, f1, f2):
        self.assertEqual(len(f1.filters), len(f2.filters))
        for i in range(0, len(f1.filters)):
            self.assertBloomerEqual(f1.filters[i], f2.filters[i])
        self.assertEqual(f1.salt, f2.salt)
        self.assertEqual(f1.defaultHashAlg, f2.defaultHashAlg)
        self.assertEqual(f1.invertedLogic, f2.invertedLogic)

    def test_bloomer_serial_deserial(self):
        b1 = filtercascade.Bloomer(size=32, nHashFuncs=6, level=1)

        h = MockFile()
        b1.tofile(h)
        (buf, b2) = filtercascade.Bloomer.from_buf(h)
        self.assertEqual(len(buf), 0)
        self.assertBloomerEqual(b1, b2)

    def test_fc_serial_deserial(self):
        f1 = filtercascade.FilterCascade()
        f1.initialize(exclude=["A", "B", "C"], include=["D"])

        h = MockFile()
        f1.tofile(h)

        f2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(f1, f2)

    def test_fc_input_types(self):
        f1 = filtercascade.FilterCascade()
        f1.initialize(include=["A"], exclude=["D"])

        f2 = filtercascade.FilterCascade()
        f2.initialize(include=[b"A"], exclude=[b"D"])

        incClass = SimpleToByteClass(ord("A"))
        excClass = SimpleToByteClass(ord("D"))
        f3 = filtercascade.FilterCascade()
        f3.initialize(include=[incClass], exclude=[excClass])

        self.assertTrue(incClass.method_called)
        self.assertTrue(excClass.method_called)

        self.assertFilterCascadeEqual(f1, f2)
        self.assertFilterCascadeEqual(f1, f3)

    def test_fc_include_not_list(self):
        f = filtercascade.FilterCascade()
        with self.assertRaises(TypeError):
            f.initialize(
                include=predictable_serial_gen(1), exclude=predictable_serial_gen(1)
            )

    def test_fc_exclude_must_be_iterable(self):
        f = filtercascade.FilterCascade([])
        with self.assertRaises(TypeError):
            f.initialize(include=[], exclude=list(1))

    def test_fc_iterable(self):
        f = filtercascade.FilterCascade(filters=[])

        iterator, small_set = get_serial_iterator_and_set(
            num_iterator=500_000, num_set=3_000
        )
        f.initialize(include=small_set, exclude=iterator)
        self.assertFalse(f.invertedLogic)

        self.assertEqual(len(f.filters), 10)
        self.assertEqual(
            list(map(lambda x: x.size, f.filters)),
            [26824, 10624, 2184, 5208, 1440, 1872, 1440, 1440, 1440, 1440],
        )

        h = MockFile()
        f.tofile(h)
        self.assertEqual(len(h), 6843)

    def test_verify_failure(self):
        """
        This test cheats, changing the corpus of data out from under the Bloom
        filter. Not every such change would raise an AssertionError,
        particularly on these small data-sets.
        """
        fc = filtercascade.FilterCascade()

        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        with self.assertRaises(AssertionError):
            iterator2, small_set2 = get_serial_iterator_and_set(
                num_iterator=10, num_set=2
            )
            fc.verify(include=small_set2, exclude=iterator2)

    def test_fc_load_version_1(self):
        fc = filtercascade.FilterCascade(version=1)
        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_load_version_2(self):
        fc = filtercascade.FilterCascade(version=2)
        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_load_version_2_with_salt(self):
        fc = filtercascade.FilterCascade(
            version=2,
            salt=b"nacl",
            defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
        )
        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)
        self.assertFalse(fc.invertedLogic)

        h = MockFile()
        fc.tofile(h)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_heterogenous_hash_algorithms(self):
        fc = filtercascade.FilterCascade(
            filters=[
                filtercascade.Bloomer(
                    size=32,
                    nHashFuncs=6,
                    level=1,
                    hashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
                ),
                filtercascade.Bloomer(
                    size=32,
                    nHashFuncs=1,
                    level=2,
                    hashAlg=filtercascade.fileformats.HashAlgorithm.MURMUR3,
                ),
            ]
        )

        h = MockFile()
        fc.tofile(h)

        with self.assertRaises(ValueError):
            filtercascade.FilterCascade.from_buf(h)

    def test_fc_small_filter_length(self):
        fc = filtercascade.FilterCascade(min_filter_length=8)

        iterator, small_set = get_serial_iterator_and_set(
            num_iterator=5_000, num_set=100
        )

        fc.initialize(include=small_set, exclude=iterator)
        h = MockFile()
        fc.tofile(h)
        self.assertEqual(len(h.data), 280)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_inverted_logic_iterators(self):
        fc = filtercascade.FilterCascade()
        self.assertFalse(fc.invertedLogic)

        iterator, huge_set = get_serial_iterator_and_set(
            num_iterator=100, num_set=50_000
        )
        with self.assertRaises(filtercascade.InvertedLogicException):
            fc.initialize(include=huge_set, exclude=iterator)

    def test_fc_inverted_logic_automatic(self):
        fc = filtercascade.FilterCascade(min_filter_length=1024)
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

        self.assertEqual(len(h.data), 1055)

        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertFilterCascadeEqual(fc, fc2)

        iterator, huge_set = get_serial_iterator_and_set(
            num_iterator=100, num_set=50_000
        )
        fc2.verify(include=huge_set, exclude=iterator)

    def test_fc_inverted_logic_explicit(self):
        fc = filtercascade.FilterCascade(invertedLogic=True)
        iterator, small_set = get_serial_iterator_and_set(num_iterator=2, num_set=2)
        fc.initialize(include=small_set, exclude=set(iterator))
        self.assertTrue(fc.invertedLogic)

        iterator, small_set = get_serial_iterator_and_set(num_iterator=2, num_set=2)
        fc.verify(include=small_set, exclude=iterator)

        h = MockFile()
        fc.tofile(h)
        fc2 = filtercascade.FilterCascade.from_buf(h)
        self.assertTrue(fc2.invertedLogic)
        self.assertFilterCascadeEqual(fc, fc2)

    def test_fc_inverted_logic_disk_layout(self):
        fc = filtercascade.FilterCascade(
            defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256, salt=b"a"
        )
        iterator, huge_set = get_serial_iterator_and_set(
            num_iterator=100, num_set=50_000
        )

        # Should automatically invert the logic
        fc.initialize(include=huge_set, exclude=set(iterator))
        self.assertTrue(fc.invertedLogic)

        h = MockFile()
        fc.tofile(h)
        self.assertEqual(h.data[0:1], b"\x02")
        self.assertEqual(h.data[2], 1)  # inverted
        self.assertEqual(h.data[3], 1)  # salt_len
        self.assertEqual(h.data[4], ord("a"))  # salt
        self.assertEqual(h.data[5], filtercascade.fileformats.HashAlgorithm.SHA256)

    def test_fc_standard_logic_disk_layout(self):
        fc = filtercascade.FilterCascade(
            defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256, salt=b"a"
        )
        iterator, small_set = get_serial_iterator_and_set(
            num_iterator=50_000, num_set=100
        )

        # Should automatically invert the logic
        fc.initialize(include=small_set, exclude=iterator)
        self.assertFalse(fc.invertedLogic)

        h = MockFile()
        fc.tofile(h)
        self.assertEqual(h.data[0:1], b"\x02")
        self.assertEqual(h.data[2], 0)  # inverted
        self.assertEqual(h.data[3], 1)  # salt_len
        self.assertEqual(h.data[4], ord("a"))  # salt
        self.assertEqual(h.data[5], filtercascade.fileformats.HashAlgorithm.SHA256)

    def test_fc_write_rewrite(self):
        _blocked = [
            ("guid1@", "1.0"),
            ("@guid2", "1.0"),
            ("@guid2", "1.1"),
            ("guid3@", "0.01b1"),
        ]
        blocked = [f"{guid}:{version}" for guid, version in _blocked]
        _not_blocked = [
            ("guid10@", "1.0"),
            ("@guid20", "1.0"),
            ("@guid20", "1.1"),
            ("guid30@", "0.01b1"),
            ("guid100@", "1.0"),
            ("@guid200", "1.0"),
            ("@guid200", "1.1"),
            ("guid300@", "0.01b1"),
        ]
        not_blocked = [f"{guid}:{version}" for guid, version in _not_blocked]

        salt = b"sixteenbyteslong"
        fprs = [len(blocked) / (math.sqrt(2) * len(not_blocked)), 0.5]

        f = MockFile()

        with warnings.catch_warnings(record=True) as w:
            cascade_out = filtercascade.FilterCascade.cascade_with_characteristics(
                capacity=int(len(blocked) * 1.1),
                error_rates=fprs,
                defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
                salt=salt,
            )
            assert "deprecated" in str(w[-1].message)

            cascade_out.initialize(include=blocked, exclude=not_blocked)
            cascade_out.verify(include=blocked, exclude=not_blocked)

            cascade_out.tofile(f)

        cascade_in = filtercascade.FilterCascade.from_buf(f)
        self.assertFilterCascadeEqual(cascade_out, cascade_in)
        cascade_in.verify(include=blocked, exclude=not_blocked)


class TestFilterCascadeSalts(unittest.TestCase):
    def test_non_byte_salt(self):
        with self.assertRaises(ValueError):
            filtercascade.FilterCascade(
                defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
                salt=64,
            )

    def test_murmur_with_salt(self):
        with self.assertRaises(ValueError):
            filtercascade.FilterCascade(
                defaultHashAlg=filtercascade.fileformats.HashAlgorithm.MURMUR3,
                salt=b"happiness",
            )

    def test_sha256_with_salt(self):
        fc = filtercascade.FilterCascade(
            defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
            salt=b"happiness",
        )

        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        self.assertEqual(len(fc.filters), 1)
        self.assertEqual(fc.bitCount(), 8128)

        f = MockFile()
        fc.tofile(f)
        self.assertEqual(len(f.data), 1039)

    def test_fc_version_1_with_salt(self):
        with self.assertRaises(ValueError):
            filtercascade.FilterCascade(
                defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
                salt=b"happiness",
                version=1,
            )

    def test_expected_error_rates(self):
        fc = filtercascade.FilterCascade()
        result = fc.set_crlite_error_rates(include_len=50, exclude_len=1_000)
        self.assertAlmostEqual(result[0], 0.0353, places=3)
        self.assertEqual(result[1], 0.5)
        self.assertEqual(result, fc.error_rates)

        with self.assertRaises(filtercascade.InvertedLogicException):
            fc.set_crlite_error_rates(include_len=1_000, exclude_len=50)

    def test_set_error_rates(self):
        fc = filtercascade.FilterCascade()
        with self.assertRaises(ValueError):
            fc.set_error_rates([])
        with self.assertRaises(filtercascade.InvalidErrorRateException):
            fc.set_error_rates([-1])
        with self.assertRaises(filtercascade.InvalidErrorRateException):
            fc.set_error_rates([1.1])
        with self.assertRaises(filtercascade.InvalidErrorRateException):
            fc.set_error_rates([0])
        with self.assertRaises(filtercascade.InvalidErrorRateException):
            fc.set_error_rates([0, 0.25, 0.9])
        with self.assertRaises(filtercascade.InvalidErrorRateException):
            fc.set_error_rates([0.25, 0.9, 1.0])
        with self.assertRaises(filtercascade.InvalidErrorRateException):
            fc.set_error_rates([0.25, 0.9, 940])

        fc.set_error_rates([0.99, 0.01])

    def test_inverted_logic_erroneous_error_rate(self):
        not_blocked = ["one_not_blocked_item"]
        blocked = [str(i) for i in range(1000)]
        fprs = [len(blocked) / (math.sqrt(2) * len(not_blocked)), 0.5]
        with self.assertRaises(filtercascade.InvalidErrorRateException):
            filtercascade.FilterCascade(
                defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
                salt=b"VERY_PREDICTABLE",
                error_rates=fprs,
            )

    def test_increased_false_positive_rate_in_deeper_layer(self):
        salt = b"VERY_PREDICTABLE"
        blocked = []
        not_blocked = []
        for i in range(1, 1000):
            not_blocked.append(str(-i))
            blocked.append(str(i))
        fprs = [len(blocked) / (math.sqrt(2) * len(not_blocked)), 0.5]
        fc = filtercascade.FilterCascade(
            error_rates=fprs,
            defaultHashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
            salt=salt,
        )
        fc.initialize(include=blocked, exclude=not_blocked)
        fc.verify(include=blocked, exclude=not_blocked)

        self.assertEqual(len(fc.filters), 6)
        self.assertEqual(fc.bitCount(), 7992)


class TestFilterCascadeAlgorithms(unittest.TestCase):
    def verify_minimum_sets(self, *, hashAlg, salt):
        fc = filtercascade.FilterCascade(defaultHashAlg=hashAlg, salt=salt)

        iterator, small_set = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc.initialize(include=small_set, exclude=iterator)

        self.assertEqual(len(fc.filters), 1)
        self.assertEqual(fc.bitCount(), 8128)

        f = MockFile()
        fc.tofile(f)
        self.assertEqual(
            len(f.data), 1030 + (len(salt) if isinstance(salt, bytes) else 0)
        )

        fc2 = filtercascade.FilterCascade.from_buf(f)
        iterator2, small_set2 = get_serial_iterator_and_set(num_iterator=10, num_set=1)
        fc2.verify(include=small_set2, exclude=iterator2)

    def test_murmurhash3(self):
        self.verify_minimum_sets(
            hashAlg=filtercascade.fileformats.HashAlgorithm.MURMUR3,
            salt=None,
        )

    def test_sha256(self):
        self.verify_minimum_sets(
            hashAlg=filtercascade.fileformats.HashAlgorithm.SHA256,
            salt=None,
        )

    def test_sha256ctr(self):
        self.verify_minimum_sets(
            hashAlg=filtercascade.fileformats.HashAlgorithm.SHA256CTR, salt=b"salt"
        )


if __name__ == "__main__":
    unittest.main()
