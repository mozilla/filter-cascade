# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import bitarray
import datetime
import hashlib
import logging
import math
import mmh3
import struct
from filtercascade import fileformats
from deprecated import deprecated

log = logging.getLogger(__name__)


class InvertedLogicException(Exception):
    def __init__(self, *, depth, exclude_count, include_len):
        self.message = (
            f"At Depth {depth}, exclude set ({exclude_count}) was < include set "
            f"({include_len}). If you reached this exception, then either your "
            "input data had an uncountable iterator, or your filter length was "
            "insufficient, and you need to increase it. The only way to fix this "
            "issue is via a code update where you either manually swap the input "
            "'include' and  'exclude' parameters and set the invertedLogic boolean "
            "to True upon construction, or set a larger min_filter_length."
        )

    def __str__(self):
        return self.message


# A simple-as-possible bloom filter implementation making use of version 3 of the 32-bit murmur
# hash function (for compat with multi-level-bloom-filter-js).
# mgoodwin 2018
class Bloomer:
    def __init__(
        self,
        *,
        size,
        nHashFuncs,
        level,
        hashAlg=fileformats.HashAlgorithm.MURMUR3,
        salt=None,
    ):
        self.nHashFuncs = nHashFuncs
        self.size = size
        self.level = level
        self.hashAlg = fileformats.HashAlgorithm(hashAlg)
        self.salt = salt

        self.bitarray = bitarray.bitarray(self.size, endian="little")
        self.bitarray.setall(False)

        if self.salt and not isinstance(self.salt, bytes):
            raise ValueError("salt must be passed as bytes")
        if self.salt and self.hashAlg == fileformats.HashAlgorithm.MURMUR3:
            raise ValueError("salt not permitted for MurmurHash3")

    def hash(self, *, hash_no, key):
        if not isinstance(key, bytes):
            to_bytes_op = getattr(key, "to_bytes", None)
            if isinstance(key, str):
                key = key.encode("utf-8")
            elif callable(to_bytes_op):
                key = to_bytes_op()
            else:
                key = str(key).encode("utf-8")

        if self.hashAlg == fileformats.HashAlgorithm.MURMUR3:
            if self.salt:
                raise ValueError("salts not permitted for MurmurHash3")
            hash_seed = ((hash_no << 16) + self.level) & 0xFFFFFFFF
            h = (mmh3.hash(key, hash_seed) & 0xFFFFFFFF) % self.size
            return h

        if self.hashAlg == fileformats.HashAlgorithm.SHA256:
            m = hashlib.sha256()
            if self.salt:
                m.update(self.salt)
            m.update(fileformats.bloomer_sha256_hash_struct.pack(hash_no, self.level))
            m.update(key)
            h = (
                int.from_bytes(m.digest()[:4], byteorder="little", signed=False)
                % self.size
            )
            return h

        raise Exception(f"Unknown hash algorithm: {self.hashAlg}")

    def add(self, key):
        for i in range(self.nHashFuncs):
            index = self.hash(hash_no=i, key=key)
            self.bitarray[index] = True

    def __contains__(self, key):
        for i in range(self.nHashFuncs):
            index = self.hash(hash_no=i, key=key)
            if not self.bitarray[index]:
                return False
        return True

    def clear(self):
        self.bitarray.setall(False)

    # Follows the bitarray.tofile parameter convention.
    def tofile(self, f):
        """Write the bloom filter to file object `f'. Underlying bits
        are written as machine values. This is much more space
        efficient than pickling the object."""
        f.write(
            fileformats.bloomer_struct.pack(
                self.hashAlg, self.size, self.nHashFuncs, self.level
            )
        )
        f.flush()
        self.bitarray.tofile(f)

    @classmethod
    def filter_with_characteristics(
        cls,
        *,
        elements,
        falsePositiveRate,
        hashAlg=fileformats.HashAlgorithm.MURMUR3,
        salt=None,
        level=1,
    ):
        nHashFuncs = Bloomer.calc_n_hashes(falsePositiveRate)
        size = Bloomer.calc_size(nHashFuncs, elements, falsePositiveRate)
        return Bloomer(
            size=size, nHashFuncs=nHashFuncs, level=level, hashAlg=hashAlg, salt=salt
        )

    @classmethod
    def calc_n_hashes(cls, falsePositiveRate):
        return math.ceil(math.log(1.0 / falsePositiveRate, 2))

    @classmethod
    def calc_size(cls, nHashFuncs, elements, falsePositiveRate):
        # From CRLite paper, https://cbw.sh/static/pdf/larisch-oakland17.pdf
        min_bits = math.ceil(1.44 * elements * math.log(1 / falsePositiveRate, 2))
        # Ensure the result is divisible by 8 for full bytes
        return 8 * math.ceil(min_bits / 8)

    @classmethod
    def from_buf(cls, buf, salt=None):
        log.debug(len(buf))
        hashAlgInt, size, nHashFuncs, level = fileformats.bloomer_struct.unpack(
            buf[: fileformats.bloomer_struct.size]
        )
        buf = buf[fileformats.bloomer_struct.size :]

        byte_count = math.ceil(size / 8)
        ba = bitarray.bitarray(endian="little")

        ba.frombytes(buf[:byte_count])
        buf = buf[byte_count:]

        bloomer = Bloomer(
            size=size,
            nHashFuncs=nHashFuncs,
            level=level,
            hashAlg=fileformats.HashAlgorithm(hashAlgInt),
            salt=salt,
        )
        log.debug(
            f"from_buf size is {size} ({byte_count} bytes), level {level}, nHashFuncs, {nHashFuncs}"
        )
        bloomer.bitarray = ba

        return (buf, bloomer)


class FilterCascade:
    def __init__(
        self,
        filters=None,
        *,
        error_rates=[0.02, 0.5],
        growth_factor=1.1,
        min_filter_length=10_000,
        version=2,
        defaultHashAlg=fileformats.HashAlgorithm.MURMUR3,
        salt=None,
        invertedLogic=None,
    ):
        """
            Construct a FilterCascade.
            error_rates: If not supplied, defaults will be calculated
            invertedLogic: If not supplied (or left as None), it will be auto-
                detected.
        """
        self.filters = filters or []
        self.error_rates = error_rates
        self.growth_factor = growth_factor
        self.min_filter_length = min_filter_length
        self.version = version
        self.defaultHashAlg = defaultHashAlg
        self.salt = salt
        self.invertedLogic = invertedLogic

        if self.salt and version < 2:
            raise ValueError("salt requires format version 2 or greater")
        if self.salt and not isinstance(self.salt, bytes):
            raise ValueError("salt must be passed as byteas")
        if version < 2 and self.defaultHashAlg != fileformats.HashAlgorithm.MURMUR3:
            raise ValueError(
                "hashes other than MurmurHash3 require version 2 or greater"
            )
        if self.salt and self.defaultHashAlg == fileformats.HashAlgorithm.MURMUR3:
            raise ValueError("salts not permitted for MurmurHash3")

    def set_error_rates(self, new_rates):
        if len(new_rates) < 1:
            raise ValueError("You must supply at least one error rate")
        self.error_rates = new_rates

    def set_crlite_error_rates(self, *, include_len, exclude_len):
        if include_len > exclude_len:
            raise InvertedLogicException(
                depth=None, exclude_count=exclude_len, include_len=include_len
            )
        self.error_rates = [include_len / (math.sqrt(2) * exclude_len), 0.5]
        return self.error_rates

    def initialize(self, *, include, exclude):
        """
            Arg "exclude" is potentially larger than main memory, so it should
            be assumed to be passed as a lazy-loading iterator. If it isn't,
            that's fine. The "include" arg must fit in memory and should be
            assumed to be a set.
        """
        try:
            iter(exclude)
        except TypeError as te:
            raise TypeError("exclude is not iterable", te)
        try:
            len(include)
        except TypeError as te:
            raise TypeError("include is not a list", te)

        if self.invertedLogic is None:
            try:
                self.invertedLogic = len(include) > len(exclude)
            except TypeError:
                self.invertedLogic = False

        if self.invertedLogic:
            include, exclude = exclude, include

        include_len = len(include)

        depth = 1
        maxSequentialGrowthLayers = 3
        sequentialGrowthLayers = 0

        while include_len > 0:
            starttime = datetime.datetime.utcnow()
            er = self.error_rates[-1]
            if depth < len(self.error_rates):
                er = self.error_rates[depth - 1]

            if depth > len(self.filters):
                self.filters.append(
                    # For growth-stability reasons, we force all layers to be at least
                    # min_filter_length large. This is important for the deep layers near the end.
                    Bloomer.filter_with_characteristics(
                        elements=max(
                            int(include_len * self.growth_factor),
                            self.min_filter_length,
                        ),
                        salt=self.salt,
                        falsePositiveRate=er,
                        level=depth,
                        hashAlg=self.defaultHashAlg,
                    )
                )
            else:
                # Filter already created for this layer. Check size and resize if needed.
                required_size = Bloomer.calc_size(
                    self.filters[depth - 1].nHashFuncs, include_len, er
                )
                if self.filters[depth - 1].size < required_size:
                    # Resize filter
                    self.filters[depth - 1] = Bloomer.filter_with_characteristics(
                        elements=int(include_len * self.growth_factor),
                        falsePositiveRate=er,
                        level=depth,
                        hashAlg=self.defaultHashAlg,
                    )
                    log.info("Resized filter at {}-depth layer".format(depth))
            filter = self.filters[depth - 1]
            log.debug(
                "Initializing the {}-depth layer. err={} include_len={} size={} hashes={}".format(
                    depth, er, include_len, filter.size, filter.nHashFuncs
                )
            )
            # loop over the elements that *should* be there. Add them to the filter.
            for elem in include:
                filter.add(elem)

            # loop over the elements that should *not* be there. Create a new layer
            # that *includes* the false positives and *excludes* the true positives
            log.debug("Processing false positives")
            false_positives = set()
            exclude_count = 0
            for elem in exclude:
                exclude_count += 1
                if elem in filter:
                    false_positives.add(elem)
            log.debug(f"Found {len(false_positives)} false positives at depth {depth}.")

            if depth == 1 and exclude_count < include_len:
                raise InvertedLogicException(
                    depth=depth, exclude_count=exclude_count, include_len=include_len
                )

            endtime = datetime.datetime.utcnow()
            log.debug(
                "Took {} ms to process layer {} with bit count {}".format(
                    (endtime - starttime).seconds * 1000
                    + (endtime - starttime).microseconds / 1000,
                    depth,
                    len(filter.bitarray),
                )
            )
            # Sanity check layer growth.  Bit count should be going down
            # as false positive rate decreases.
            if depth > 2:
                if len(filter.bitarray) > len(self.filters[depth - 3].bitarray):
                    sequentialGrowthLayers += 1
                    log.warning(
                        "Increase in false positive rate detected. Depth {} has {}"
                        " bits and depth {} has {} bits. {}/{} allowed warnings.".format(
                            depth,
                            len(filter.bitarray),
                            depth - 3 + 1,
                            len(self.filters[depth - 3].bitarray),
                            sequentialGrowthLayers,
                            maxSequentialGrowthLayers,
                        )
                    )
                    if sequentialGrowthLayers >= maxSequentialGrowthLayers:
                        log.error(
                            "Too many sequential false positive increases detected. Aborting."
                        )
                        self.filters.clear()
                        return
                else:
                    sequentialGrowthLayers = 0

            include, exclude = false_positives, include
            include_len = len(include)
            if include_len > 0:
                depth = depth + 1
        # Filter characteristics loaded from meta file may result in unused layers.
        # Remove them.
        if depth < len(self.filters):
            del self.filters[depth:]

    def __internal_contains__(self, elem):
        for layer, filter in [
            (idx + 1, self.filters[idx]) for idx in range(len(self.filters))
        ]:
            even = layer % 2 == 0
            if elem in filter:
                if layer == len(self.filters):
                    return even is not True
            else:
                return even is not False

    def __contains__(self, elem):
        result = self.__internal_contains__(elem)
        return not result if self.invertedLogic is True else result

    @deprecated(
        version="0.2.3",
        reason="Use the verify function which has the same semantics as initialize",
    )
    def check(self, *, entries, exclusions):
        self.verify(include=entries, exclude=exclusions)

    def verify(self, *, include, exclude):
        for entry in include:
            assert entry in self, f"Verification Failure: false negative: {entry}"
        for entry in exclude:
            assert entry not in self, f"Verification Failure: false positive: {entry}"

    def bitCount(self):
        total = 0
        for filter in self.filters:
            total = total + len(filter.bitarray)
        return total

    def layerCount(self):
        return len(self.filters)

    # Follows the bitarray.tofile parameter convention.
    def tofile(self, f):
        if self.version > 2:
            raise Exception(f"Unknown version: {self.version}")

        f.write(fileformats.version_struct.pack(self.version))
        if self.version > 1:
            salt_len = len(self.salt) if self.salt else 0
            f.write(
                fileformats.version_2_salt_struct.pack(self.invertedLogic, salt_len)
            )
            if self.salt:
                f.write(self.salt)

        for filter in self.filters:
            filter.tofile(f)
            f.flush()

    @classmethod
    def from_buf(cls, buf):
        inverted = False
        salt = None

        (version,) = fileformats.version_struct.unpack(
            buf[: fileformats.version_struct.size]
        )
        buf = buf[fileformats.version_struct.size :]

        if version > 2:
            raise Exception(f"Unknown version: {version}")
        if version > 1:
            (inverted, salt_len) = fileformats.version_2_salt_struct.unpack(
                buf[: fileformats.version_2_salt_struct.size]
            )
            buf = buf[fileformats.version_2_salt_struct.size :]

            if salt_len > 0:
                salt = buf[:salt_len]
                buf = buf[salt_len:]

        filters = []
        while len(buf) > 0:
            (buf, f) = Bloomer.from_buf(buf, salt=salt)
            filters.append(f)
        assert len(buf) == 0, "buffer should be consumed"

        hashAlg = filters[0].hashAlg
        for f in filters:
            if f.hashAlg != hashAlg:
                log.warning(
                    f"Layer {f.level} using hash {f.hashAlg}, but layer 0 is using {hashAlg}"
                )
                raise ValueError("All filter layers should use the same hash algorithm")

        return FilterCascade(
            filters=filters,
            version=version,
            defaultHashAlg=hashAlg,
            salt=salt,
            invertedLogic=inverted,
        )

    @classmethod
    @deprecated(
        version="0.4.0",
        reason=(
            "Use the standard __init__ function generally set error rates with "
            + "set_crlite_error_rates or set_error_rates"
        ),
    )
    def cascade_with_characteristics(
        cls,
        *,
        capacity,
        error_rates,
        defaultHashAlg=fileformats.HashAlgorithm.MURMUR3,
        salt=None,
        layer=0,
    ):
        return FilterCascade(
            filters=[
                Bloomer.filter_with_characteristics(
                    elements=capacity,
                    falsePositiveRate=error_rates[0],
                    hashAlg=defaultHashAlg,
                    salt=salt,
                )
            ],
            error_rates=error_rates,
            defaultHashAlg=defaultHashAlg,
            salt=salt,
        )
