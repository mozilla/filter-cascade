import struct

# The header for each Bloom filter level
# Little endian (<)
# byte 0: Hash algorithm enumeration, as an unsigned char
# bytes 1-4: L, length of the bitarray, in bytes, as an unsigned int
# bytes 5-8: the number of hash functions for this layer, as an unsigned int
# byte 9: The layer number of this bloom filter, as an unsigned char
bloomer_struct = struct.Struct(b"<BIIB")

# This struct packs the hash iteration number and the layer number
# into two bytes in a defined way for SHA256.
# Little endian (<)
# byte 0-3: hash iteration number for this layer, as an unsigned int
# byte 4: layer number of this bloom filter, as an unsigned char
bloomer_sha256_hash_struct = struct.Struct(b"<IB")

# The version struct is a simple 2-byte short indicating version number
# Little endian (<)
# bytes 0-1: The version number of this filter, as an unsigned short
version_struct = struct.Struct(b"<H")

# version 2 filters, after the version_struct field, have
# the following:
# Little endian (<)
# byte 0: Whether the decision logic should be inverted, as a boolean
# byte 1: L, length of salt field as a unsigned char
# bytes 2+: salt field of length L
version_2_salt_struct = struct.Struct(b"<?B")
