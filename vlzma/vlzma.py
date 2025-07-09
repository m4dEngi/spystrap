import zlib
import lzma
import struct
import os


VZ_HEADER_SIZE = 7
# char  'V'
# char  'Z'
# char  version
# int32 timestamp

VZ_FOOTER_SIZE = 10
# int32 crc32_decoded
# int32 size_decoded
# char  'z'
# char  'v'

LZMA_HEADER_SIZE = 5
# byte  props
# int32 dict_size


def decompress(vz_path: str) -> bytes:
    """Decompress vz lzma package to bytes buffer

    :param vz_path: path to .zip.vz package
    :return: bytes buffer containing decoded zip archive
    """

    file_size = os.path.getsize(vz_path)
    if file_size < VZ_HEADER_SIZE + VZ_FOOTER_SIZE + LZMA_HEADER_SIZE:
        raise ValueError("Bad zip.vz! Too small to be valid.")

    with open(vz_path, "rb") as f:
        mv = memoryview(f.read())
        # read vz header
        v, z, rev, timestamp = struct.unpack("=cccI", mv[:VZ_HEADER_SIZE])
        # read vz footer
        crc32, size, _z, _v = struct.unpack("=IIcc", mv[-VZ_FOOTER_SIZE:])
        if v != b'V' or z != b'Z' or _v != b'v' or _z != b'z':
            raise ValueError("Bad zip.vz! Corrupted.")
        if rev != b'a':
            raise ValueError("Bad zip.vz! Unsupported revision.")

        # python's lzma does not support autodetecting and decoding old/legacy lzma
        # but we can still extract it as RAW after some manual header/props parsing
        # and supplying custom filter to lzma.decompress
        props, dict_size = struct.unpack("<BI", mv[VZ_HEADER_SIZE:VZ_HEADER_SIZE+LZMA_HEADER_SIZE])
        lc = props % 9
        t = props // 9
        lp = t % 5
        pb = t // 5

        lzma_filter = [{
            "id": lzma.FILTER_LZMA1,
            "dict_size": dict_size,
            "lc": lc,
            "lp": lp,
            "pb": pb
        }]

        dec_buf = lzma.decompress(mv[VZ_HEADER_SIZE+LZMA_HEADER_SIZE:-VZ_FOOTER_SIZE],
                                    filters=lzma_filter,
                                    format=lzma.FORMAT_RAW)
        dec_crc = zlib.crc32(dec_buf)
        if dec_crc != crc32:
            raise ValueError("Bad zip.vz! CRC32 mismatch!")

        return dec_buf


def compress(buf: bytes, vz_path_out: str) -> None:
    # TODO
    raise NotImplementedError