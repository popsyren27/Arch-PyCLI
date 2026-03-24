import os
import unittest

from core import secure_store as ss


class SecureStoreTests(unittest.TestCase):
    def test_small_write_read(self):
        ss.write_encrypted('unittest/hello.txt', b'hello world', overwrite=True)
        data = ss.read_encrypted('unittest/hello.txt')
        self.assertEqual(data, b'hello world')
        ss.delete('unittest/hello.txt')

    def test_stream_file(self):
        src = 'scripts/test_src_tmp.bin'
        os.makedirs('scripts', exist_ok=True)
        with open(src, 'wb') as f:
            f.write(b'A' * 200000)

        ss.write_encrypted_file('unittest/big.bin', src, overwrite=True, chunk_size=65536)
        parts = list(ss.stream_decrypt('unittest/big.bin'))
        data = b''.join(parts)
        self.assertEqual(len(data), 200000)
        self.assertEqual(data, b'A' * 200000)

        ss.delete('unittest/big.bin')
        os.remove(src)


if __name__ == '__main__':
    unittest.main()
