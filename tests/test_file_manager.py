import os
import unittest

from core import file_manager as fm


class FileManagerTests(unittest.TestCase):
    def test_create_read(self):
        fm.create_file('unittest/fm.txt', 'hello file', exist_ok=True)
        out = fm.read_file('unittest/fm.txt')
        self.assertEqual(out, 'hello file')
        fm.delete_file('unittest/fm.txt')

    def test_write_from_src(self):
        os.makedirs('scripts', exist_ok=True)
        src = 'scripts/fm_src.txt'
        with open(src, 'w', encoding='utf-8') as f:
            f.write('from src content')

        fm.write_file('unittest/fromfile.txt', src, overwrite=True)
        out = fm.read_file('unittest/fromfile.txt')
        self.assertEqual(out, 'from src content')
        fm.delete_file('unittest/fromfile.txt')
        os.remove(src)


if __name__ == '__main__':
    unittest.main()
