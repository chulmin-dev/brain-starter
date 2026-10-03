"""Concurrent storage updates must serialize on POSIX and native Windows."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class AtomicLockTests(unittest.TestCase):
    def test_concurrent_read_modify_write_preserves_every_update(self):
        worker = """
import sys, time
from pathlib import Path
from plus._atomic import atomic_write_text, exclusive_lock
path = Path(sys.argv[1])
for _ in range(20):
    with exclusive_lock(path):
        value = int(path.read_text(encoding='utf-8'))
        time.sleep(0.005)
        atomic_write_text(path, str(value + 1))
"""
        skill_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            counter = Path(directory) / 'counter'
            counter.write_text('0', encoding='utf-8')
            children = [subprocess.Popen([sys.executable, '-c', worker, str(counter)],
                        cwd=skill_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        for _ in range(2)]
            try:
                for child in children:
                    _, stderr = child.communicate(timeout=20)
                    self.assertEqual(child.returncode, 0, stderr.decode('utf-8', errors='replace'))
                self.assertEqual(counter.read_text(encoding='utf-8'), '40')
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()


if __name__ == '__main__':
    unittest.main()
