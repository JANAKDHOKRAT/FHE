"""Exercise actual subprocess failures and timeout cleanup, without FHE setup."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('study_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
report_spec = importlib.util.spec_from_file_location('study_summary', Path(__file__).with_name('summarize.py'))
report = importlib.util.module_from_spec(report_spec)
report_spec.loader.exec_module(report)


class ProcessIsolation(unittest.TestCase):
    def test_failed_or_running_study_cannot_produce_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for status in ('running', 'failed'):
                (root / 'manifest.json').write_text(json.dumps({'status': status}))
                with self.assertRaises(ValueError):
                    report.summarize(root)

    def test_nonzero_exit_and_diagnostics_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = runner.command([sys.executable, '-c',
                                     'import sys; print("qualification failed"); sys.exit(7)'],
                                    root, os.environ.copy(), root / 'failure.log', 10)
            self.assertEqual(result['returncode'], 7)
            self.assertIn('qualification failed', (root / 'failure.log').read_text())
            self.assertEqual(result['log_sha256'], runner.digest(root / 'failure.log'))

    def test_timeout_terminates_and_reaps_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.command([sys.executable, '-c',
                                'import os,time; open("pid","w").write(str(os.getpid())); time.sleep(30)'],
                               root, os.environ.copy(), root / 'timeout.log', 1)
            pid = int((root / 'pid').read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


if __name__ == '__main__':
    unittest.main()
