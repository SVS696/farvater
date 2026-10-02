import subprocess
import unittest
from unittest.mock import patch

from system_backup import package_versions


class PackageInventoryTests(unittest.TestCase):
    def capture(self, manager, output, returncode=0):
        with patch('system_backup.shutil.which', side_effect=lambda n: '/usr/bin/'+n if n==manager else None), patch('system_backup.subprocess.run', return_value=subprocess.CompletedProcess([],returncode,output,'')) as run:
            result=package_versions()
        return result,run.call_args.args[0]

    def test_rpm_host_does_not_require_dpkg(self):
        rows,command=self.capture('rpm','curl\t8.1-2.x86_64\n')
        self.assertEqual(rows,['curl\t8.1-2.x86_64'])
        self.assertEqual(command[0],'rpm')

    def test_pacman_inventory_keeps_metadata_contract(self):
        rows,command=self.capture('pacman','curl 8.1-2\npython 3.12.0-1\n')
        self.assertEqual(rows,['curl\t8.1-2','python\t3.12.0-1'])
        self.assertEqual(command,['pacman','-Q'])

    def test_dpkg_inventory_keeps_metadata_contract(self):
        rows,command=self.capture('dpkg-query','curl\t8.1-2\n')
        self.assertEqual(rows,['curl\t8.1-2'])
        self.assertEqual(command[0],'dpkg-query')

    def test_failed_native_inventory_is_not_empty_success(self):
        with self.assertRaises(ValueError):
            self.capture('rpm','',returncode=1)

    def test_unknown_manager_refuses_system_export(self):
        with patch('system_backup.shutil.which', return_value=None), patch('system_backup.subprocess.run') as run:
            with self.assertRaises(ValueError):package_versions()
            run.assert_not_called()


if __name__=='__main__':unittest.main()
