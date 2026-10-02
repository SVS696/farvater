import tempfile
from pathlib import Path
import unittest
import system_backup as backup


class RecoveryScopeTests(unittest.TestCase):
 def test_expanded_scope_cannot_export_or_import_recovery_capsules(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   reserved=['var/lib/okopy-recovery/journal/rollback.py',
             'usr/local/lib/systemd/system/infrastructure-recovery-fixture.service',
             'usr/local/lib/systemd/system/app.service.d/90-infrastructure-recovery-fixture.conf']
   regular=['etc/vpn.conf','usr/local/lib/systemd/system/custom.service',
            'usr/local/lib/systemd/system/app.service.d/custom.conf']
   for name in reserved+regular:
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
   config={'trees':['etc','usr/local/lib','var/lib'],'required':['etc/vpn.conf']}
   selected=backup.selected_paths(config,root)
   for name in reserved:
    self.assertNotIn(name,selected);self.assertFalse(backup.covered(name,config))
   self.assertNotIn('var/lib/okopy-recovery',selected)
   for name in regular:
    self.assertIn(name,selected);self.assertTrue(backup.covered(name,config))

 def test_cannot_override_protection_by_declaring_capsule_required(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);p=root/'var/lib/okopy-recovery/state';p.parent.mkdir(parents=True);p.write_text('fixture')
   with self.assertRaises(ValueError):backup.selected_paths({'trees':['var/lib'],'required':['var/lib/okopy-recovery/state']},root)


if __name__=='__main__':unittest.main()
