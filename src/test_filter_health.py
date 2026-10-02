import subprocess
import copy
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from health_collect import probe


class FilterHealthTests(unittest.TestCase):
    check={'kind':'dns_filter','blocked_domain':'blocked.test','allowed_domain':'allowed.test',
           'filtered':{'server':'127.0.0.1','port':53},
           'unfiltered':{'server':'127.0.0.1','port':5300}}

    def verify(self,reference,blocked,allowed,expected,code=0):
        def reply(args,timeout):
            self.assertEqual(timeout,4)
            body=(reference if args[args.index('-p')+1]=='5300' else
                  (allowed if args[-2]=='allowed.test' else blocked))
            return subprocess.CompletedProcess(args,code,body,'private-stderr')
        with patch('health_collect.run',side_effect=reply):
            status,detail=probe(self.check)
        self.assertEqual(status,expected);self.assertNotIn('private-stderr',detail)

    good=';; status: NOERROR\nname. 60 IN A 93.184.216.34'
    zero=';; status: NOERROR\nname. 60 IN A 0.0.0.0'
    nx=';; status: NXDOMAIN'

    def test_both_supported_blocks_require_working_reference_and_allowed_name(self):
        for block in (self.zero,self.nx):
            self.verify(self.good,block,self.good,'up')

    def test_reference_failure_and_upstream_block_are_unknown(self):
        for reference in (self.nx,self.zero,';; status: SERVFAIL',
                          ';; status: NOERROR\nname. 60 IN A 10.0.0.1'):
            self.verify(reference,self.nx,self.good,'unknown')

    def test_allowed_name_failure_and_removed_block_are_down(self):
        for allowed in (self.nx,self.zero,';; status: SERVFAIL'):
            self.verify(self.good,self.nx,allowed,'down')
        for blocked in (self.good,';; status: SERVFAIL',';; status: REFUSED',
                        ';; status: NOERROR',self.zero+'\nname. 60 IN A 93.184.216.34'):
            self.verify(self.good,blocked,self.good,'down')

    def test_malformed_output_and_collector_failure_never_pass(self):
        for bad in ('malformed',self.nx+'\n;; status: NOERROR',
                    ';; status: NOERROR\nname. 60 IN A not-an-ip'):
            self.verify(self.good,bad,self.good,'unknown')
        self.verify(self.good,self.nx,self.good,'unknown',code=-6)

    def test_config_change_before_and_during_measurement_invalidates_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config';path.write_bytes(b'original')
            check=copy.deepcopy(self.check)
            check['config_binding']={'path':str(path),'sha256':hashlib.sha256(b'original').hexdigest()}
            path.write_bytes(b'changed')
            with patch('health_collect.run') as run:
                self.assertEqual(probe(check)[0],'unknown');run.assert_not_called()
            path.write_bytes(b'original')
            def reply(args,timeout):
                path.write_bytes(b'changed')
                body=self.nx if args[-2]=='blocked.test' and args[args.index('-p')+1]=='53' else self.good
                return subprocess.CompletedProcess(args,0,body,'')
            with patch('health_collect.run',side_effect=reply):
                self.assertEqual(probe(check)[0],'unknown')


if __name__=='__main__':unittest.main()
