import json
import unittest

from candidate_bundle import build_bundle,validate_bundle,encode,sha
import test_candidate_config as fixtures


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.policy=fixtures.CandidateConfigTests().base()
        self.files=build_bundle(self.policy,api_secret='x'*32)

    def test_generated_files_validate_and_hashes_bind_exact_bytes(self):
        meta=validate_bundle(self.files)
        self.assertEqual(meta['config_sha256'],sha(self.files['config.json']))
        self.assertEqual(meta['policy_sha256'],sha(self.files['applied-policy.json']))
        self.assertEqual(json.loads(self.files['applied-policy.json']),self.policy)

    def test_config_and_hash_tampering_are_rejected_even_when_hashes_agree(self):
        config=json.loads(self.files['config.json']);config['dns']['final']='isp'
        files=dict(self.files);files['config.json']=encode(config)
        meta=json.loads(files['policy-manifest.json']);meta['config_sha256']=sha(files['config.json'])
        files['policy-manifest.json']=encode(meta)
        with self.assertRaises(ValueError):validate_bundle(files)

    def test_stale_policy_or_manifest_blocks_package(self):
        for name in ('applied-policy.json','policy-manifest.json'):
            files=dict(self.files);value=json.loads(files[name])
            if name=='applied-policy.json':value['profiles'][0]['name']='changed policy'
            else:value['modes'][0]['pairs']['default']['exit']='wrong'
            files[name]=encode(value)
            with self.subTest(name=name),self.assertRaises(ValueError):validate_bundle(files)

    def test_bundle_cannot_change_listener_ports_or_add_build_options(self):
        with self.assertRaises(ValueError):
            build_bundle(self.policy,api_secret='x'*32,options={'default_filtering':False,'dns_port':53})
        files=dict(self.files);files['extra.json']=b'{}'
        with self.assertRaises(ValueError):validate_bundle(files)
