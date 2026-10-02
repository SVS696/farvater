"""One reproducible private package: policy, native config and mode manifest.

The server rebuilds the native config with the existing compiler before applying
it. A set of matching caller-supplied hashes is not sufficient validation.
"""
import copy
import hashlib
import json
from pathlib import Path

from candidate_config import build_candidate_config

NAMES = ('applied-policy.json', 'policy-manifest.json', 'config.json')
OPTION_NAMES = {'default_filtering','source_identity','filtered_resolvers','additional_dns','pair_probes','adguard_adapter','lan_adapter','vpn_adapter'}
MAX_FILE_BYTES = 32 * 1024 * 1024


def encode(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build_bundle(policy, *, api_secret, options=None):
    # Mapping order has no policy semantics; native entry lists must nevertheless
    # reproduce byte-for-byte after the canonical policy JSON has been read back.
    policy=json.loads(encode(policy))
    options=copy.deepcopy(options or {'default_filtering':False})
    if set(options)-OPTION_NAMES or type(options.get('default_filtering')) is not bool:
        raise ValueError('Invalid bundle build options')
    if 'source_identity' in options and type(options['source_identity']) is not bool:
        raise ValueError('Invalid source identity option')
    built=build_candidate_config(policy,api_secret=api_secret,dns_port=5301,proxy_port=2081,api_port=9091,**options)
    policy_canonical_sha=sha(json.dumps(policy,sort_keys=True).encode())
    policy_bytes=encode(policy)
    built['config']['experimental']['cache_file']={
        'enabled':True,'path':'/var/lib/okopy-candidate/cache.db',
        'cache_id':'general-'+policy_canonical_sha[:16],'store_fakeip':True}
    config=encode(built['config'])
    manifest={'bundle_version':1,'policy_sha256':sha(policy_bytes),'policy_canonical_sha256':policy_canonical_sha,'config_sha256':sha(config),
        'build_options':options,'modes':built['modes'],'queues':built['queues']}
    if 'probes' in built:
        manifest['probes']=built['probes'];manifest['unconfigured_probe_queues']=built['unconfigured_probe_queues']
    if 'adguard' in built:manifest['adguard']=built['adguard']
    if 'unmapping' in built:manifest['unmapping']=built['unmapping']
    files={'applied-policy.json':policy_bytes,'policy-manifest.json':encode(manifest),'config.json':config}
    if any(len(data)>MAX_FILE_BYTES for data in files.values()):raise ValueError('Bundle file too large')
    return files


def validate_bundle(files):
    if not isinstance(files,dict) or set(files)!=set(NAMES):raise ValueError('Bundle requires exactly three files')
    if any(not isinstance(data,bytes) or len(data)>MAX_FILE_BYTES for data in files.values()):
        raise ValueError('Invalid bundle file')
    policy=json.loads(files['applied-policy.json']);config=json.loads(files['config.json'])
    manifest=json.loads(files['policy-manifest.json'])
    expected=build_bundle(policy,api_secret=config['experimental']['clash_api']['secret'],options=manifest['build_options'])
    if files!=expected:raise ValueError('Bundle differs from the policy compiler output')
    return manifest


def read_bundle(directory):
    root=Path(directory);files={}
    for name in NAMES:
        with (root/name).open('rb') as stream:files[name]=stream.read(MAX_FILE_BYTES+1)
    return files
