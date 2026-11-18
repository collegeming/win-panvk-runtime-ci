"""Offline candidate-manifest checks: no device, NDK, or network."""
import copy
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # keep the worktree clean under python3 -I
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_manifest import compile_manifest

HERE = Path(__file__).resolve().parent
BASE = json.loads((HERE.parent / 'production' / 'win-panvk.manifest.json').read_text(encoding='utf-8'))
BASE.pop('candidates', None)  # tests are independent of enrolled diagnostic entries
SHA = 'a' * 64
DIAG = '/data/data/cn.classfun.droidvm/files/runtimes/win-panvk-diag-v1/bin/crosvm'


def candidate(**overrides):
    entry = {'profile': 'win-panvk-v1', 'id': 'win-panvk-diag-v1', 'path': DIAG, 'sha256': SHA, 'enabled': True}
    entry.update(overrides)
    return entry


def output(candidates=None):
    data = copy.deepcopy(BASE)
    if candidates is None:
        data.pop('candidates', None)
    else:
        data['candidates'] = candidates
    return compile_manifest(data)


def refused(entry):
    try:
        output([entry])
    except AssertionError:
        return
    raise AssertionError('accepted invalid candidate: %r' % (entry,))


def main():
    absent = output()
    assert output([]) == absent, 'empty candidates must equal missing key'
    assert '#define CANDIDATE_COUNT 0' in absent
    enabled = output([candidate()])
    prefix = absent.split('static const struct Candidate')[0]
    assert enabled.startswith(prefix), 'profile/file/env tables must be byte-identical'
    assert '{"win-panvk-v1","win-panvk-diag-v1","%s","%s",1}' % (DIAG, SHA) in enabled
    assert '#define CANDIDATE_COUNT 1' in enabled
    assert output([candidate()]) == enabled, 'generator must be deterministic'
    refused(candidate(id=''))
    refused(candidate(profile='missing-v1'))
    refused(candidate(sha256='A' * 64))
    refused(candidate(sha256='abc'))
    refused(candidate(path='runtimes/win-panvk-diag-v1/bin/crosvm'))
    refused(candidate(path='/data/data/cn.classfun.droidvm/files/runtimes/win-panvk-diag-v1/bin/../crosvm'))
    refused(candidate(path='/data/data/cn.classfun.droidvm/files/runtimes/panvk-v1/bin/crosvm'))
    refused(candidate(path='/data/data/cn.classfun.droidvm/files/runtimes/panvk-v1/lib/crosvm'))
    refused(candidate(path='/data/data/cn.classfun.droidvm/files/runtimes/gfxstream-v1/lib/crosvm'))
    refused(candidate(enabled=1))
    try:
        output([candidate(), candidate(profile='panvk-v1')])
    except AssertionError:
        pass
    else:
        raise AssertionError('accepted duplicate candidate id')
    print('candidate manifest self-test: OK')


if __name__ == '__main__':
    main()
