"""Compile reviewed JSON into constants; never load user-selected paths at runtime."""
import json
import re
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent

def compile_manifest(data):
    assert data['schema'] == 1
    profiles = data['profiles']
    allowed = {'gfxstream-v1', 'panvk-v1', 'win-panvk-v1'}
    assert {p['id'] for p in profiles} <= allowed
    assert len({p['uuid'] for p in profiles}) == len(profiles)
    assert len({(p['disk']['dev'], p['disk']['ino']) for p in profiles}) == len(profiles)
    q = lambda s: json.dumps(s, ensure_ascii=False)
    rows = []
    files = []
    envs = []
    for p in profiles:
        assert p['disk']['backing'] is None
        assert p['disk']['format'] in ('raw', 'qcow2')
        assert not p['enabled'] or not p['blocked_by']
        paths = [p['runtime']]
        for key in ('kernel', 'initrd', 'firmware'):
            if p.get(key):
                paths.append(p[key])
        paths += p['libraries']
        for f in paths:
            assert f['path'].startswith('/') and not any(c in f['path'] for c in '\n,')
            assert '..' not in f['path'].split('/')
            assert re.fullmatch('[0-9a-f]{64}', f['sha256'])
        run = '/data/data/cn.classfun.droidvm/run/'
        socket = run + p['display_name'] + '.sock'
        assert len(socket.encode()) < 108
        ident = p['uuid']
        service = f'name=droidvm_disp_{ident}_gpu-0,screen=gpu-0'
        def path_or_null(key):
            return q(p[key]['path']) if p.get(key) else '0'
        rows.append('{' + ','.join([q(p['id']), q(p['uuid']), q(p['disk']['path']), q(p['disk']['backend_path']), str(p['disk']['dev']), str(p['disk']['ino']), path_or_null('kernel'), path_or_null('initrd'), path_or_null('firmware'), q(socket), q(service), q(p['runtime']['path']), q(p['library_path']), str(int(p['enabled'])), str(len(files)), str(len(paths)), str(len(envs)), str(len(p['environment']))]) + '}')
        files.extend('{' + q(f['path']) + ',' + q(f['sha256']) + '}' for f in paths)
        envs.extend('{' + q(k) + ',' + q(v) + '}' for k, v in p['environment'].items())
    # Candidate binaries are opt-in diagnostics: same validation discipline as
    # profile files, but they must live outside every profile runtime tree.
    by_id = {p['id']: p for p in profiles}
    runtime_paths = {p['runtime']['path'] for p in profiles}
    runtime_roots = {str(PurePosixPath(p['runtime']['path']).parent.parent) for p in profiles}
    candidate_ids = set()
    candidate_rows = []
    for c in data.get('candidates', []):
        assert c['profile'] in by_id
        assert c['id'] and c['id'] not in candidate_ids
        candidate_ids.add(c['id'])
        assert isinstance(c['enabled'], bool)
        assert re.fullmatch('[0-9a-f]{64}', c['sha256'])
        assert c['path'].startswith('/') and not any(ch in c['path'] for ch in '\n,')
        assert not c['path'].startswith('//')  # POSIX keeps "//" as a distinct root
        assert '..' not in c['path'].split('/')
        assert c['path'] not in runtime_paths
        path = PurePosixPath(c['path'])
        own_root = PurePosixPath(by_id[c['profile']]['runtime']['path']).parent.parent
        assert path != own_root and own_root not in path.parents
        assert all(PurePosixPath(root) not in path.parents for root in runtime_roots)
        candidate_rows.append('{' + ','.join([q(c['profile']), q(c['id']), q(c['path']), q(c['sha256']), str(int(c['enabled']))]) + '}')
    return ('static const struct Profile profiles[] = {' + ',\n'.join(rows) + '};\n'
            + 'static const struct FileHash files[] = {' + ',\n'.join(files) + '};\n'
            + 'static const struct Env envs[] = {' + ',\n'.join(envs) + '};\n'
            + '#define GUARD ' + q(data['guard']) + '\n'
            + '#define STOCK ' + q(data['stock']['path']) + '\n'
            + '#define STOCK_HASH ' + q(data['stock']['sha256']) + '\n'
            + '#define PROBE_NONCE ' + q(data.get('test_only_probe_nonce', '')) + '\n'
            + 'static const struct Candidate candidates[] = {' + (',\n'.join(candidate_rows) if candidate_rows else '{0,0,0,0,0}') + '};\n'
            + '#define CANDIDATE_COUNT ' + str(len(candidate_rows)) + '\n')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, default=ROOT / 'manifest.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'manifest.inc')
    opts = parser.parse_args()
    opts.output.write_text(compile_manifest(json.loads(opts.manifest.read_text(encoding='utf-8'))), encoding='utf-8')
