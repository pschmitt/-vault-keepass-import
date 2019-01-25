import keepass_import
import sh
import requests
import time


def test_export_to_vault_duplicates():
    token = 'mytoken'
    container = 'test-import-keepass'
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
    sh.docker('run', '-e', f'VAULT_DEV_ROOT_TOKEN_ID={token}', '-p', '8200:8200',
              '--rm', '--cap-add=IPC_LOCK', '-d', f'--name={container}', 'vault')

    def run_import():
        return keepass_import.export_to_vault(
            keepass_db='test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url='http://127.0.0.1:8200',
            vault_token=token)

    for _ in range(60):
        try:
            r0 = run_import()
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    assert r0 == {'title1': 'changed',
                  'Group1/title1group1': 'changed',
                  'Group1/Group1a/title1group1a': 'changed'}
    r1 = run_import()
    assert r1 == {'title1 (1)': 'changed',
                  'Group1/title1group1 (1)': 'changed',
                  'Group1/Group1a/title1group1a (1)': 'changed'}
    r2 = run_import()
    assert r2 == {'title1 (2)': 'changed',
                  'Group1/title1group1 (2)': 'changed',
                  'Group1/Group1a/title1group1a (2)': 'changed'}
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
    for _ in range(60):
        try:
            r = keepass_import.export_to_vault(
                keepass_db='test_db.kdbx',
                keepass_password='master1',
                keepass_keyfile=None,
                vault_url='http://127.0.0.1:8200',
                vault_token=token,
                vault_backend='keepass')
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
    assert r['data']['version'] == 1
    assert r['warnings'] is None
