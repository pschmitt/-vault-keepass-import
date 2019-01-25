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


def test_export_to_vault_no_duplicates():
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
            vault_token=token,
            allow_duplicates=False)

    for _ in range(60):
        try:
            r1 = run_import()
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    assert r1 == {'title1': 'changed',
                  'Group1/title1group1': 'changed',
                  'Group1/Group1a/title1group1a': 'changed'}
    # converged
    r2 = run_import()
    assert all(map(lambda x: x == 'ok', r2.values()))
    assert r1.keys() == r2.keys()
    # idempotent
    r3 = run_import()
    assert r2 == r3
    sh.docker('rm', '-f', container, _ok_code=[1, 0])

def test_export_to_vault_reset():
    token = 'mytoken'
    container = 'test-import-keepass'
    url = 'http://127.0.0.1:8200'
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
    sh.docker('run', '-e', f'VAULT_DEV_ROOT_TOKEN_ID={token}', '-p', '8200:8200',
              '--rm', '--cap-add=IPC_LOCK', '-d', f'--name={container}', 'vault')

    def run_import():
        return keepass_import.export_to_vault(
            keepass_db='test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=url,
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
    keepass_import.reset_vault_backend(vault_url=url, vault_token=token, vault_backend='secrets')
    r1 = run_import()
    assert r1 == {'title1 (1)': 'changed',
                  'Group1/title1group1 (1)': 'changed',
                  'Group1/Group1a/title1group1a (1)': 'changed'}
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
