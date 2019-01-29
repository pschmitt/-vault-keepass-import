from vault_keepass_import import main
import sh
import os
import pytest
import requests
import time


def test_export_to_vault_duplicates():
    token = 'mytoken'
    container = 'test-import-keepass'
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
    sh.docker('run', '-e', f'VAULT_DEV_ROOT_TOKEN_ID={token}', '-p', '8200:8200',
              '--rm', '--cap-add=IPC_LOCK', '-d', f'--name={container}', 'vault')

    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url='http://127.0.0.1:8200',
            vault_backend='keepass',
            vault_token=token)

    for _ in range(60):
        try:
            r0 = run_import()
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
    r1 = run_import()
    assert r1 == {'keepass/title1 (1)': 'changed',
                  'keepass/Group1/title1group1 (1)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (1)': 'changed',
                  'keepass/withattachement (1)': 'changed'}
    r2 = run_import()
    assert r2 == {'keepass/title1 (2)': 'changed',
                  'keepass/Group1/title1group1 (2)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (2)': 'changed',
                  'keepass/withattachement (2)': 'changed'}
    sh.docker('rm', '-f', container, _ok_code=[1, 0])


def test_export_to_vault_no_duplicates():
    token = 'mytoken'
    container = 'test-import-keepass'
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
    sh.docker('run', '-e', f'VAULT_DEV_ROOT_TOKEN_ID={token}', '-p', '8200:8200',
              '--rm', '--cap-add=IPC_LOCK', '-d', f'--name={container}', 'vault')

    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url='http://127.0.0.1:8200',
            vault_token=token,
            vault_backend='keepass',
            allow_duplicates=False)

    for _ in range(60):
        try:
            r1 = run_import()
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    assert r1 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
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
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=url,
            vault_backend='keepass',
            vault_token=token)

    for _ in range(60):
        try:
            r0 = run_import()
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
    main.reset_vault_backend(vault_url=url, vault_token=token, vault_backend='secrets')
    r1 = run_import()
    assert r1 == {'keepass/title1 (1)': 'changed',
                  'keepass/Group1/title1group1 (1)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (1)': 'changed',
                  'keepass/withattachement (1)': 'changed'}
    sh.docker('rm', '-f', container, _ok_code=[1, 0])


def test_client_cert(tmpdir):
    tmppath = str(tmpdir)
    opensslconfig = tmppath + '/opensslconfig'
    open(opensslconfig, 'w').write("""
        [ req ]
        default_bits           = 2048
        default_keyfile        = keyfile.pem
        distinguished_name     = req_distinguished_name
        attributes             = req_attributes
        prompt                 = no
        output_password        = mypass

        [ req_distinguished_name ]
        C                      = GB
        ST                     = Test State or Province
        L                      = Test Locality
        O                      = Organization Name
        OU                     = Organizational Unit Name
        CN                     = Common Name
        emailAddress           = test@email.address

        [ req_attributes ]
        challengePassword              = A challenge password
    """)
    sh.openssl.req(
        '-config', opensslconfig,
        '-nodes', '-new', '-x509', '-keyout', 'server.key', '-out', 'server.crt',
        _cwd=tmppath)
    os.chmod(tmppath + '/server.key', 0o644)
    config = tmppath + '/config.hcl'
    open(config, 'w').write("""
    listener tcp {
       address     = "0.0.0.0:8300"

       tls_cert_file                      = "/etc/test_ssl/server.crt"
       tls_key_file                       = "/etc/test_ssl/server.key"
       tls_client_ca_file                 = "/etc/test_ssl/server.crt"
       tls_require_and_verify_client_cert = true
    }
    """)
    token = 'mytoken'
    container = 'test-import-keepass'
    sh.docker('rm', '-f', container, _ok_code=[1, 0])
    sh.docker('run', '-e', f'VAULT_DEV_ROOT_TOKEN_ID={token}', '-p', '8200:8200',
              '-p', '8300:8300',
              '-v', f'{config}:/vault/config/config.hcl',
              '-v', f'{tmppath}:/etc/test_ssl',
              '-d',
              '--rm', '--cap-add=IPC_LOCK', f'--name={container}', 'vault')

    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url='https://127.0.0.1:8300',
            vault_backend='keepass',
            vault_token=token,
            ssl_verify=False,
            cert=(tmppath + '/server.crt', tmppath + '/server.key'))

    for _ in range(60):
        try:
            r0 = run_import()
            break
        except requests.exceptions.ConnectionError as e:
            print(str(e))
            time.sleep(1)
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}

    with pytest.raises(requests.exceptions.SSLError):
        main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url='https://127.0.0.1:8300',
            vault_backend='keepass',
            vault_token=token,
            ssl_verify=False)

    sh.docker('rm', '-f', container, _ok_code=[1, 0])
