import hvac
import os
import pytest
import requests
import sh
import time


@pytest.fixture
def vault_server(tmpdir):
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
        CN                     = 127.0.0.1
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
    sh.docker('run', '-e', f'VAULT_DEV_ROOT_TOKEN_ID={token}',
              '-p', '8200:8200',
              '-p', '8300:8300',
              '-v', f'{config}:/vault/config/config.hcl',
              '-v', f'{tmppath}:/etc/test_ssl',
              '-d',
              '--rm', '--cap-add=IPC_LOCK', f'--name={container}', 'vault')
    crt = tmppath + '/server.crt'
    key = tmppath + '/server.key'

    client = hvac.Client(
        url='http://127.0.0.1:8200', token=token, cert=(crt, key), verify=False
    )
    for _ in range(60):
        try:
            client.sys.read_health_status()
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)

    client.sys.read_health_status()

    yield {
        'token': token,
        'http': 'http://127.0.0.1:8200',
        'https': 'https://127.0.0.1:8300',
        'crt': crt,
        'key': key,
    }

    sh.docker('rm', '-f', container, _ok_code=[1, 0])
