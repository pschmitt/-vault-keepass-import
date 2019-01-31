from vault_keepass_import import main
import hvac
import pytest
import requests
import base64


def test_export_to_vault_duplicates(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['http'],
            vault_backend='keepass',
            vault_token=vault_server['token'],
            cert=(None, None),
            verify=False,
        )

    r0 = run_import()
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


def test_export_to_vault_imports_expected_fields(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['http'],
            vault_backend='keepass',
            vault_token=vault_server['token'],
            cert=(None, None),
            verify=False,
            allow_duplicates=False)

    r1 = run_import()
    assert r1 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    withattachement = client.secrets.kv.v2.read_secret_version(
        'keepass/withattachement')['data']['data']
    assert withattachement['0/attached.txt'] == base64.b64encode(
        "CONTENT\n".encode('ascii')).decode('ascii')
    assert withattachement['custom_property1'] == 'custom_value1'
    assert withattachement['notes'] == 'note2'
    assert withattachement['password'] == 'password2'
    assert withattachement['url'] == 'url2'
    assert withattachement['username'] == 'user2'
    assert 'Notes' not in withattachement
    

def test_export_to_vault_no_duplicates(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['http'],
            vault_backend='keepass',
            vault_token=vault_server['token'],
            cert=(None, None),
            verify=False,
            allow_duplicates=False)

    r1 = run_import()
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


def test_export_to_vault_reset(vault_server):
    def run_import():
        return main.export_to_vault(
            keepass_db='tests/test_db.kdbx',
            keepass_password='master1',
            keepass_keyfile=None,
            vault_url=vault_server['http'],
            vault_backend='keepass',
            vault_token=vault_server['token'],
            cert=(None, None),
            verify=False,
        )

    r0 = run_import()
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}
    main.reset_vault_secrets_engine(url=vault_server['http'],
                                    token=vault_server['token'],
                                    path='secret',
                                    cert=(None, None),
                                    verify=False)
    r1 = run_import()
    assert r1 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}


def test_client_cert(vault_server):
    kwargs = dict(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['https'],
        vault_backend='keepass',
        vault_token=vault_server['token'],
        allow_duplicates=False,
    )

    # SUCCESS with CA and client certificate provided
    r0 = main.export_to_vault(
            verify=vault_server['crt'],
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        )
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachement': 'changed'}

    # SUCCESS with CA missing but verify False  and client certificate provided
    r0 = main.export_to_vault(
            verify=False,
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        )
    assert r0 == {'keepass/title1': 'ok',
                  'keepass/Group1/title1group1': 'ok',
                  'keepass/Group1/Group1a/title1group1a': 'ok',
                  'keepass/withattachement': 'ok'}

    # FAILURE with missing client certificate
    with pytest.raises(requests.exceptions.SSLError):
        main.export_to_vault(
            verify=False,
            cert=(None, None),
            **kwargs,
        )

    # FAILURE with missing CA
    with pytest.raises(requests.exceptions.SSLError):
        main.export_to_vault(
            verify=True,
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        )
