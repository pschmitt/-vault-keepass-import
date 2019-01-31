from vault_keepass_import import main
import hvac
import pytest
import requests
import base64


def test_export_to_vault_duplicates(vault_server):
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_backend='keepass',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r0 = importer.export_to_vault()
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachment': 'changed'}
    r1 = importer.export_to_vault()
    assert r1 == {'keepass/title1 (1)': 'changed',
                  'keepass/Group1/title1group1 (1)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (1)': 'changed',
                  'keepass/withattachment (1)': 'changed'}
    r2 = importer.export_to_vault()
    assert r2 == {'keepass/title1 (2)': 'changed',
                  'keepass/Group1/title1group1 (2)': 'changed',
                  'keepass/Group1/Group1a/title1group1a (2)': 'changed',
                  'keepass/withattachment (2)': 'changed'}


def verify_withattachment(vault_server, kv_version):
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    if kv_version == '2':
        entry = client.secrets.kv.v2.read_secret_version(
            'keepass/withattachment')['data']['data']
    else:
        entry = client.secrets.kv.v1.read_secret(
            'keepass/withattachment')['data']
    assert entry['0/attached.txt'] == base64.b64encode(
        "CONTENT\n".encode('ascii')).decode('ascii')
    assert entry['custom_property1'] == 'custom_value1'
    assert entry['notes'] == 'note2'
    assert entry['password'] == 'password2'
    assert entry['url'] == 'url2'
    assert entry['username'] == 'user2'
    assert 'Notes' not in entry


def test_export_to_vault_imports_expected_fields(vault_server):
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_backend='keepass',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r1 = importer.export_to_vault()
    assert r1 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachment': 'changed'}
    verify_withattachment(vault_server, '2')


def test_export_to_vault_no_duplicates(vault_server):
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_backend='keepass',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r0 = importer.export_to_vault()
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachment': 'changed'}
    r1 = importer.export_to_vault(allow_duplicates=False)
    # converged
    r2 = importer.export_to_vault(allow_duplicates=False)
    assert all(map(lambda x: x == 'ok', r2.values()))
    assert r1.keys() == r2.keys()
    # idempotent
    r3 = importer.export_to_vault(allow_duplicates=False)
    assert r2 == r3


def test_export_to_vault_reset(vault_server):
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_backend='keepass',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r0 = importer.export_to_vault()
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachment': 'changed'}
    importer.reset_vault_secrets_engine(path='secret')
    r1 = importer.export_to_vault()
    assert r1 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachment': 'changed'}


def test_client_cert(vault_server):
    kwargs = dict(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['https'],
        vault_backend='keepass',
        vault_token=vault_server['token'],
    )

    # SUCCESS with CA and client certificate provided
    r0 = main.Importer(
            verify=vault_server['crt'],
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        ).export_to_vault(allow_duplicates=False)
    assert r0 == {'keepass/title1': 'changed',
                  'keepass/Group1/title1group1': 'changed',
                  'keepass/Group1/Group1a/title1group1a': 'changed',
                  'keepass/withattachment': 'changed'}

    # SUCCESS with CA missing but verify False  and client certificate provided
    r0 = main.Importer(
            verify=False,
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        ).export_to_vault(allow_duplicates=False)
    assert r0 == {'keepass/title1': 'ok',
                  'keepass/Group1/title1group1': 'ok',
                  'keepass/Group1/Group1a/title1group1a': 'ok',
                  'keepass/withattachment': 'ok'}

    # FAILURE with missing client certificate
    with pytest.raises(requests.exceptions.SSLError):
        main.Importer(
            verify=False,
            cert=(None, None),
            **kwargs,
        ).export_to_vault(allow_duplicates=False)

    # FAILURE with missing CA
    with pytest.raises(requests.exceptions.SSLError):
        main.Importer(
            verify=True,
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        ).export_to_vault(allow_duplicates=False)


def test_kv_v1(vault_server):
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    client.sys.disable_secrets_engine(path='secret')
    client.sys.enable_secrets_engine(backend_type='kv', options={'version': '1'}, path='secret')

    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_backend='keepass',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r0 = importer.export_to_vault()
    assert 'keepass/title1' in r0
    verify_withattachment(vault_server, '1')
