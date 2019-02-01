from vault_keepass_import import main
import hvac
import pytest
import requests
import base64


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
        vault_prefix='keepass/',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r1 = importer.export_to_vault()
    assert r1 == {'keepass/title1': 'new',
                  'keepass/Group1/title1group1': 'new',
                  'keepass/Group1/Group1a/title1group1a': 'new',
                  'keepass/withattachment': 'new'}
    verify_withattachment(vault_server, '2')


def test_export_to_vault_dry_run(vault_server):
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_prefix='keepass/',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False,
        dry_run=True)

    r1 = importer.export_to_vault()
    assert r1 == {'keepass/title1': 'new',
                  'keepass/Group1/title1group1': 'new',
                  'keepass/Group1/Group1a/title1group1a': 'new',
                  'keepass/withattachment': 'new'}
    r2 = importer.export_to_vault()
    assert r2 == {'keepass/title1': 'new',
                  'keepass/Group1/title1group1': 'new',
                  'keepass/Group1/Group1a/title1group1a': 'new',
                  'keepass/withattachment': 'new'}


def test_export_to_vault(vault_server):
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_prefix='keepass/',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r0 = importer.export_to_vault()
    assert r0 == {'keepass/title1': 'new',
                  'keepass/Group1/title1group1': 'new',
                  'keepass/Group1/Group1a/title1group1a': 'new',
                  'keepass/withattachment': 'new'}
    r1 = importer.export_to_vault()
    # converged
    r2 = importer.export_to_vault()
    assert all(map(lambda x: x == 'ok', r2.values()))
    assert r1.keys() == r2.keys()
    # idempotent
    r3 = importer.export_to_vault()
    assert r2 == r3


def test_erase(vault_server):
    prefix = 'keepass/'
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_prefix=prefix,
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)
    importer.set_verbosity(True)

    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    importer.export_to_vault()
    keys = client.secrets.kv.v2.list_secrets(prefix)['data']['keys']
    assert 'Group1/' in keys
    assert 'withattachment' in keys
    importer.erase(importer.prefix)
    with pytest.raises(hvac.exceptions.InvalidPath):
        client.secrets.kv.v2.list_secrets(prefix)


def test_client_cert(vault_server):
    kwargs = dict(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['https'],
        vault_prefix='keepass/',
        vault_token=vault_server['token'],
    )

    # SUCCESS with CA and client certificate provided
    r0 = main.Importer(
            verify=vault_server['crt'],
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        ).export_to_vault()
    assert r0 == {'keepass/title1': 'new',
                  'keepass/Group1/title1group1': 'new',
                  'keepass/Group1/Group1a/title1group1a': 'new',
                  'keepass/withattachment': 'new'}

    # SUCCESS with CA missing but verify False  and client certificate provided
    r0 = main.Importer(
            verify=False,
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        ).export_to_vault()
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
        ).export_to_vault()

    # FAILURE with missing CA
    with pytest.raises(requests.exceptions.SSLError):
        main.Importer(
            verify=True,
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        ).export_to_vault()


def switch_to_kv_v1(vault_server):
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    client.sys.disable_secrets_engine(path='secret/')
    client.sys.enable_secrets_engine(backend_type='kv', options={'version': '1'}, path='secret/')


def test_kv_v1(vault_server):
    switch_to_kv_v1(vault_server)

    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_prefix='keepass/',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    r0 = importer.export_to_vault()
    assert 'keepass/title1' in r0
    verify_withattachment(vault_server, '1')


def test_export_info():
    assert main.Importer.export_info('ok', 'PATH', {}, {}) == 'ok: PATH'
    assert main.Importer.export_info('changed', 'PATH', {
        'removed1': 'v1',
        'removed2': 'v2',
        'identical': 'v3',
        'different': 'K1',
    }, {
        'identical': 'v3',
        'different': 'K2',
        'added1': 'v4',
        'added2': 'v4',
    }) == 'changed: PATH added added1 added2, removed removed1 removed2, changed different'
