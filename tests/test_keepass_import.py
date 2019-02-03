import argparse
from vault_keepass_import import main
import hvac
import pytest
import requests
import base64
from tests.modified_environ import modified_environ


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


def verify_expected_secrets(results, state):
    assert results == {'keepass/Group1/title1group1': state,
                       'keepass/Group1/Group1a/title1group1a': state,
                       'keepass/withattachment': state,
                       'keepass/title1 (TJxu0nxlyEuaKYNYpi0NPQ==)': state,
                       'keepass/title1 (kFl/iRsoVUWDUdmmCDXwJg==)': state}


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

    verify_expected_secrets(importer.export_to_vault(), 'new')
    verify_withattachment(vault_server, '2')


def test_delete_less_qualified_path(vault_server):
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_prefix='keepass/',
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False)

    less_qualified = 'keepass/title1'
    importer.create_or_update_secret(less_qualified, {'something': 'else'})

    verify_expected_secrets(importer.export_to_vault(), 'new')
    verify_withattachment(vault_server, '2')

    with pytest.raises(hvac.exceptions.InvalidPath):
        importer.vault.secrets.kv.v2.read_secret_version(less_qualified)


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

    verify_expected_secrets(importer.export_to_vault(), 'new')
    verify_expected_secrets(importer.export_to_vault(), 'new')


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

    verify_expected_secrets(importer.export_to_vault(), 'new')
    verify_expected_secrets(importer.export_to_vault(), 'ok')


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
    verify_expected_secrets(r0, 'new')

    # SUCCESS with CA missing but verify False  and client certificate provided
    r0 = main.Importer(
            verify=False,
            cert=(vault_server['crt'], vault_server['key']),
            **kwargs,
        ).export_to_vault()
    verify_expected_secrets(r0, 'ok')

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

    verify_expected_secrets(importer.export_to_vault(), 'new')
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


@pytest.mark.parametrize("version", ['1', '2'])
def test_vault_secret_operators(vault_server, version):
    path = 'mysecrets'
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    client.sys.enable_secrets_engine(backend_type='kv', options={'version': version}, path=path)

    prefix = 'keepass/'
    importer = main.Importer(
        keepass_db='tests/test_db.kdbx',
        keepass_password='master1',
        keepass_keyfile=None,
        vault_url=vault_server['http'],
        vault_prefix=prefix,
        vault_token=vault_server['token'],
        cert=(None, None),
        verify=False,
        path=path)

    secret_key = prefix + 'my/key'
    secret_value = {'field': 'value'}
    importer.create_or_update_secret(secret_key, secret_value)
    assert importer.read_secret(secret_key) == secret_value
    importer.erase(prefix)
    with pytest.raises(hvac.exceptions.InvalidPath):
        importer.read_secret(secret_key)


def test_parser():
    parser = main.parser()
    assert type(parser) == argparse.ArgumentParser
    with pytest.raises(SystemExit):
        parser.parse_args(['--version'])


def test_parse_args(mocker):
    password_value = 'PASSWORD'
    token_value = 'TOKEN'
    with modified_environ(
            'VAULT_ADDR',
            'VAULT_SKIP_VERIFY',
            'VAULT_CACERT',
            'VAULT_CLIENT_CERT',
            'VAULT_CLIENT_KEY',
    ):
        (args, token, password, verify) = main.parse_args([
            'db.kdbx', '--password', password_value, '--token', token_value
        ])
        assert args.token == token_value
        assert args.password == password_value
        assert args.vault == main.DEFAULT_VAULT_ADDR
        assert args.ssl_no_verify is False
        assert args.ca_cert is None
        assert args.client_cert is None
        assert args.client_key is None
        assert verify is True

    addr = 'ADDR'
    skip_verify = 'yes'
    cacert = 'CACERT'
    client_cert = 'CLIENT_CERT'
    client_key = 'CLIENT_KEY'
    with modified_environ(
            VAULT_ADDR=addr,
            VAULT_SKIP_VERIFY=skip_verify,
            VAULT_CACERT=cacert,
            VAULT_CLIENT_CERT=client_cert,
            VAULT_CLIENT_KEY=client_key,
    ):
        (args, token, password, verify) = main.parse_args([
            'db.kdbx', '--password', password_value, '--token', token_value
        ])
        assert args.token == token_value
        assert args.password == password_value
        assert args.vault == addr
        assert args.ssl_no_verify is True
        assert args.ca_cert == cacert
        assert args.client_cert == client_cert
        assert args.client_key == client_key
        assert verify is False

    (args, token, password, verify) = main.parse_args([
        'db.kdbx', '--password', password_value, '--token', token_value,
        '--ca-cert', cacert
    ])
    assert args.ca_cert == cacert
    assert verify == cacert

    getpass = mocker.patch('getpass.getpass')
    (args, token, password, verify) = main.parse_args([
        'db.kdbx', '--token', token_value,
    ])
    getpass.assert_called_once_with('KeePass password: ')

    getpass = mocker.patch('getpass.getpass')
    (args, token, password, verify) = main.parse_args([
        'db.kdbx', '--password', password_value,
    ])
    getpass.assert_called_once_with('Vault token: ')
