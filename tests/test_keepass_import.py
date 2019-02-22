import argparse
from vault_keepass_import import main
import hvac
import mock
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
    assert results == {
        'keepass/A_B_C_D_E_F_G_éà': state,
        'keepass/Group1/title1group1': state,
        'keepass/Group1/Group1a/title1group1a': state,
        'keepass/withattachment': state,
        'keepass/title1 (TJxu0nxlyEuaKYNYpi0NPQ==)': state,
        'keepass/title1 (kFl/iRsoVUWDUdmmCDXwJg==)': state,
        'keepass/Trailing whitespace1/Trailing whitespace2/Trailing whitespace3': state,
    }


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


def test_get_path():
    prefix = 'PREFIX/'  # guaranteed to end with a / by the Importer constructor
    entry = mock.MagicMock()
    entry.title = 'TITLE'
    entry.parentgroup.path = 'GROUP'
    assert main.Importer.get_path(prefix, entry) == 'PREFIX/GROUP/TITLE'
    entry.parentgroup.path = '/'
    assert main.Importer.get_path(prefix, entry) == 'PREFIX/TITLE'
    entry.title = '|'.join(["-{:02x}-{}".format(i, chr(i)) for i in range(128)])
    expected = ('PREFIX/'
                '-00-_|-01-_|-02-_|-03-_|-04-_|-05-_|-06-_|-07-_|'
                '-08-_|-09-_|-0a-_|-0b-_|-0c-_|-0d-_|-0e-_|-0f-_|'
                '-10-_|-11-_|-12-_|-13-_|-14-_|-15-_|-16-_|-17-_|'
                '-18-_|-19-_|-1a-_|-1b-_|-1c-_|-1d-_|-1e-_|-1f-_|'
                '-20- |-21-!|-22-"|-23-_|-24-$|-25-_|-26-&|-27-\'|'
                '-28-_|-29-)|-2a-_|-2b-_|-2c-,|-2d--|-2e-.|-2f-/|'
                '-30-0|-31-1|-32-2|-33-3|-34-4|-35-5|-36-6|-37-7|'
                '-38-8|-39-9|-3a-:|-3b-;|-3c-<|-3d-=|-3e->|-3f-?|'
                '-40-@|-41-A|-42-B|-43-C|-44-D|-45-E|-46-F|-47-G|'
                '-48-H|-49-I|-4a-J|-4b-K|-4c-L|-4d-M|-4e-N|-4f-O|'
                '-50-P|-51-Q|-52-R|-53-S|-54-T|-55-U|-56-V|-57-W|'
                '-58-X|-59-Y|-5a-Z|-5b-_|-5c-_|-5d-]|-5e-^|-5f-_|'
                '-60-`|-61-a|-62-b|-63-c|-64-d|-65-e|-66-f|-67-g|'
                '-68-h|-69-i|-6a-j|-6b-k|-6c-l|-6d-m|-6e-n|-6f-o|'
                '-70-p|-71-q|-72-r|-73-s|-74-t|-75-u|-76-v|-77-w|'
                '-78-x|-79-y|-7a-z|-7b-{|-7c-||-7d-}|-7e-~|-7f-_')
    assert main.Importer.get_path(prefix, entry) == expected
    entry.title = 'éà'
    assert main.Importer.get_path(prefix, entry) == 'PREFIX/éà'
    entry.title = 'A B /C / D '
    assert main.Importer.get_path(prefix, entry) == 'PREFIX/A B/C/ D'


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
