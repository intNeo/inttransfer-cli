import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from getpass import getpass
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit

try:
    import requests
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit('Установите зависимости: python -m pip install requests cryptography')

VERSION = '1.0.0'
CHUNK = 4 * 1024 * 1024


class ClientError(Exception):
    pass


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(text):
    return base64.b64decode(text, validate=True)


def digest(data):
    return b64(hashlib.sha256(data).digest())


def pack(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def seal(key, plaintext, aad):
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, plaintext, aad.encode('utf-8'))


def unseal(key, encrypted, aad):
    if len(encrypted) < 28:
        raise ClientError('Повреждённый зашифрованный блок')
    return AESGCM(key).decrypt(encrypted[:12], encrypted[12:], aad.encode('utf-8'))


def password_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000, 32)


def make_fragment(key, password, context):
    value = {'v': 1, 'context': context}
    if password:
        salt = secrets.token_bytes(16)
        value.update(salt=b64(salt), wrapped=b64(seal(password_key(password, salt), key, 'inttransfer-key-v1:' + context)))
    else:
        value['key'] = b64(key)
    return b64(pack(value))


def parse_fragment(fragment):
    try:
        value = json.loads(unb64(fragment))
        if value['v'] != 1 or len(unb64(value['context'])) != 32:
            raise ValueError()
        return value
    except (ValueError, KeyError, TypeError):
        raise ClientError('Неверный формат ключа в ссылке') from None


def unwrap_fragment(value, password):
    try:
        if 'wrapped' in value:
            salt = unb64(value['salt'])
            if len(salt) != 16:
                raise ValueError()
            key = unseal(password_key(password, salt), unb64(value['wrapped']), 'inttransfer-key-v1:' + value['context'])
        else:
            key = unb64(value['key'])
        if len(key) != 32:
            raise ValueError()
        return key
    except (InvalidTag, KeyError, TypeError, ValueError):
        raise ClientError('Неверный пароль или повреждённая ссылка') from None


def validate_time(text):
    match = re.fullmatch(r'([0-9]+)([hd])', text.strip().lower())
    if not match:
        raise ClientError('Срок: 1h–168h или 1d–7d (например, 6h, 1d)')
    hours = int(match[1]) * (24 if match[2] == 'd' else 1)
    if not 1 <= hours <= 168:
        raise ClientError('Срок хранения должен быть от 1 часа до 7 дней')
    return hours


def normalize_server(text):
    parsed = urlsplit(text)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password:
        raise ClientError('Укажите адрес сервера: https://transfer.example.com')
    if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ClientError('--server должен содержать только адрес сервера, без пути')
    return f'{parsed.scheme}://{parsed.netloc}'


def download_input(text, server=None, fragment=None):
    parsed = urlsplit(text)
    if parsed.scheme:
        base = normalize_server(f'{parsed.scheme}://{parsed.netloc}')
        match = re.fullmatch(r'/d/([A-Za-z0-9_-]+)', parsed.path)
        if not match or parsed.query:
            raise ClientError('Нужна новая ссылка вида https://server/d/ID#КЛЮЧ')
        file_id = match[1]
        fragment = unquote(parsed.fragment) or fragment
        if server and normalize_server(server) != base:
            raise ClientError('--server не совпадает с сервером в ссылке')
    else:
        if not server or not re.fullmatch(r'[A-Za-z0-9_-]+', text):
            raise ClientError('Укажите полную ссылку или ID вместе с --server и --key')
        base, file_id = normalize_server(server), text
    if not fragment:
        raise ClientError('Одного ID недостаточно: нужен ключ после # в полной ссылке или --key')
    return base, file_id, fragment


class API:
    def __init__(self, server, insecure=False, allow_http=False, retries=5):
        self.server = normalize_server(server)
        parsed = urlsplit(self.server)
        if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1') and not allow_http:
            raise ClientError('Используйте HTTPS. Для явного разрешения HTTP укажите --allow-http')
        self.verify = not insecure
        self.retries = retries
        self.session = requests.Session()
        self.session.headers['User-Agent'] = f'intTransfer-CLI/{VERSION} Python/{sys.version_info.major}.{sys.version_info.minor}'

    def request(self, method, path, token=None, **kwargs):
        headers = {'Authorization': 'Bearer ' + token} if token else {}
        for attempt in range(self.retries + 1):
            try:
                response = self.session.request(method, self.server + path, headers=headers,
                                                verify=self.verify, timeout=(15, 120), allow_redirects=False, **kwargs)
                if 200 <= response.status_code < 300:
                    return response
                try:
                    message = response.json().get('error', f'HTTP {response.status_code}')
                except (ValueError, AttributeError):
                    message = f'HTTP {response.status_code}'
                if 300 <= response.status_code < 400:
                    raise ClientError('Сервер перенаправляет запрос. Укажите конечный HTTPS-адрес')
                retry = response.status_code == 429 or (response.status_code >= 500 and response.status_code != 507)
                response.close()
                if not retry:
                    raise ClientError(str(message))
            except requests.exceptions.SSLError:
                raise ClientError('Ошибка TLS-сертификата. Проверьте сертификат сервера и системное время') from None
            except requests.RequestException:
                message = 'Соединение прервано или сервер недоступен'
            if attempt == self.retries:
                raise ClientError(f'{message}. Повторите ту же команду для продолжения')
            delay = min(2 ** attempt, 15)
            print(f'Повтор {attempt + 1}/{self.retries} через {delay} с…', file=sys.stderr)
            time.sleep(delay)

    def json(self, method, path, **kwargs):
        with self.request(method, path, **kwargs) as response:
            try:
                return response.json()
            except ValueError:
                raise ClientError('Сервер вернул некорректный JSON') from None


def state_path(action, identity, custom=None):
    if custom:
        return Path(custom).expanduser().resolve()
    root = Path.home() / '.cache' / 'inttransfer-cli'
    return root / (action + '-' + hashlib.sha256(identity.encode()).hexdigest()[:32] + '.json')


def save_state(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.inttransfer-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            target.write(pack(value))
            target.flush()
            os.fsync(target.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_state(path):
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if value.get('v') != 1:
            raise ValueError()
        return value
    except (ValueError, TypeError, AttributeError):
        raise ClientError(f'Повреждён файл состояния: {path}. Сохраните его перед восстановлением') from None


@contextmanager
def state_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = path.with_suffix(path.suffix + '.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'r+b') as handle:
        if os.name == 'nt':
            import msvcrt
            if handle.seek(0, 2) == 0:
                handle.write(b'\0'); handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise ClientError('Эта передача уже выполняется другим процессом') from None
        else:
            import fcntl
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ClientError('Эта передача уже выполняется другим процессом') from None
        try:
            yield
        finally:
            if os.name == 'nt':
                handle.seek(0); msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def progress(done, total):
    print(f'\rБлоки: {done}/{total} ({done / total:.0%})', end='', file=sys.stderr, flush=True)


def upload_file(api, file_path, password='', time_str='7d', state=None, new=False):
    source = Path(file_path).expanduser().resolve()
    if not source.is_file():
        raise ClientError('Исходный файл не найден')
    hours = validate_time(time_str)
    cfg = api.json('GET', '/api/config')
    if cfg.get('chunkSize') != CHUNK:
        raise ClientError('Сервер использует неподдерживаемый размер блока')
    size = source.stat().st_size
    if size > cfg['maxFileSize']:
        raise ClientError(f"Лимит сервера: {cfg['maxFileSize'] / 1024**2:g} МиБ")
    count = max(1, (size + CHUNK - 1) // CHUNK)
    path = state_path('upload', api.server + '\n' + str(source), state)
    with state_lock(path):
        session = None if new else read_state(path)
        if session and (session.get('server') != api.server or session.get('path') != str(source) or session.get('size') != size):
            raise ClientError('Состояние относится к другому файлу. Для новой передачи укажите --new')
        if session and session.get('done'):
            if session.get('expires', 0) <= time.time():
                raise ClientError('Срок прежней передачи истёк. Для новой загрузки укажите --new')
            print(session['url'])
            print('Уже загружено. Для новой ссылки используйте --new.', file=sys.stderr)
            return session['url']
        if session:
            print('Продолжение: используются прежние пароль и срок хранения.', file=sys.stderr)
        with source.open('rb') as data:
            if not session:
                print('Подготовка контрольных сумм…', file=sys.stderr)
                hashes = [digest(data.read(CHUNK)) for _ in range(count)]
                if data.read(1):
                    raise ClientError('Файл изменился во время чтения')
                key, context = secrets.token_bytes(32), b64(secrets.token_bytes(32))
                manifest = {'v': 1, 'name': source.name, 'size': size, 'type': mimetypes.guess_type(source.name)[0] or '',
                            'chunkSize': CHUNK, 'count': count, 'hashes': hashes}
                session = {'v': 1, 'server': api.server, 'path': str(source), 'size': size, 'raw': b64(key), 'context': context,
                           'hashes': hashes, 'fragment': make_fragment(key, password, context), 'hours': hours,
                           'token': b64(secrets.token_bytes(32)), 'manifest': b64(seal(key, pack(manifest), 'manifest:' + context))}
                save_state(path, session)
            # Validate every block, including blocks already uploaded, before resuming.
            data.seek(0)
            for expected in session['hashes']:
                if digest(data.read(CHUNK)) != expected:
                    raise ClientError('Содержимое файла изменилось. Нужен исходный файл или --new')
            if data.read(1):
                raise ClientError('Содержимое файла изменилось')
            if not session.get('id'):
                result = api.json('POST', '/api/files', token=session['token'],
                                  json={'size': size, 'hours': session['hours'], 'manifest': session['manifest']})
                session.update(id=result['id'], expires=result['expires'])
                save_state(path, session)
            base = '/api/files/' + session['id']
            status = api.json('GET', base + '/status', token=session['token'])
            received = set(status['chunks'])
            key, context = unb64(session['raw']), session['context']
            for index in range(count):
                if index not in received:
                    data.seek(index * CHUNK)
                    plaintext = data.read(CHUNK)
                    if digest(plaintext) != session['hashes'][index]:
                        raise ClientError('Файл изменился во время отправки')
                    pending = session.get('pending')
                    if not pending or pending['index'] != index:
                        pending = {'index': index, 'data': b64(seal(key, plaintext, f'chunk:{context}:{index}'))}
                        session['pending'] = pending
                        save_state(path, session)
                    with api.request('PUT', base + f'/chunks/{index}', token=session['token'], data=unb64(pending['data'])):
                        pass
                    session.pop('pending', None)
                    save_state(path, session)
                progress(index + 1, count)
            api.json('POST', base + '/complete', token=session['token'])
        url = api.server + '/d/' + session['id'] + '#' + session['fragment']
        save_state(path, {'v': 1, 'server': api.server, 'path': str(source), 'size': size, 'done': True, 'url': url, 'expires': session['expires']})
        print('\nДо: ' + datetime.fromtimestamp(session['expires'], timezone.utc).isoformat(), file=sys.stderr)
        print(url)
        return url


def safe_name(name):
    name = str(name).replace('\\', '/').split('/')[-1]
    name = re.sub(r'[\x00-\x1f<>:"|?*]', '_', name).strip(' .')
    if not name or name in ('.', '..') or re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', name):
        name = 'download.bin'
    return name


def validate_manifest(manifest, metadata):
    try:
        size, count = manifest['size'], manifest['count']
        if manifest['v'] != 1 or manifest['chunkSize'] != CHUNK or type(size) is not int or size < 0:
            raise ValueError()
        if type(count) is not int or count != max(1, (size + CHUNK - 1) // CHUNK):
            raise ValueError()
        if metadata['size'] != size or metadata['count'] != count or len(manifest['hashes']) != count:
            raise ValueError()
        if not isinstance(manifest['name'], str) or any(len(unb64(h)) != 32 for h in manifest['hashes']):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise ClientError('Некорректный манифест файла') from None


def download_file(api, file_id, fragment, password='', output=None, state=None, overwrite=False):
    value = parse_fragment(fragment)
    if 'wrapped' in value and password is None:
        password = getpass('Пароль файла: ')
    key = unwrap_fragment(value, password or '')
    base = '/api/files/' + file_id
    metadata = api.json('GET', base)
    try:
        manifest = json.loads(unseal(key, unb64(metadata['manifest']), 'manifest:' + value['context']))
    except (InvalidTag, ValueError, KeyError):
        raise ClientError('Ключ не подходит или манифест повреждён') from None
    validate_manifest(manifest, metadata)
    target = Path(output).expanduser() if output else Path(safe_name(manifest['name']))
    if target.is_dir():
        target = target / safe_name(manifest['name'])
    target = target.absolute()
    if target.is_symlink():
        raise ClientError('Путь назначения является символической ссылкой')
    if target.exists() and not overwrite:
        raise ClientError('Файл уже существует. Укажите другой --output или --overwrite')
    identity = digest((api.server + '/' + file_id + '#' + fragment + '\n' + str(target)).encode())
    path = state_path('download', identity, state)
    part = target.with_name('.inttransfer-' + hashlib.sha256(identity.encode()).hexdigest()[:24] + '.part')
    with state_lock(path):
        saved = read_state(path)
        if saved and saved.get('identity') != identity:
            raise ClientError('Файл состояния относится к другому скачиванию')
        done = saved.get('next', 0) if saved else 0
        if type(done) is not int or not 0 <= done <= manifest['count']:
            raise ClientError('Некорректное состояние скачивания')
        target.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(part, flags, 0o600)
        with os.fdopen(fd, 'r+b') as data:
            # Recheck completed plaintext to detect local damage after interruption.
            verified = 0
            for index in range(done):
                length = min(CHUNK, manifest['size'] - index * CHUNK)
                block = data.read(length)
                if len(block) != length or digest(block) != manifest['hashes'][index]:
                    break
                verified += 1
            done = verified
            data.seek(min(done * CHUNK, manifest['size']))
            data.truncate()
            for index in range(done, manifest['count']):
                with api.request('GET', base + f'/chunks/{index}') as response:
                    encrypted = response.content
                try:
                    plaintext = unseal(key, encrypted, f"chunk:{value['context']}:{index}")
                except InvalidTag:
                    raise ClientError(f'Блок {index} повреждён: тег шифрования не совпадает') from None
                length = min(CHUNK, manifest['size'] - index * CHUNK)
                if len(plaintext) != length or digest(plaintext) != manifest['hashes'][index]:
                    raise ClientError(f'Контрольная сумма блока {index} не совпадает')
                data.write(plaintext); data.flush(); os.fsync(data.fileno())
                save_state(path, {'v': 1, 'identity': identity, 'next': index + 1})
                progress(index + 1, manifest['count'])
            if data.tell() != manifest['size']:
                raise ClientError('Неверный итоговый размер файла')
        if overwrite:
            os.replace(part, target)
        else:
            os.link(part, target)  # Atomic, never silently overwrite an existing path.
            part.unlink()
        path.unlink(missing_ok=True)
        print(f'\nСохранено: {target}', file=sys.stderr)
        return target


def main():
    parser = argparse.ArgumentParser(description='intTransfer CLI — консольный клиент для файлообменника intTransfer.')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('-a', '--action', required=True, choices=['upload', 'download'])
    parser.add_argument('-s', '--server', help='URL сервера; не нужен при скачивании по полной ссылке')
    parser.add_argument('-p', '--password', nargs='?', const=True, help='Пароль; без значения — безопасный интерактивный ввод')
    parser.add_argument('-i', '--insecure', action='store_true', help='Отключить проверку TLS-сертификата')
    parser.add_argument('--allow-http', action='store_true', help='Явно разрешить HTTP вне localhost')
    parser.add_argument('--file', help='Исходный файл для upload')
    parser.add_argument('-t', '--time', default='7d', help='1h–168h или 1d–7d; по умолчанию 7d')
    parser.add_argument('--file-id', '--url', dest='file_id', help='Полная ссылка /d/ID#КЛЮЧ либо ID с --key')
    parser.add_argument('--key', help='Фрагмент после #, если --file-id содержит только ID')
    parser.add_argument('-o', '--output', help='Файл или каталог назначения')
    parser.add_argument('--state', help='Собственный путь к JSON-состоянию передачи')
    parser.add_argument('--new', action='store_true', help='Начать новую загрузку вместо сохранённой')
    parser.add_argument('--overwrite', action='store_true', help='Заменить существующий файл после успешного скачивания')
    parser.add_argument('--retries', type=int, default=5, help='Количество повторов сетевого запроса (0–20)')
    args = parser.parse_args()
    if not 0 <= args.retries <= 20:
        parser.error('--retries: от 0 до 20')
    try:
        password = getpass('Пароль файла: ') if args.password is True else args.password
        if args.action == 'upload':
            if not args.server or not args.file:
                parser.error('Для upload обязательны --server и --file')
            api = API(args.server, args.insecure, args.allow_http, args.retries)
            upload_file(api, args.file, password or '', args.time, args.state, args.new)
        else:
            if not args.file_id:
                parser.error('Для download обязательна полная ссылка в --file-id или --url')
            server, file_id, fragment = download_input(args.file_id, args.server, args.key)
            api = API(server, args.insecure, args.allow_http, args.retries)
            download_file(api, file_id, fragment, password, args.output, args.state, args.overwrite)
    except KeyboardInterrupt:
        print('\nПередача прервана. Повторите команду для продолжения.', file=sys.stderr)
        return 130
    except (ClientError, OSError, EOFError) as error:
        print(f'Ошибка: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
