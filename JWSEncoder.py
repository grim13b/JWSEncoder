import argparse
import base64
import datetime
import hashlib
import hmac
import json
import uuid


def create_header():
    header = {
        'alg': 'HS256',
        'typ': 'JOSE'
    }
    return base64.b64encode(json.dumps(header).encode('utf-8')).decode('utf-8')


def build_payload(filename, issuer, subject, expiry_period):
    jst = datetime.timezone(datetime.timedelta(hours=+9), 'JST')
    dt = datetime.datetime.now(jst)

    created_at = int(dt.timestamp())
    expired_at = int((dt + datetime.timedelta(hours=expiry_period)).timestamp())

    with open(filename) as f:
        user_data = json.load(f)

    payload = {
        'jti': str(uuid.uuid4()),
        'iss': issuer,
        'sub': subject,
        'iat': created_at,
        'exp': expired_at
    }

    payload.update(user_data)
    return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')


def main(arguments):
    encoded_header = create_header()
    encoded_payload = build_payload(arguments.jsonfile, arguments.issuer, arguments.subject, arguments.expiryperiod)

    message = '{}.{}'.format(encoded_header, encoded_payload)

    private_key = arguments.privatekey
    signature = hmac.digest(private_key.encode(), message.encode(), hashlib.sha256)
    encoded_signature = base64.b64encode(signature).decode('utf-8')

    print('{}.{}.{}'.format(encoded_header, encoded_payload, encoded_signature))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('jsonfile', type=str, help='署名したいJsonファイル.')
    parser.add_argument('privatekey', type=str, help='署名に使う秘密鍵.')

    parser.add_argument('-v', '--version', type=str, default='1.0', help='データのバージョン.')
    parser.add_argument('-i', '--issuer', type=str, default='hoge', help='この署名付きデータの発行者')
    parser.add_argument('-s', '--subject', type=str, default='jwt-encode-example',  help='発行者が定めた用途')
    parser.add_argument('-e', '--expiryperiod', type=int, default=24,  help='この署名付きデータの有効期間(単位:時間)')

    args = parser.parse_args()

    main(args)
