import jwt
from jwt.exceptions import *
import datetime
from django.conf import settings


def create_token(payload, timeout=20):
    headers = {
        'type': 'jwt',
        'alg': 'HS256'
    }
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=timeout)

    return jwt.encode(payload=payload, key=settings.SECRET_KEY, algorithm="HS256", headers=headers)


def parse_token(token):
    result = {'status': False, 'data': None, 'error': None}

    try:
        verify_payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
        result['data'] = verify_payload
        result['status'] = True
    except ExpiredSignatureError:
        result['error'] = "token已经失效"
    except DecodeError:
        result['error'] = 'token认证失败'
    except InvalidTokenError:
        result['error'] = '非法的token'

    return result
