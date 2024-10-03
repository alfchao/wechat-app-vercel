import functools
import json
import traceback
import requests
from flask import Flask, request
from pydantic import BaseModel
from redis import Redis
from pathlib import Path
import os

class Settings(BaseModel):
    """
    Config for the application.
    """
    KV_URL: str = ''
    redis_prefix: str = ''
    corp_id: str = ''
    corp_secret: str = ''
    agent_id: str = ''
    WECHAT_API_URL: str = ''
    sendKey: str = ''


rootPath = Path(__file__).parent.parent

envFile = rootPath / '.env'

if envFile.exists():
    with open(envFile, 'r') as f:
        env = f.readlines()
        settings = Settings(**{line.split('=', 1)[0].strip().strip('"').strip("'"): line.split('=', 1)[1].strip().strip('"').strip("'") for line in env})
else:
    env_map = dict(os.environ)
    settings = Settings(**env_map)

print(settings)

app = Flask(__name__)


def unicode_convert(data):
    """
    Convert unicode to utf-8.
    """
    if isinstance(data, list):
        return [unicode_convert(item) for item in data]
    elif isinstance(data, dict):
        return {unicode_convert(k): unicode_convert(v) for k, v in data.items()}
    elif isinstance(data, bytes):
        return data.decode('utf-8')
    else:
        return data


class ParamsModel(BaseModel):
    user_ids: str
    msg: str
    sendKey: str


def auth_request(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        redis_url = settings.KV_URL.replace('redis', 'rediss', 1)
        redis_client = Redis.from_url(redis_url)
        redis_key = f"{settings.redis_prefix}:{settings.corp_id}_{settings.agent_id}_access_token"
        access_token = unicode_convert(redis_client.get(redis_key))
        rsp_json = {'errcode': 40014}
        if access_token:
            kwargs['access_token'] = access_token
            rsp_json = func(*args, **kwargs)
        if rsp_json.get('errcode') == 0:
            pass
        elif rsp_json.get('errcode') == 40014:
            print('重新获取access_token')
            rsp = requests.get(
                f"{settings.WECHAT_API_URL}/gettoken?corpid={settings.corp_id}&corpsecret={settings.corp_secret}")
            print(rsp.text)
            access_token = rsp.json()
            kwargs['access_token'] = access_token['access_token']
            redis_client.set(redis_key, access_token['access_token'], ex=access_token['expires_in'])
            rsp_json = func(*args, **kwargs)
        else:
            pass
        return rsp_json

    return wrapper


@auth_request
def send_msg(user_ids: str, msg: str, **kwargs) -> dict:
    req_data = {
        "touser": f"{user_ids}",
        "totag": "vercel|消息通知",
        "msgtype": "text",
        "agentid": settings.agent_id,
        "text": {
            "content": f"{msg}"
        },
        "safe": 0,
        "enable_id_trans": 0,
        "enable_duplicate_check": 0,
        "duplicate_check_interval": 1800
    }
    headers = {'Content-Type': 'application/json'}
    rsp = requests.post(f"{settings.WECHAT_API_URL}/message/send?access_token={kwargs['access_token']}",
                        data=json.dumps(req_data, ensure_ascii=False), headers=headers)
    print(rsp.text)
    return rsp.json()


@app.route('/', methods=['GET'])
def home():
    try:
        args = request.args
        print(args)
        args = ParamsModel(**args)
        if args.sendKey != settings.sendKey:
            return 'error'
        else:
            print(send_msg(args.user_ids.replace(',', '|'), args.msg))
    except:
        print(traceback.format_exc())
    return 'Hello, World!'


if __name__ == '__main__':
    app.run(debug=True, )
