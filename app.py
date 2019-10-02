import json
import logging
import os
from contextlib import contextmanager

from flask import Flask
from flask import request
from flask import Response
from flask_cors import CORS
from kazoo.client import KazooClient
from kazoo.security import make_digest_acl, make_acl, make_digest_acl_credential

app = Flask(__name__)
cors = CORS(app, origin='*')
ZOO_HOSTS = '127.0.0.1:2181'
client = KazooClient(hosts=ZOO_HOSTS)
client.start()
ROOT = '/config'

anonymous_acl = make_acl('world', 'anyone', read=True)


def make_response(success=True, data=None, code=0, msg=''):
    resp_json = {
        'success': success,
        'code': code,
        'data': data,
        'msg': msg
    }
    return Response(json.dumps(resp_json))


def get_credential():
    username = request.json['auth']['username']
    password = request.json['auth']['password']
    return username, password


@app.route('/children', methods=['POST'])
def get_children():
    relative_path = request.json['path']
    full_path = ROOT + relative_path
    if not os.path.isabs(full_path) and '..' not in full_path:
        return make_response(success=False, data=None, code=400, msg='只能使用绝对路径')
    children = []
    for c in client.get_children(full_path):
        sub_path = full_path + '/' + c
        if c not in ('passwd', 'password', 'secret'):
            raw_value, _stat = client.get(sub_path)
            value = '' if not raw_value else raw_value.decode('utf8')
        else:
            value = '******'
        children.append({
            'leaf': not bool(client.get_children(sub_path)),
            'name': c,
            'value': value,
            'key': relative_path + '/' + c})
    return make_response(data=children)


@contextmanager
def auth_kazoo(username, password):
    auth_client = KazooClient(hosts=ZOO_HOSTS)
    try:
        auth_client.start(timeout=5)
        credential = make_digest_acl_credential(username, password)
        auth_client.add_auth('digest', credential)
        yield auth_client
    finally:
        auth_client.stop()


@app.route('/create', methods=["POST"])
def create():
    dirname = ROOT + request.json['path']
    name = request.json['name']
    value = request.json['value']
    try:
        options = request.json['options']
        options_params = {}
        new_path = dirname + '/' + name
        if options['create']:
            username, password = get_credential()
            with auth_kazoo(username, password) as auth_client:
                admin_acl = make_digest_acl(username, password, **options)
                acl_list = [anonymous_acl, admin_acl]
                options_params['acl'] = acl_list
                auth_client.create(new_path, value=value.encode('utf8'), **options_params)
        else:
            client.create(new_path, value=value.encode('utf8'), **options_params)
        return make_response(success=True, msg='创建成功')
    except Exception as e:
        logging.exception('error when create node: %s', str(e))
        return make_response(success=False, msg='创建节点出错: %s' % str(e))


@app.route('/delete', methods=['POST'])
def delete():
    full_path = ROOT + request.json['path']
    try:
        options = request.json['options']
        if options['delete']:
            username, password = get_credential()
            with auth_kazoo(username, password) as auth_client:
                auth_client.delete(full_path)
        else:
            client.delete(full_path)
        return make_response(msg='删除节点成功')
    except Exception as e:
        logging.exception('error when delete node: %s', str(e))
        return make_response(success=False, msg='删除节点失败')


@app.route('/write', methods=['POST'])
def change():
    full_path = ROOT + request.json['path']
    name = request.json['name']
    value = request.json['value']
    try:
        options = request.json['options']
        if options['write']:
            username, password = get_credential()
            with auth_kazoo(username, password) as auth_client:
                auth_client.set(full_path + '/' + name, value.encode('utf8'))
        else:
            client.set(full_path + '/' + name, value.encode('utf8'))
        return make_response(msg='修改节点成功')
    except Exception as e:
        logging.exception('error when write node: %s', str(e))
        return make_response(success=False, msg='修改节点失败')


if __name__ == '__main__':
    app.run(debug=True)
