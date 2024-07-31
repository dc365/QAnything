import time
import uuid
import shortuuid
from datetime import datetime
from sanic_jwt import Responses, exceptions, protected
from sanic import request
from sanic.response import json as sanic_json
import jwt
from qanything_kernel.core.local_doc_qa import LocalDocQA
from qanything_kernel.utils.custom_log import debug_logger, qa_logger
from qanything_kernel.utils.general_utils import *

__all__ = ["login", "add_user", "list_users", "get_user", "change_user", "change_user_profile_pic", "change_password", "delete_user",
           "store_refresh_token", "retrieve_refresh_token",
           "list_roles", "add_role", "change_role", "delete_role", "QAResponses"]

async def login(req: request, *args, **kwargs):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_name = safe_get(req, 'user_name')
    passwd = safe_get(req, 'password')
    if user_name is None or passwd is None:
        raise exceptions.AuthenticationFailed("Missing username or password.")
    debug_logger.info("login %s", user_name)
    is_right,user_id = local_doc_qa.mysql_client.check_passwd(user_name, passwd)
    if not is_right:
        raise exceptions.AuthenticationFailed("Invalid username or password")
    else:
        #return { 'user_id': user_id }
        return sanic_json({"code": 200, "msg": "success",
                   "data": { "user_id": user_id,
                       "access_token": "test", "refresh_token": "refresh_token_test"}})

#@protected()
async def add_user(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_name = safe_get(req, 'user_name')
    if user_name is None:
        return sanic_json({"code": 2002, "msg": f'输入非法！request.json：{req.json}，请检查！'})
    user_exist = local_doc_qa.mysql_client.check_user_name_exist(user_name)
    if user_exist:
        return sanic_json({"code": 2003, "msg": f'用户名已存在：{user_name}，请检查！'})
    create_by = safe_get(req, 'user_id')
    debug_logger.info("add user %s", user_name)
    #user_id = 'u'+ uuid.uuid4().hex
    user_id = 'u' + shortuuid.uuid()
    pid = safe_get(req, 'pid')
    if pid is None:
        return sanic_json({"code": 2003, "msg": f'pid 未指定，请检查！'})
    user_type = safe_get(req, 'user_type')
    if user_type is None:
        return sanic_json({"code": 2003, "msg": f'user_type 未指定，请检查！'})
    if user_type == 'user':
        profile_pic = safe_get(req, 'profile_pic')
        password = safe_get(req, 'password')
        user_state = safe_get(req, 'user_state')
        telephone = safe_get(req, 'telephone')
        region = safe_get(req, 'region')
        wechat_id = safe_get(req, 'wechat_id')
        role_ids = safe_get(req, 'role_ids')
        if role_ids is not None:
            role_ids = ','.join(role_ids)
    else:
        profile_pic = ''
        password = ''
        user_state = ''
        telephone = ''
        region = ''
        wechat_id = ''
        role_ids = ''

    local_doc_qa.mysql_client.add_user(user_id, pid, user_type, user_name, password, profile_pic, user_state,
                                               telephone, region, wechat_id, role_ids, create_by)
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M")
    return sanic_json({"code": 200, "msg": "success create user {}".format(user_id),
                       "data": {"user_id": user_id}})


#@protected()
async def change_user(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_id = safe_get(req, 'user_id')
    debug_logger.info("change user %s", user_id)
    user_exist = local_doc_qa.mysql_client.check_user_exist_(user_id)
    if not user_exist:
        return sanic_json({"code": 2001, "msg": "fail, user {} not exist".format(user_id)})
    user_name = safe_get(req, 'user_name')
    user_type = safe_get(req, 'user_type')
    if user_type is None:
        return sanic_json({"code": 2003, "msg": f'user_type 未指定，请检查！'})
    if user_type == 'user':
        profile_pic = safe_get(req, 'profile_pic')
        password = safe_get(req, 'password')
        user_state = safe_get(req, 'user_state')
        telephone = safe_get(req, 'telephone')
        region = safe_get(req, 'region')
        wechat_id = safe_get(req, 'wechat_id')
        role_ids = safe_get(req, 'role_ids')
        if role_ids is not None:
            role_ids = ','.join(role_ids)
    else:
        profile_pic = ''
        password = ''
        user_state = ''
        telephone = ''
        region = ''
        wechat_id = ''
        role_ids = ''
    local_doc_qa.mysql_client.change_user(user_id, user_name, password, profile_pic, user_state, telephone, region, wechat_id, role_ids)
    return sanic_json({"code": 200, "msg": "change user {} success".format(user_id),
                       })

async def change_user_profile_pic(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_id = safe_get(req, 'user_id')
    debug_logger.info("change user profile pic %s", user_id)
    user_exist = local_doc_qa.mysql_client.check_user_exist_(user_id)
    if not user_exist:
        return sanic_json({"code": 2001, "msg": "fail, user {} not exist".format(user_id)})
    profile_pic = safe_get(req, 'profile_pic')
    local_doc_qa.mysql_client.change_user(user_id, profile_pic)
    return sanic_json({"code": 200, "msg": "change user {} success".format(user_id),
                       })

#@protected()
async def list_users(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_type = safe_get(req, 'user_type')
    if user_type is None:
        return sanic_json({"code": 2003, "msg": f'user_type 未指定，请检查！'})
    if user_type == 'user':
        pid = safe_get(req, 'pid')
    else:
        pid = 0

    user_infos = local_doc_qa.mysql_client.get_user_list(user_type, pid)
    datas = []
    if user_type != 'user':
        for user in user_infos:
            datas.append({
                "user_id": user[0],
                "id": user[1],
                "pid": user[2],
                "user_name": user[3],
                "user_type": user[4]
            })
    else:
        for user in user_infos:
            datas.append({
                "user_id": user[0],
                "id":user[1],
                "pid": user[2],
                "user_name": user[3],
                "user_type": user[4],
                "telephone": user[5],
                "password": user[6],
                "user_state": user[7],
                "profile_pic": user[8],
                "wechat_id": user[9],
                "role_ids": user[10].split(',') if user[10] is not None else [],
                "region": user[11],
                "create_by": user[12],
                "add_datetime": user[13]
            })
    return sanic_json({ "code": 200, "msg": "success",
                        "data": datas
                       })

#@protected()
async def get_user(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_id = safe_get(req, 'user_id')
    debug_logger.info("get user %s", user_id)
    user_exist = local_doc_qa.mysql_client.check_user_exist_(user_id)
    if not user_exist:
        return sanic_json({"code": 2001, "msg": "fail, user {} not exist".format(user_id)})
    user_infos = local_doc_qa.mysql_client.get_user(user_id)
    if user_infos is not None and len(user_infos) > 0:
        user0 = user_infos[0]
        return sanic_json({"code": 200, "msg": "success",
                       "data":{
                           "id":user0[0],
                           "pid": user0[1],
                           "user_name": user0[2],
                           "user_type": user0[3],
                           "telephone":user0[4],
                           "password":user0[5],
                           "user_state":user0[6],
                           "region": user0[7],
                           "profile_pic":user0[8],
                           "wechat_id":user0[9],
                           "role_ids":user0[10].split(',') if user0[10] is not None else [],
                           "add_datetime": user0[11]
                       }
                           })
    else:
        return sanic_json({"code": 2002, "msg": "failed".format(user_id),
                       })

#@protected()
async def delete_user(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_id = safe_get(req, 'user_id')
    debug_logger.info("delete user %s", user_id)
    user_exist = local_doc_qa.mysql_client.check_user_exist_(user_id)
    if not user_exist:
        return sanic_json({"code": 2001, "msg": "fail, user {} not exist".format(user_id)})
    local_doc_qa.mysql_client.delete_user(user_id)
    return sanic_json({"code": 200, "msg": "delete user {} success".format(user_id),
                       })

#@protected()
async def change_password(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    user_id = safe_get(req, 'user_id')
    if user_id is None:
        return sanic_json({"code": 2002, "msg": f'输入非法！request.json：{req.json}，请检查！'})
    debug_logger.info("change password %s", user_id)
    user_exist = local_doc_qa.mysql_client.check_user_exist(user_id)
    if not user_exist:
        return sanic_json({"code": 2003, "msg": "fail, user {} not exist".format(user_exist)})
    old_password = safe_get(req, 'old_password')
    if old_password is None or old_password == '':
        return sanic_json({"code": 2004, "msg": "missing old password"})
    passwd_infos = local_doc_qa.mysql_client.get_passwd(user_id)
    if passwd_infos is not None:
        if len(passwd_infos) > 0:
            if passwd_infos[0][0] != old_password:
                return sanic_json({"code": 2004, "msg": "fail, invalid old password"})
    password = safe_get(req, 'new_password')
    local_doc_qa.mysql_client.change_passwd(user_id, password)
    return sanic_json({"code": 200, "msg": "change user {} password success".format(user_id)})

#@protected()
async def list_roles(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    role_infos = local_doc_qa.mysql_client.get_role_list()
    datas = []
    role_ids = []
    for role in role_infos:
        datas.append({
            "role_id":role[0],
            "role_name":role[1],
            "relate_kb": []
        })
        role_ids.append(role[0])
    role_kb_permissions = local_doc_qa.mysql_client.get_role_permissions(role_ids)
    if role_kb_permissions is not None:
        for data in datas:
            for rk_permission in role_kb_permissions:
                if data['role_id'] == rk_permission[0]:
                    data['relate_kb'].append([rk_permission[1], rk_permission[2]])
    return sanic_json({ "code": 200, "msg": "success",
                        "data": datas
                       })
#@protected()
async def add_role(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    role_id = safe_get(req, 'role_id')
    if role_id is None or role_id.strip() == '':
        role_id = "r" + shortuuid.uuid()
    debug_logger.info("add role %s", role_id)
    role_name = safe_get(req, 'role_name')
    if role_name is None or role_name == '':
        return sanic_json({"code": 2003, "msg": f'未提供角色名，请检查！'})
    role_exist = local_doc_qa.mysql_client.check_role_exist(role_id)
    if role_exist:
        return sanic_json({"code": 2001, "msg": "fail, role {} already exist".format(role_id)})

    local_doc_qa.mysql_client.add_role(role_id, role_name)
    return sanic_json({"code": 200, "msg": "success",
                       "data":{
                           "role_id": role_id
                       }})

#@protected()
async def change_role(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    role_id = safe_get(req, 'role_id')
    if role_id is None:
        return sanic_json({"code": 2002, "msg": f'输入非法！request.json：{req.json}，请检查！'})
    debug_logger.info("change role %s", role_id)
    role_name = safe_get(req, 'role_name')
    permissions = safe_get(req, 'relate_kbs')
    if role_name is None and permissions is None:
        return sanic_json({"code": 2003, "msg": f'未提供角色名或权限，请检查！'})
    role_exist = local_doc_qa.mysql_client.check_role_exist(role_id)
    if not role_exist:
        return sanic_json({"code": 2001, "msg": "fail, role {} not exist".format(role_id)})
    if role_name is not None:
        local_doc_qa.mysql_client.change_role(role_id, role_name)
    if permissions is not None:
        local_doc_qa.mysql_client.change_role_permissions(role_id, permissions)
    return sanic_json({"code": 200, "msg": "success".format(role_id)})

#@protected()
async def delete_role(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    role_id = safe_get(req, 'role_id')
    debug_logger.info("delete role %s", role_id)
    user_exist = local_doc_qa.mysql_client.check_role_exist_(role_id)
    if not user_exist:
        return sanic_json({"code": 2001, "msg": "fail, role {} not exist".format(role_id)})
    local_doc_qa.mysql_client.delete_role(role_id)
    return sanic_json({"code": 200, "msg": "delete role {} success".format(role_id),
                       })

def store_refresh_token(user_id, refresh_token, *args, **kwargs):
    from qanything_kernel.connector.database.mysql.mysql_client import KnowledgeBaseManager
    mysql_client = KnowledgeBaseManager()
    old_r = mysql_client.get_refresh_token(user_id)
    if old_r is None:
        mysql_client.add_refresh_token(user_id, refresh_token)

def retrieve_refresh_token(req: request, user_id, *args, **kwargs):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    r= local_doc_qa.mysql_client.get_refresh_token(user_id)
    print(r)
    return r

class QAResponses(Responses):
    @staticmethod
    def extend_authenticate(request,
                            user=None,
                            access_token=None,
                            refresh_token=None):
        r = jwt.decode(access_token, options={"verify_signature": False})
        exp  = r['exp']
        exp_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(exp))
        return {
            "code":200,
            "msg":"success",
            "data":{
                "user_id": user['user_id']  if user is not None else '',
                "access_token": access_token,
                "refresh_token": refresh_token,
                "exp": exp_time
            }
        }

    @staticmethod
    def extend_retrieve_user(request, user=None, payload=None):
        return {}

    @staticmethod
    def extend_verify(request, user=None, payload=None):
        return {}

    @staticmethod
    def extend_refresh(request,
                       user=None,
                       access_token=None,
                       refresh_token=None,
                       purported_token=None,
                       payload=None):
        r = jwt.decode(refresh_token, options={"verify_signature": False})
        exp = r['exp']
        exp_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))
        return {
            "code": 200,
            "msg":"success",
            "data":{
                "access_token": access_token,
                "exp": exp_time
            }
        }

    @staticmethod
    def exception_response(request, exception):
        reasons = (
            exception.args[0]
            if isinstance(exception.args[0], list)
            else [exception.args[0]]
        )
        return sanic_json(
            {   "code": exception.status_code,
                "msg": reasons,
                "exception": exception.__class__.__name__},
            status=exception.status_code,
        )