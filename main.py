# -*- coding: utf8 -*-
import math
import traceback
import threading
from datetime import datetime
import pytz
import uuid

import json
import random
import re
import time
import os

from util.aes_help import encrypt_data, decrypt_data
import util.zepp_helper as zeppHelper
import util.push_util as push_util

# token 字典的线程锁，保护并发读写安全
_token_lock = threading.Lock()


def get_int_value_default(_config: dict, _key, default):
    """获取配置中的整数值，不存在则使用默认值"""
    _config.setdefault(_key, default)
    return int(_config.get(_key))


def get_min_max_by_time(hour=None, minute=None):
    """根据当前北京时间计算步数范围"""
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute
    time_rate = min((hour * 60 + minute) / (22 * 60), 1)
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)
    return int(time_rate * min_step), int(time_rate * max_step)


def desensitize_user_name(user):
    """账号脱敏显示"""
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    return f'{user[:3]}****{user[-4:]}'


def get_beijing_time():
    """获取北京时间"""
    target_timezone = pytz.timezone('Asia/Shanghai')
    return datetime.now().astimezone(target_timezone)


def format_now():
    """格式化当前北京时间"""
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")


def get_time():
    """获取毫秒级时间戳字符串"""
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)


def get_access_token(location):
    """从重定向 URL 中提取 access token"""
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if len(result) == 0:
        return None
    return result[0]


def get_error_code(location):
    """从重定向 URL 中提取错误码"""
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if len(result) == 0:
        return None
    return result[0]


def safe_traceback():
    """返回脱敏后的异常信息，避免泄漏敏感变量"""
    lines = traceback.format_exc().splitlines()
    safe_lines = []
    sensitive_keys = ['password', 'pwd', 'token', 'access_token',
                      'login_token', 'app_token', 'CONFIG', 'AES_KEY']
    for line in lines:
        lower_line = line.lower()
        if any(key in lower_line for key in sensitive_keys):
            safe_lines.append("  [敏感信息已隐藏]")
        else:
            safe_lines.append(line)
    return "\n".join(safe_lines)


class MiMotionRunner:
    def __init__(self, _user, _passwd):
        self.user_id = None
        self.device_id = str(uuid.uuid4())
        user = str(_user)
        password = str(_passwd)
        self.invalid = False
        self.log_str = ""
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True
            return
        self.password = password
        if (user.startswith("+86")) or "@" in user:
            pass
        else:
            user = "+86" + user
        self.is_phone = user.startswith("+86")
        self.user = user

    def login(self):
        """登录并获取 app_token，支持三级 token 缓存降级"""
        with _token_lock:
            user_token_info = user_tokens.get(self.user)

        if user_token_info is not None:
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id", self.device_id)
            self.user_id = user_token_info.get("user_id")

            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                with _token_lock:
                    user_token_info["device_id"] = self.device_id

            # 尝试使用缓存的 app_token
            ok, msg = zeppHelper.check_app_token(app_token)
            if ok:
                self.log_str += "使用加密保存的app_token\n"
                return app_token

            self.log_str += f"app_token失效，尝试重新获取\n"

            # 尝试用 login_token 刷新 app_token
            app_token, msg = zeppHelper.grant_app_token(login_token)
            if app_token is not None:
                self.log_str += "重新获取app_token成功\n"
                with _token_lock:
                    user_token_info["app_token"] = app_token
                    user_token_info["app_token_time"] = get_time()
                return app_token

            self.log_str += f"login_token失效，尝试重新获取\n"

            # 尝试用 access_token 重新获取 login_token
            login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(
                access_token, self.device_id, self.is_phone)
            if login_token is not None:
                with _token_lock:
                    user_token_info["login_token"] = login_token
                    user_token_info["app_token"] = app_token
                    user_token_info["user_id"] = user_id
                    user_token_info["login_token_time"] = get_time()
                    user_token_info["app_token_time"] = get_time()
                self.user_id = user_id
                return app_token

            self.log_str += f"access_token已失效\n"

        # 所有缓存失效，重新登录
        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "登录获取accessToken失败"
            return None

        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(
            access_token, self.device_id, self.is_phone)
        if login_token is None:
            self.log_str += f"登录提取的access_token无效"
            return None

        user_token_info = {
            "access_token": access_token,
            "login_token": login_token,
            "app_token": app_token,
            "user_id": user_id,
            "access_token_time": get_time(),
            "login_token_time": get_time(),
            "app_token_time": get_time(),
            "device_id": self.device_id,
        }
        with _token_lock:
            user_tokens[self.user] = user_token_info
        return app_token

    def login_and_post_step(self, min_step, max_step):
        """登录并提交步数"""
        if self.invalid:
            return "账号或密码配置有误", False

        app_token = self.login()
        if app_token is None:
            return "登录失败！", False

        step = str(random.randint(min_step, max_step))
        self.log_str += f"已设置为随机步数范围({min_step}~{max_step}) 随机值:{step}\n"
        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id)
        return f"修改步数（{step}）[{msg}]", ok


def run_single_account(total, idx, user_mi, passwd_mi):
    """执行单个账号的刷步数"""
    idx_info = f"[{idx + 1}/{total}]" if idx is not None else ""
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"
    try:
        runner = MiMotionRunner(user_mi, passwd_mi)
        exec_msg, success = runner.login_and_post_step(min_step, max_step)
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
        exec_result = {"user": user_mi, "success": success, "msg": exec_msg}
    except Exception:
        safe_tb = safe_traceback()
        log_str += f"执行异常:\n{safe_tb}\n"
        exec_result = {"user": user_mi, "success": False, "msg": "执行异常，请检查日志"}
    print(log_str)
    return exec_result


def execute():
    """主执行函数"""
    user_list = users.split('#')
    passwd_list = passwords.split('#')
    exec_results = []

    if len(user_list) != len(passwd_list):
        print(f"账号数长度[{len(user_list)}]和密码数长度[{len(passwd_list)}]不匹配，跳过执行")
        exit(1)

    idx, total = 0, len(user_list)

    if use_concurrent:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # 强制求值，确保所有任务完成后再继续
            exec_results = list(executor.map(
                lambda x: run_single_account(total, x[0], *x[1]),
                enumerate(zip(user_list, passwd_list))
            ))
    else:
        for user_mi, passwd_mi in zip(user_list, passwd_list):
            exec_results.append(run_single_account(total, idx, user_mi, passwd_mi))
            idx += 1
            if idx < total:
                time.sleep(sleep_seconds)

    if encrypt_support:
        persist_user_tokens()

    success_count = 0
    push_results = []
    for result in exec_results:
        push_results.append(result)
        if result['success']:
            success_count += 1

    summary = f"\n执行账号总数{total}，成功：{success_count}，失败：{total - success_count}"
    print(summary)
    push_util.push_results(push_results, summary, push_config)


def prepare_user_tokens() -> dict:
    """读取并解密 token 缓存文件"""
    data_path = "encrypted_tokens.data"
    if not os.path.exists(data_path):
        return dict()

    with open(data_path, 'rb') as f:
        data = f.read()
    try:
        decrypted_data = decrypt_data(data, aes_key, None)
        return json.loads(decrypted_data.decode('utf-8', errors='strict'))
    except Exception:
        print("密钥不正确或者加密内容损坏，放弃token缓存")
        return dict()


def persist_user_tokens():
    """加密并保存 token 到文件（原子写入）"""
    data_path = "encrypted_tokens.data"
    tmp_path = data_path + ".tmp"
    try:
        origin_str = json.dumps(user_tokens, ensure_ascii=False)
        cipher_data = encrypt_data(origin_str.encode("utf-8"), aes_key, None)
        with open(tmp_path, 'wb') as f:
            f.write(cipher_data)
        os.replace(tmp_path, data_path)  # 原子替换，防止写入中断导致文件损坏
    except Exception:
        print(f"保存token文件失败: {safe_traceback()}")
        # 清理临时文件
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


if __name__ == "__main__":
    time_bj = get_beijing_time()
    encrypt_support = False
    user_tokens = dict()

    # 初始化 AES 加密
    if "AES_KEY" in os.environ:
        aes_key = os.environ.get("AES_KEY")
        if aes_key is not None:
            aes_key = aes_key.encode('utf-8')
            if len(aes_key) == 16:
                encrypt_support = True
        if encrypt_support:
            user_tokens = prepare_user_tokens()
        else:
            print("AES_KEY未设置或者无效，无法使用加密保存功能")

    # 读取配置
    if "CONFIG" not in os.environ:
        print("未配置CONFIG变量，无法执行")
        exit(1)

    config = dict()
    try:
        config = dict(json.loads(os.environ.get("CONFIG")))
    except Exception:
        print("CONFIG格式不正确，请检查Secret配置，请严格按照JSON格式：使用双引号包裹字段和值，逗号不能多也不能少")
        exit(1)

    # 初始化推送配置
    push_config = push_util.PushConfig(
        push_plus_token=config.get('PUSH_PLUS_TOKEN'),
        push_plus_hour=config.get('PUSH_PLUS_HOUR'),
        push_plus_max=get_int_value_default(config, 'PUSH_PLUS_MAX', 30),
        push_wechat_webhook_key=config.get('PUSH_WECHAT_WEBHOOK_KEY'),
        telegram_bot_token=config.get('TELEGRAM_BOT_TOKEN'),
        telegram_chat_id=config.get('TELEGRAM_CHAT_ID')
    )

    # 解析休眠间隔
    try:
        sleep_seconds = float(config.get('SLEEP_GAP', 5))
    except (ValueError, TypeError):
        print("SLEEP_GAP 配置无效，使用默认值 5 秒")
        sleep_seconds = 5.0

    # 解析账号密码
    users = config.get('USER')
    passwords = config.get('PWD')
    if users is None or passwords is None:
        print("未正确配置账号密码，无法执行")
        exit(1)

    # 解析步数范围
    min_step, max_step = get_min_max_by_time()

    # 解析是否并发
    use_concurrent = str(config.get('USE_CONCURRENT', '')).lower() == 'true'
    if not use_concurrent:
        print(f"多账号执行间隔：{sleep_seconds}秒")

    execute()
