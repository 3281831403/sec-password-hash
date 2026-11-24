"""PBKDF2 密码哈希核心接口。

本模块只依赖 Python 标准库。盐与随机源都由调用方显式传入，模块内部不读取
时钟、不访问系统随机源、不做任何隐式随机。八个公开函数的契约见各自
docstring，实现必须逐条满足。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Any, Callable, Iterable

ALGORITHM = "pbkdf2_sha256"
MIN_ITERATIONS = 100_000
MIN_SALT_BYTES = 16
DIGEST_BYTES = 32

# 无前导零的十进制非负整数（"0" 本身合法，但迭代下限会拦掉它）。
# 用 \Z 而非 $：$ 允许字符串末尾尾随换行，控制字符会借此混过解析。
_INTEGER_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
# 无填充的 URL 安全 base64 字符集：拒绝等号、空白、控制字符及其他多余字符。
_B64_RE = re.compile(r"[A-Za-z0-9_-]+\Z")


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(segment: str) -> bytes:
    """严格解码无填充 URL 安全 base64；字符集非法或数据损坏一律 ValueError。

    urlsafe_b64decode 不支持 validate 参数，先转回标准字符表，再用
    b64decode(validate=True) 拒绝任何非字母表字符。
    """
    if not _B64_RE.match(segment):
        raise ValueError("base64 字段含非法字符")
    standard = segment.replace("-", "+").replace("_", "/")
    padded = standard + "=" * (-len(standard) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("base64 字段损坏") from exc


# 缺陷 1：盐只能来自调用方显式传入的熵源，禁止用时间、进程号或模块级状态
# 推导，保证同一时刻注册的两个账号也会拿到不同的盐。
def salt_bytes(entropy: Callable[[int], bytes], size: int = MIN_SALT_BYTES) -> bytes:
    """从调用方提供的熵源生成固定长度的密码学盐。

    参数：
        entropy: 可调用对象，签名为 entropy(n) -> bytes，必须恰好返回 n 字节。
                 它是唯一的随机性来源，实现不得用时间、进程号或模块级状态代替。
        size:    盐长度，单位字节，默认 16。必须是 int 且不小于 16。

    返回：
        长度为 size 的 bytes，即 entropy(size) 的返回值。

    异常：
        TypeError: entropy 不可调用，或 entropy 返回的不是 bytes。
        ValueError: size 小于 16，或 entropy 返回的字节数不等于 size。
        实现不得静默截断、补齐或重试。

    契约要点：长度固定；同一熵源连续调用应当得到不同盐；不同调用方各自
    传入熵源，不得共享模块级盐。
    """
    if not callable(entropy):
        raise TypeError("entropy 必须是可调用对象")
    if not isinstance(size, int):
        raise TypeError("size 必须是 int")
    if size < MIN_SALT_BYTES:
        raise ValueError(f"盐长度不得小于 {MIN_SALT_BYTES} 字节")

    salt = entropy(size)
    if not isinstance(salt, bytes):
        raise TypeError("entropy 必须返回 bytes")
    if len(salt) != size:
        raise ValueError("entropy 返回的字节数必须恰好等于 size，不得截断或补齐")
    return salt


# 缺陷 2：严格使用调用方给定的迭代次数，不得忽略、钳制或固定为 1000。
# 缺陷 3：密码与盐作为 PBKDF2 的两个独立输入传入，禁止首尾直接拼接。
def derive(password: str, salt: bytes, iterations: int) -> bytes:
    """用 PBKDF2-HMAC-SHA256 派生固定 32 字节摘要。

    参数：
        password:   明文密码，str，按 UTF-8 编码后作为 PBKDF2 的密码。
        salt:       盐，bytes，长度不得小于 16。
        iterations: 迭代次数，int 且不得小于 100000。实现必须严格使用该值，
                    不得忽略、钳制或替换为固定值。

    返回：
        32 字节摘要，等价于：
        hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                            iterations, dklen=32)

    异常：
        TypeError: 参数类型不符合上述约定。
        ValueError: salt 短于 16 字节，或 iterations 小于 100000。

    契约要点：密码与盐是 PBKDF2 的两个独立输入，实现不得把二者简单拼接；
        相同密码、相同盐、相同迭代必须得到相同结果；盐变化一位，结果就必须
        整体不同；容差为 0。
    """
    if not isinstance(password, str):
        raise TypeError("password 必须是 str")
    if not isinstance(salt, bytes):
        raise TypeError("salt 必须是 bytes")
    if len(salt) < MIN_SALT_BYTES:
        raise ValueError(f"salt 不得短于 {MIN_SALT_BYTES} 字节")
    if not isinstance(iterations, int):
        raise TypeError("iterations 必须是 int")
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"iterations 不得小于 {MIN_ITERATIONS}")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=DIGEST_BYTES,
    )


# 缺陷 4：算法名写入存储串第一段，记录自描述，换算法后新旧记录可区分。
def encode(salt: bytes, digest: bytes, iterations: int) -> str:
    """把盐、摘要与迭代次数编码为可存储字符串。

    格式固定为四段，以美元符号分隔：
        pbkdf2_sha256$<iterations>$<salt>$<digest>

    其中 iterations 为十进制无前导零整数；salt 与 digest 均为 URL 安全的
    base64，不带等号填充。算法名必须写入第一段，升级算法后新旧记录才能
    区分。

    参数：
        salt:       盐，bytes，长度不得小于 16。
        digest:     摘要，bytes，长度必须恰好为 32。
        iterations: 迭代次数，int 且不得小于 100000。

    返回：
        上述格式的 str。

    异常：
        TypeError: 参数类型不符合约定。
        ValueError: salt 短于 16 字节、digest 不是 32 字节，或 iterations
                    小于 100000。

    契约要点：编码必须自描述；容差为 0，不存储额外可变字段。
    """
    if not isinstance(salt, bytes):
        raise TypeError("salt 必须是 bytes")
    if not isinstance(digest, bytes):
        raise TypeError("digest 必须是 bytes")
    if len(salt) < MIN_SALT_BYTES:
        raise ValueError(f"salt 不得短于 {MIN_SALT_BYTES} 字节")
    if len(digest) != DIGEST_BYTES:
        raise ValueError(f"digest 必须恰好为 {DIGEST_BYTES} 字节")
    if not isinstance(iterations, int):
        raise TypeError("iterations 必须是 int")
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"iterations 不得小于 {MIN_ITERATIONS}")

    return "$".join(
        (
            ALGORITHM,
            str(iterations),
            _b64_encode(salt),
            _b64_encode(digest),
        )
    )


# 缺陷 5：解析时严格校验迭代下限，迭代为 1 的记录不得通过；同时做全字段
# 严格校验，任何一条不满足都抛 ValueError，不返回半成品。
def decode(encoded: str) -> dict[str, Any]:
    """解析并严格校验 encode 产生的存储字符串。

    返回：
        {
            "algorithm": "pbkdf2_sha256",
            "iterations": int,
            "salt": bytes,
            "digest": bytes,
        }

    校验规则（任一不满足都必须抛 ValueError，不得返回半成品）：
        1. encoded 是 str，且按美元符号切分后恰好四段。
        2. 第一段必须是已知算法名 pbkdf2_sha256。
        3. 第二段是十进制无前导零整数，且不小于 100000。
        4. 第三段是合法 URL 安全 base64，解码后长度不小于 16。
        5. 第四段是合法 URL 安全 base64，解码后长度恰好为 32。
        6. 不接受填充等号、空白、控制字符或其他多余字符。

    异常：
        TypeError: encoded 不是 str。
        ValueError: 上述任一规则不满足。

    契约要点：迭代下限必须在这里校验；一条迭代为 1 的记录不得通过。
    """
    if not isinstance(encoded, str):
        raise TypeError("encoded 必须是 str")

    parts = encoded.split("$")
    if len(parts) != 4:
        raise ValueError("存储串必须恰好包含四段")

    algorithm, iteration_field, salt_field, digest_field = parts
    if algorithm != ALGORITHM:
        raise ValueError(f"未知算法: {algorithm!r}")

    if not _INTEGER_RE.match(iteration_field):
        raise ValueError("迭代次数字段必须是无前导零的十进制整数")
    iterations = int(iteration_field)
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"iterations 不得小于 {MIN_ITERATIONS}")

    salt = _b64_decode(salt_field)
    if len(salt) < MIN_SALT_BYTES:
        raise ValueError(f"salt 不得短于 {MIN_SALT_BYTES} 字节")

    digest = _b64_decode(digest_field)
    if len(digest) != DIGEST_BYTES:
        raise ValueError(f"digest 必须恰好为 {DIGEST_BYTES} 字节")

    return {
        "algorithm": algorithm,
        "iterations": iterations,
        "salt": salt,
        "digest": digest,
    }


# 缺陷 6：摘要比较必须走 hmac.compare_digest 恒定时间比较，禁止普通等号。
# 缺陷 7：记录非法时返回 False（不可用），绝不向调用方抛异常绕过上层判断。
def verify(password: str, encoded: str) -> bool:
    """校验明文密码是否与存储字符串匹配。

    流程：
        1. 调用 decode 解析记录。
        2. 使用记录中的盐与迭代次数调用 derive。
        3. 用 hmac.compare_digest 比较派生摘要与记录摘要，必须恒定时间，
           禁止使用普通等号比较 bytes。

    返回：
        完全匹配返回 True，否则返回 False。容差为 0，不接受前缀匹配、
        长度容差或大小写不敏感比较。

    异常：
        不向调用方抛出异常。encoded 格式非法、字段非法、算法未知、迭代低于
        下限、base64 损坏、类型错误等任何情况都返回 False。调用方不得被
        异常绕过，也不得靠捕获异常判断密码错误。
    """
    try:
        record = decode(encoded)
        candidate = derive(
            password,
            record["salt"],
            record["iterations"],
        )
    except Exception:
        return False

    return hmac.compare_digest(candidate, record["digest"])


# 缺陷 8：算法与迭代两个维度都要比较；记录无法解析本身也意味着需要升级。
def needs_rehash(encoded: str, policy: dict[str, Any]) -> bool:
    """判断一条存储记录是否需要按当前策略升级。

    返回 True 的条件（任一满足）：
        1. encoded 无法解析或字段非法。
        2. 记录中的算法与 policy["algorithm"] 不同。
        3. 记录中的迭代次数小于 policy["iterations"]。
    只有算法相同且迭代次数不小于策略值时返回 False。

    参数：
        encoded: 存储字符串。
        policy:  至少包含 algorithm、iterations、salt_bytes 三个键，且应能
                 通过 validate_policy 校验。

    契约要点：算法和迭代两个维度都要比较；只比较算法会让弱迭代记录永远
    不升级。
    """
    try:
        record = decode(encoded)
    except (TypeError, ValueError):
        return True

    if record["algorithm"] != policy["algorithm"]:
        return True
    if record["iterations"] < policy["iterations"]:
        return True
    return False


# 缺陷 9：盐长度下限必须独立校验；三个维度全部检查，问题一次性列全。
def validate_policy(policy: dict[str, Any]) -> list[str]:
    """校验密码策略，返回问题码列表，空列表表示策略合格。

    参数：
        policy: 至少包含以下键的 dict：
                algorithm:  算法名，必须为 pbkdf2_sha256。
                iterations: 迭代次数，int 且不小于 100000。
                salt_bytes: 盐长度，int 且不小于 16。

    返回：
        按固定顺序排列的问题码列表：
            unknown_algorithm    算法不在支持列表
            iterations_too_low   迭代次数缺失、类型错误或小于 100000
            salt_too_short       盐长度缺失、类型错误或小于 16

    异常：
        TypeError: policy 不是 dict。

    契约要点：盐长度下限必须检查；三个维度独立检查，问题应全部列出而不是
    在第一个错误处提前返回。
    """
    if not isinstance(policy, dict):
        raise TypeError("policy 必须是 dict")

    problems: list[str] = []

    if policy.get("algorithm") != ALGORITHM:
        problems.append("unknown_algorithm")

    iterations = policy.get("iterations")
    if not isinstance(iterations, int) or iterations < MIN_ITERATIONS:
        problems.append("iterations_too_low")

    salt_size = policy.get("salt_bytes")
    if not isinstance(salt_size, int) or salt_size < MIN_SALT_BYTES:
        problems.append("salt_too_short")

    return problems


# 缺陷 10：每条记录独立调熵源生成新盐，禁止整批复用同一份盐。
def hash_batch(
    records: Iterable[dict[str, Any]], policy: dict[str, Any]
) -> dict[str, str]:
    """按统一策略批量哈希用户记录，每条记录独立生成盐。

    参数：
        records: 可迭代对象，元素为 dict，至少包含：
                 username: 非空 str，作为结果字典的键，同批内不得重复。
                 password: str，明文密码。
        policy:  除 algorithm、iterations、salt_bytes 外，还必须包含：
                 entropy: 可调用对象，签名为 entropy(n) -> bytes，作为盐的
                          唯一随机源。

    返回：
        {username: encoded_string}，与输入记录一一对应。

    行为要求：
        1. 先调用 validate_policy 校验策略，有问题则抛 ValueError。
        2. 每条记录都重新调用 salt_bytes(policy["entropy"], policy["salt_bytes"])，
           不得复用盐。
        3. 每条记录独立 derive、encode，不共享中间状态。

    异常：
        TypeError: policy 或 records 结构不符合约定。
        ValueError: 策略不合格、username 重复或记录字段非法。
    """
    if not isinstance(policy, dict):
        raise TypeError("policy 必须是 dict")

    problems = validate_policy(policy)
    if problems:
        raise ValueError(f"策略不合格: {problems}")

    entropy = policy.get("entropy")
    if not callable(entropy):
        raise TypeError("policy['entropy'] 必须是可调用对象")

    salt_size = policy["salt_bytes"]
    iterations = policy["iterations"]
    result: dict[str, str] = {}

    for record in records:
        if not isinstance(record, dict):
            raise TypeError("每条记录都必须是 dict")

        username = record.get("username")
        password = record.get("password")
        if not isinstance(username, str) or not username:
            raise ValueError("username 必须是非空 str")
        if not isinstance(password, str):
            raise ValueError("password 必须是 str")
        if username in result:
            raise ValueError(f"username 重复: {username!r}")

        # 每条记录独立取盐、独立派生，互不共享盐或中间状态。
        salt = salt_bytes(entropy, salt_size)
        digest = derive(password, salt, iterations)
        result[username] = encode(salt, digest, iterations)

    return result
