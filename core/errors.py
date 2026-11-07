"""错误码与可展示异常。

为什么要统一（对应评审 4.5）：现有 HTTP 层有三种错误形态混用——
``{"ok": false, "error": "..."}``、纯文本 404、以及未捕获异常导致的 500。
前端只能靠猜。这里给每个可预期的失败一个稳定 ``code`` + ``hint``，
既能进 envelope，也能直接展示给一线运维。
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # ---- 环境 / 依赖 ----
    """稳定错误码。前端按 ``code`` 分支处理，不靠匹配中文文案。

    分四组：环境/依赖（``E_NO_*`` / ``E_NOT_WRITABLE``）、输入（``E_BAD_*`` /
    ``E_EMPTY_CAPTURE``）、任务（``E_JOB_*``）、AI 与外发（``E_AI_*``）。
    """
    NO_ROOT = "E_NO_ROOT"
    NO_TSHARK = "E_NO_TSHARK"
    NO_NPCAP = "E_NO_NPCAP"
    NO_ADMIN = "E_NO_ADMIN"
    NO_INTERFACE = "E_NO_INTERFACE"
    NOT_WRITABLE = "E_NOT_WRITABLE"
    # ---- 输入 ----
    BAD_TARGET = "E_BAD_TARGET"
    BAD_PCAP = "E_BAD_PCAP"
    BAD_PARAM = "E_BAD_PARAM"
    EMPTY_CAPTURE = "E_EMPTY_CAPTURE"
    # ---- 任务 ----
    JOB_BUSY = "E_JOB_BUSY"
    JOB_NOT_FOUND = "E_JOB_NOT_FOUND"
    JOB_CANCELLED = "E_JOB_CANCELLED"
    # ---- AI / 外发 ----
    AI_NOT_CONFIGURED = "E_AI_NOT_CONFIGURED"
    AI_UPSTREAM = "E_AI_UPSTREAM"
    AI_BAD_OUTPUT = "E_AI_BAD_OUTPUT"
    # ---- 其他 ----
    INTERNAL = "E_INTERNAL"
    NOT_IMPLEMENTED = "E_NOT_IMPLEMENTED"


#: 常见错误的默认提示语（可直接显示给用户）。
HINTS: dict[ErrorCode, str] = {
    ErrorCode.NO_TSHARK: "请确认 tools/WiresharkPortable/App/Wireshark/tshark.exe 存在",
    ErrorCode.NO_NPCAP: "以管理员身份运行 start.bat 完成 Npcap 安装，或改用「分析抓包文件」打开 pcap",
    ErrorCode.NO_ADMIN: "右键以管理员身份运行 start.bat；无提权时用分析抓包文件",
    ErrorCode.NOT_WRITABLE: "U 盘可能处于写保护或只读盘符，请检查物理写保护开关",
    ErrorCode.EMPTY_CAPTURE: "换一块网卡重抓 30 秒，或把目标留空后重试",
    ErrorCode.AI_NOT_CONFIGURED: "点右上角「AI 设置」填入 Key 并测试连接",
    ErrorCode.AI_BAD_OUTPUT: "模型输出未通过结构校验，已回退为本地规则结论",
}


class DiagError(Exception):
    """可预期失败。``message`` 面向用户，``hint`` 面向「下一步怎么办」。"""

    def __init__(self, code: ErrorCode, message: str, hint: str = "",
                 http_status: int = 500, **detail) -> None:
        super().__init__(message)
        self.code = ErrorCode(code)
        self.message = message
        self.hint = hint or HINTS.get(self.code, "")
        self.http_status = http_status
        self.detail = detail

    def to_dict(self) -> dict:
        """转成响应信封里的 ``error`` 对象。

        Returns:
            dict: 键 ``code``（``ErrorCode.value``）/ ``message`` / ``hint``；
                构造时带了附加参数的话再加 ``detail``。
        """
        out = {"code": self.code.value, "message": self.message, "hint": self.hint}
        if self.detail:
            out["detail"] = self.detail
        return out

    def __str__(self) -> str:  # 日志单行可读
        return f"[{self.code.value}] {self.message}" + (f"｜{self.hint}" if self.hint else "")


__all__ = ["ErrorCode", "HINTS", "DiagError"]
