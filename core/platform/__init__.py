"""平台适配层：只做「与操作系统打交道」的事，不含业务判断。

## 与标准库 ``platform`` 的同名冲突（务必看这段）

本项目历史上是**扁平模块**布局：入口把 ``core/`` 直接塞进 ``sys.path``，
于是 ``import tshark`` / ``import analyzer`` 这样的写法才能用。代价是
``core/`` 里的任何文件名都会「遮住」同名标准库模块 —— 本包就叫 ``platform``。

实测后果（不是假设）：Scapy 在被动监听引擎初始化时会执行
``import platform; platform.release()``，命中本包后抛
``AttributeError: module 'platform' has no attribute 'release'``，
Scapy 引擎因此不可用（``tests/selftest.py`` §3 抓到）。

两种根治方向，当前选了后者：

1. 全面改成包内导入、不再把 ``core/`` 加进 ``sys.path`` —— 会把 PR1
   从「只加不改」变成大范围改动，风险不可控；
2. **自愈垫片**：检测到「自己被当作顶层 ``platform`` 导入」时，从 ``sys.path``
   里**排除 core/ 之后**重新定位标准库那份，把它的公开属性镜像到当前模块对象上，
   让调用方拿到的就是标准库；本包自身只在 ``core.platform`` 名下提供能力。

注意定位方式：本项目用的是便携版**嵌入式 Python**，标准库打包在
``tools/python/python311.zip`` 里，**没有** ``Lib/platform.py`` 这个文件。
所以不能用「拼 ``os.__file__`` 同级路径」的写法，必须走
``importlib.machinery.PathFinder`` 让导入系统自己去 zip / 目录里找。

第 2 种是**有意的妥协**：它保证 ``import platform`` 在任何路径下都返回标准库，
同时不动现有 4700 行代码的导入方式。等目录收敛完成后，这段可以删。
"""

import os
import sys

if __name__ == "platform":
    # ---- 被 `import platform` 命中：交出标准库实现，自己退场 ----
    import importlib.machinery
    import importlib.util

    _mirror: dict = {}
    try:
        # core/ 目录就是本文件的上上级：排除它才能找到「没有本包遮蔽」的那份
        _core_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _search = [p for p in sys.path
                   if os.path.abspath(p or os.curdir) != _core_dir]
        _spec = importlib.machinery.PathFinder.find_spec("platform", _search)
        if _spec is not None and _spec.loader is not None:
            _real = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_real)      # 标准库 platform 不会反向 import platform
            sys.modules["platform"] = _real      # 之后所有 import 直接命中真身
            # 本次导入的调用方拿到的是**当前**这个模块对象（import 机制返回的是它），
            # 所以必须把真身的公开属性镜像过来，否则 `platform.release()` 仍然不存在。
            _mirror = {k: v for k, v in vars(_real).items() if not k.startswith("__")}
            globals().update(_mirror)
    except Exception:                            # noqa: BLE001  极端环境下宁可空着也不崩
        _mirror = {}
    __all__ = list(_mirror)
else:
    # ---- 正常身份 core.platform：提供真正的平台适配能力 ----
    from . import paths, winapi  # noqa: F401  re-export

    __all__ = ["paths", "winapi"]
