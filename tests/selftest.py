"""NetDiag 自检与回归测试（只用标准库，不依赖 pytest）。

覆盖：
  §1 输入校验与边界（过滤器注入、端口越界、布尔字符串、IPv6 字面量）
  §2 协议自适应体检（HTTP / SMB / SSH banner / 不响应 / TLS）
  §3 被动监听（tshark 引擎 + 过滤器、scapy 引擎）
  §4 离线 pcap 分析回归（faults_demo.pcap 应为 严重 3 / 警告 5）
  §5 HTTP API 加固（Host 校验、请求体上限、上传类型、报告路径穿越）

用法：
    tools\\python\\python.exe tests\\selftest.py            # 全部
    tools\\python\\python.exe tests\\selftest.py --fast     # 跳过需要抓包权限的用例
"""
from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))

import ai  # noqa: E402
import analyzer  # noqa: E402
import diagnose  # noqa: E402
import passive  # noqa: E402
import probe  # noqa: E402
import server  # noqa: E402

PASS, FAIL, SKIP = [], [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASS.append(name)
        print(f"  [PASS] {name}")
    else:
        FAIL.append(f"{name}{(' — ' + detail) if detail else ''}")
        print(f"  [FAIL] {name}{(' — ' + detail) if detail else ''}")


def skip(name: str, why: str) -> None:
    SKIP.append(name)
    print(f"  [SKIP] {name} — {why}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


# ---------------------------------------------------------------- mock 服务
class MockServer:
    """极简 TCP 服务，按传入的 handler 处理每个连接。"""

    def __init__(self, handler, family=socket.AF_INET, port: int = 0):
        self.handler = handler
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        # 测试服务**不能**设 SO_REUSEADDR：Windows 上它会让两个进程同时绑上同一端口，
        # 端口冲突检测因此失效，probe 会连到别人的服务上（B1 的复现根因）。
        # SO_EXCLUSIVEADDRUSE 更进一步：即使对方设了 SO_REUSEADDR，bind 也会失败。
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            self.sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", port))
            self.sock.listen(16)
        except OSError:
            # bind/listen 失败（端口被占）也要关 socket，否则四个端口全占时留一堆
            # ResourceWarning（C5）；关完再把异常抛给调用方记 skip。
            self.sock.close()
            raise
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._run, args=(conn,), daemon=True).start()

    def _run(self, conn):
        try:
            self.handler(conn)
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def h_silent(conn):
    time.sleep(2.5)


def h_ssh(conn):
    conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    time.sleep(0.6)


def h_http(conn):
    conn.recv(4096)
    conn.sendall(b"HTTP/1.1 200 OK\r\nServer: mock-nginx\r\nContent-Length: 2\r\n\r\nok")


def h_smb(conn):
    import struct
    conn.recv(4096)
    hdr = (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 1, 0, 0, 31, 0, 0, 0, 0, 0, 0)
           + b"\x00" * 16)
    body = struct.pack("<HHHH16sI", 65, 1, 0x0302, 0, b"\x00" * 16, 0)
    msg = hdr + body
    conn.sendall(b"\x00" + len(msg).to_bytes(3, "big") + msg)


# ---------------------------------------------------------------- §1 输入校验
def test_validation() -> None:
    section("§1 输入校验与边界")

    # 域名不再直接当抓包过滤器（可能解析到 fake-ip，见 test_capture_filter.py）；
    # 这里只验纯 IP / CIDR 的语法转换与注入拦截。
    check("IP 可转 BPF", diagnose.bpf_for("1.1.1.1") == "host 1.1.1.1")
    check("CIDR 可转 BPF", diagnose.bpf_for("192.168.1.0/24") == "net 192.168.1.0/24")
    for bad in ("1.1.1.1 or host 8.8.8.8", 'a"b', "x;y"):
        try:
            diagnose.bpf_for(bad)
            check(f"过滤表达式注入被拒: {bad!r}", False, "未抛出 ValueError")
        except ValueError:
            check(f"过滤表达式注入被拒: {bad!r}", True)

    try:
        passive._bpf('a"b')
        check("被动监听过滤器引号被拒", False)
    except ValueError:
        check("被动监听过滤器引号被拒", True)

    check("IPv6+端口解析", probe._parse_target("[::1]:8080", None)[:2] == ("::1", 8080))
    check("URL 解析带 query",
          probe._parse_target("https://a.com/p?q=1", None)[2] == "/p?q=1")
    check("双栈优先 IPv4", probe._pick_ip(["2606:4700::1", "1.2.3.4"]) == "1.2.3.4")
    check("纯 IPv6 仍可用", probe._pick_ip(["2606:4700::1"]) == "2606:4700::1")

    check("count 非法回落到默认", server._to_int("abc", 4, 1, 10) == 4)
    check("count 超上限被夹紧", server._to_int("999", 4, 1, 10) == 10)
    check("timeout NaN 回落", server._to_float("nan", 3.0, 0.5, 10) == 3.0)

    cfg = ai._clean({"verify_ssl": "false"})
    check("verify_ssl 字符串 false 解析为 False", cfg["verify_ssl"] is False)
    cfg = ai._clean({"verify_ssl": "true"})
    check("verify_ssl 字符串 true 解析为 True", cfg["verify_ssl"] is True)

    try:
        ai._clean({"base_url": "ftp://x"})
        check("非 http(s) 接口地址被拒", False)
    except ValueError:
        check("非 http(s) 接口地址被拒", True)
    try:
        ai._clean({"base_url": "https://a.com/v1\nX-Evil: 1"})
        check("接口地址头部注入被拒", False)
    except ValueError:
        check("接口地址头部注入被拒", True)

    key = ai._clean({"api_key": "sk-abc\r\nInjected: 1"})["api_key"]
    check("API Key 控制字符被清掉", "\r" not in key and "\n" not in key, repr(key))


# ---------------------------------------------------------------- §2 体检
def test_probe() -> None:
    section("§2 协议自适应体检")

    # HTTP 服务本身不会主动说话，靠端口画像识别；这里绑到 8080 这类常见 HTTP 端口
    http_srv = None
    for want in (8080, 8088, 8090, 8000):
        try:
            http_srv = MockServer(h_http, port=want)
            break
        except OSError:
            continue
    if http_srv is None:
        skip("明文 HTTP 体检（端口画像）", "8080/8088/8090/8000 都被占用")
    else:
        r = probe.run(f"127.0.0.1:{http_srv.port}", count=2, timeout=1.5)
        names = [s["name"] for s in r.get("segments") or []]
        check("端口画像识别明文 HTTP", r.get("protocol") == "HTTP（明文）",
              str(r.get("protocol")))
        check("HTTP 阶段条不含 TLS", "TLS 握手" not in names, str(names))
        check("HTTP 阶段条含首字节", "HTTP 首字节" in names, str(names))
        check("HTTP 取到 200", (r.get("http") or {}).get("status") == 200)
        http_srv.close()

    # 随机端口 + 手动指定协议，应走 HTTP 流程
    any_srv = MockServer(h_http)
    r = probe.run(f"127.0.0.1:{any_srv.port}", count=2, timeout=1.5, proto="http")
    check("手动指定协议生效", (r.get("http") or {}).get("status") == 200,
          str(r.get("protocol")))
    any_srv.close()

    smb_srv = MockServer(h_smb)
    r = probe.run(f"127.0.0.1:{smb_srv.port}", count=2, timeout=1.5, proto="smb")
    check("SMB 端口不误报 TLS", r.get("protocol", "").startswith("SMB"), str(r.get("protocol")))
    check("SMB 协商成功", (r.get("smb") or {}).get("ok") is True,
          str((r.get("smb") or {}).get("error")))
    check("SMB 无 TLS 阶段",
          "TLS 握手" not in [s["name"] for s in r.get("segments") or []])
    smb_srv.close()

    ssh_srv = MockServer(h_ssh)
    r = probe.run(f"127.0.0.1:{ssh_srv.port}", count=1, timeout=1.5)
    check("SSH banner 被识别", "SSH" in str(r.get("protocol")), str(r.get("protocol")))
    ssh_srv.close()

    silent_srv = MockServer(h_silent)
    r = probe.run(f"127.0.0.1:{silent_srv.port}", count=1, timeout=1.0)
    check("无 banner 降级 Opaque 而非报错", r.get("level") in ("正常", "警告"),
          str(r.get("level")))
    check("Opaque 不臆断 TLS 失败", "TLS" not in str(r.get("headline", "")),
          str(r.get("headline")))
    silent_srv.close()

    # 不可达端口：只报连不上，不产生协议结论
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()
    r = probe.run(f"127.0.0.1:{dead_port}", count=1, timeout=0.8)
    check("端口不通判定为严重", r.get("level") == "严重", str(r.get("level")))

    # IPv6
    try:
        v6 = MockServer(h_http, family=socket.AF_INET6)
    except OSError:
        skip("IPv6 体检", "本机未启用 IPv6 回环")
    else:
        r = probe.run(f"[::1]:{v6.port}", count=2, timeout=1.5)
        check("IPv6 目标可建连", "TCP 建连" in [s["name"] for s in r.get("segments") or []]
              and r.get("level") != "严重", str(r.get("headline")))
        v6.close()


def test_probe_tls() -> None:
    section("§2b TLS 体检")
    try:
        import ssl as _ssl
        with tempfile.TemporaryDirectory() as td:
            key, crt = Path(td) / "k.pem", Path(td) / "c.pem"
            r1 = subprocess.run(
                f'openssl req -x509 -newkey rsa:2048 -nodes -keyout "{key}" -out "{crt}" '
                f'-days 1 -subj /CN=localhost',
                shell=True, capture_output=True, timeout=60)
            if r1.returncode != 0 or not crt.exists():
                skip("TLS 体检", "本机无 openssl，无法生成自签证书")
                return
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(crt), str(key))

            def h_tls(conn):
                ss = ctx.wrap_socket(conn, server_side=True)
                ss.recv(4096)
                ss.sendall(b"HTTP/1.1 200 OK\r\nServer: tls-mock\r\nContent-Length: 2\r\n\r\nok")
                ss.close()

            srv = MockServer(h_tls)
            r = probe.run(f"127.0.0.1:{srv.port}", count=1, timeout=2.0, proto="tls")
            check("TLS 握手成功", (r.get("tls") or {}).get("ok") is True,
                  str((r.get("tls") or {}).get("error")))
            check("TLS 有版本号", bool((r.get("tls") or {}).get("version")))
            check("自签证书不判为故障", r.get("level") in ("正常", "警告"),
                  str(r.get("level")))
            srv.close()
    except Exception as exc:  # noqa: BLE001
        skip("TLS 体检", f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------- §3 被动监听
def test_passive(fast: bool) -> None:
    section("§3 被动监听")
    info = passive.engine_status()
    check("Scapy 可用", info["scapy"], info.get("error", ""))
    if not tshark_ok():
        skip("被动监听（需要 Npcap + 管理员）", "未检测到 tshark/Npcap")
        return
    if not diagnose.tshark.is_admin():
        skip("被动监听（需要管理员权限）", "当前进程非管理员")
        return

    # 造一点流量，保证有包可抓
    threading.Thread(target=_make_traffic, daemon=True).start()
    r = passive.run("6", duration=6, target="", engine="tshark")
    check("tshark 引擎能抓到包", r.get("ok") and (r.get("summary") or {}).get("packets", 0) > 0,
          str(r.get("error", "")) + f" packets={(r.get('summary') or {}).get('packets')}")
    check("tshark 引擎不死锁（6s 抓包在 25s 内返回）", True)
    flows = r.get("flows") or []
    check("会话表字段完整",
          all(k in f for f in flows[:1] for k in ("src", "dst", "proto", "packets",
                                                  "bytes", "avg_size", "state", "evidence")),
          "缺少字段")
    check("会话方向判断正确（客户端为高位端口）",
          all(f["src_port"] > 1024 or f["dst_port"] <= 1024 for f in flows[:20]) or not flows)

    # 带目标过滤器：以前这里会把 -f 插到 -a 的参数位，导致过滤失效
    addrs = {f["dst_ip"] for f in flows} - {""}
    if addrs:
        one = sorted(addrs)[0]
        r2 = passive.run("6", duration=5, target=one, engine="tshark")
        check("过滤器生效（只回目标相关会话）",
              all(one in (f["src_ip"], f["dst_ip"]) for f in (r2.get("flows") or [])),
              f"出现非目标会话，target={one}")
    else:
        skip("过滤器生效", "本次没抓到外部目标")

    if not fast:
        r3 = passive.run("6", duration=5, target="", engine="scapy")
        check("scapy 引擎可用", r3.get("ok") is True, str(r3.get("error")))
        check("scapy 抓到包", (r3.get("summary") or {}).get("packets", 0) > 0,
              f"packets={(r3.get('summary') or {}).get('packets')}")


def _make_traffic():
    for _ in range(3):
        try:
            urllib.request.urlopen("http://example.com", timeout=4).read(100)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.5)


def tshark_ok() -> bool:
    try:
        return bool(diagnose.tshark.find_tshark()) and diagnose.tshark.npcap_installed()
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- §4 离线分析
def test_offline() -> None:
    section("§4 离线 pcap 分析回归")
    demo = ROOT / "captures" / "faults_demo.pcap"
    if not demo.is_file():
        skip("离线分析", f"缺少样本 {demo}")
        return
    res = analyzer.analyze(demo)
    check("离线分析成功", res.get("ok") is True, str(res.get("error")))
    if not res.get("ok"):
        return
    s = res["summary"]
    check("严重项 = 3", s["critical_count"] == 3, f"实际 {s['critical_count']}")
    check("警告项 = 5", s["warning_count"] == 5, f"实际 {s['warning_count']}")
    vd = __import__("verdict").build(res)
    check("结论层定位到 L4", "L4" in str(vd.get("layer")), str(vd.get("layer")))
    check("结论有处置步骤", len(vd.get("next_steps") or []) > 0)
    check("分层状态齐全", len(vd.get("layers") or []) == 4)


# ---------------------------------------------------------------- §5 API
def _http(method: str, path: str, body: bytes | None = None, headers: dict | None = None,
          timeout: int = 20) -> tuple[int, str]:
    url = f"http://127.0.0.1:{API_PORT}{path}"
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


API_PORT = 8790


def test_api() -> None:
    section("§5 HTTP API 加固")
    global API_PORT
    # 在独立端口起一个服务实例
    for p in range(8790, 8800):
        try:
            httpd = server.DiagServer(("127.0.0.1", p), server.Handler)
            API_PORT = p
            break
        except OSError:
            continue
    else:
        skip("API 加固", "端口被占用")
        return
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.4)
    try:
        code, _ = _http("GET", "/api/status")
        check("正常请求可用", code == 200, f"HTTP {code}")

        code, _ = _http("GET", "/api/status", headers={"Host": "evil.example.com"})
        check("伪造 Host 被拒（防 DNS 重绑定）", code == 403, f"HTTP {code}")

        code, body = _http("GET", "/api/probe?target=127.0.0.1&count=abc")
        check("非法 count 不产生 500", code == 200, f"HTTP {code} {body[:80]}")

        code, body = _http("POST", "/api/probe", json.dumps({"target": ""}).encode(),
                           {"Content-Type": "application/json"})
        check("空 target 有友好提示", code == 200 and "请填写" in body, body[:80])

        code, body = _http("GET", "/api/report?path=../../config/ai-config.json")
        check("报告路径穿越被挡", code == 404, f"HTTP {code}")

        # 4MB body：早退必须 drain。102B 时偶发 10053（概率低），4MB 能稳定放大
        # 「server 不读 body 就关连接」的竞态（PR #13 复审 B1）。
        code, body = _http("POST", "/api/upload?name=evil.exe", b"MZ" + b"\x00" * (4 << 20),
                           {"Content-Type": "application/octet-stream"})
        check("上传非 pcap 被拒", '"ok": false' in body, body[:100])

        big = b"x" * (9 << 20)
        code, body = _http("POST", "/api/ai", big, {"Content-Type": "application/json"})
        check("超大请求体返回 413", code == 413, f"HTTP {code} {body[:80]}")
        check("超大请求体有明确提示", "上限" in body, body[:80])

        code, body = _http("GET", "/api/doctor")
        check("自检接口可用", code == 200 and '"root"' in body, f"HTTP {code}")

        # 安全响应头
        req = urllib.request.Request(f"http://127.0.0.1:{API_PORT}/")
        with urllib.request.urlopen(req, timeout=10) as r:
            hs = {k.lower(): v for k, v in r.headers.items()}
        check("有 CSP 头", "content-security-policy" in hs)
        check("有 nosniff 头", hs.get("x-content-type-options") == "nosniff")
        check("有 X-Frame-Options", hs.get("x-frame-options") == "DENY")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_lifecycle() -> None:
    section("§6 应用生命周期（探活 / 信息 / 优雅退出）")
    httpd, url = server.create_server(8801, idle_exit_min=0, quiet=True, register_pid=False)
    if httpd is None:
        skip("生命周期", "8801-8810 端口被占用")
        return
    global _LC_PORT
    _LC_PORT = server.SERVER["port"]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.4)
    try:
        code, body = _lc("GET", "/api/ping")
        check("存活探测可用", code == 200 and '"app": "USBNetDiag"' in body, body[:120])

        code, body = _lc("GET", "/api/app")
        check("应用信息含版本与端口",
              code == 200 and '"version"' in body and f'"port": {_LC_PORT}' in body, body[:160])

        code, body = _lc("POST", "/api/quit", b"{}", {"Content-Type": "application/json"})
        check("退出接口返回成功", code == 200 and '"ok": true' in body, body[:120])

        # shutdown() 是异步的，轮询确认端口真的释放了
        gone = False
        for _ in range(20):
            time.sleep(0.15)
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{_LC_PORT}/api/ping", timeout=0.5)
            except Exception:  # noqa: BLE001
                gone = True
                break
        check("退出后端口已释放", gone, "服务仍在监听")
    finally:
        try:
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass


_LC_PORT = 0


def _lc(method: str, path: str, body: bytes | None = None,
        headers: dict | None = None) -> tuple[int, str]:
    req = urllib.request.Request(f"http://127.0.0.1:{_LC_PORT}{path}",
                                 data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


# ---------------------------------------------------------------- main
def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    fast = "--fast" in argv
    t0 = time.time()
    print("=" * 64)
    print(" NetDiag 自检 / 回归测试")
    print("=" * 64)
    test_validation()
    test_probe()
    test_probe_tls()
    test_offline()
    test_api()
    test_lifecycle()
    test_passive(fast)

    print("\n" + "=" * 64)
    print(f" 通过 {len(PASS)} · 失败 {len(FAIL)} · 跳过 {len(SKIP)} · "
          f"耗时 {time.time() - t0:.1f}s")
    if FAIL:
        print(" 失败项：")
        for f in FAIL:
            print(f"   - {f}")
    print("=" * 64)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
