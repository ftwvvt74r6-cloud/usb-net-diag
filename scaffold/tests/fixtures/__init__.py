"""pcap 样本生成器包（脚本，不是测试模块）。

同时提供 ``__init__.py`` 是为了让测试可以 ``from tests.fixtures import gen_pcap``
复用生成逻辑（例如「两次生成字节一致」的确定性断言）。
"""
