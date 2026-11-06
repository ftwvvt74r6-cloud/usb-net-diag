"""采集边界：只有本包能碰 tshark / Npcap / 网卡。"""

from .live import CaptureOutcome, CapturePlan, capture, resolve_interface
from .tshark import TsharkAdapter, find_tshark

__all__ = ["CaptureOutcome", "CapturePlan", "capture", "resolve_interface",
           "TsharkAdapter", "find_tshark"]
