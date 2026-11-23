"""让仓库根目录进入导入路径，保证 pwhash 可被 tests 直接导入。"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
