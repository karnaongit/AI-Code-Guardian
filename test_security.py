from pathlib import Path
from guardian.core.pipeline import ScanPipeline
import json

p = ScanPipeline()
res = p.scan(Path('./vuln_test.py').parent, business_requirements=None)
print("TOTAL FINDINGS:", len(res["scan"]["findings"]))
