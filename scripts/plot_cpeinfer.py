"""Plot the held-out precision-recall curve of cpeinfer against the string-match baseline.

Reads results/cpeinfer/precision_coverage.csv and summary.json; writes docs/cpeinfer_precision_recall.png.
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

root = Path(__file__).resolve().parents[1]
res = root / "results" / "cpeinfer"
curve = pd.read_csv(res / "precision_coverage.csv").dropna(subset=["vendor_product_precision"])
s = json.loads((res / "summary.json").read_text())
t, b = s["test"]["vendor_product"], s["baseline"]["vendor_product"]

fig, ax = plt.subplots(figsize=(8, 4.4))
ax.plot(100 * curve["vendor_product_recall"], 100 * curve["vendor_product_precision"], color="#1f77b4",
        label="resolver (vendor:product), threshold 0.05-0.99")
ax.plot(100 * curve["vendor_recall"], 100 * curve["vendor_precision"], color="#aec7e8", ls="--",
        label="resolver (vendor only)")
ax.scatter([100 * t["recall"]], [100 * t["precision"]], color="#d62728", zorder=5,
           label=f"operating point (threshold {s['threshold']:.2f} from validation)")
ax.scatter([100 * b["recall"]], [100 * b["precision"]], color="black", marker="s", zorder=5,
           label="string-match baseline")
ax.axhline(100 * s["min_precision"], color="grey", lw=0.8, ls=":")
ax.set_xlabel(f"% of NIST vendor:product pairs recovered (recall), {s['counts']['test']:,} held-out {s['test_year']} CVEs")
ax.set_ylabel("% of proposed CPEs that are correct")
ax.set_ylim(min(70, 100 * curve["vendor_product_precision"].min() - 2), 100.5)
ax.set_xlim(0, 100)
ax.set_title(f"CNA affected block -> NVD CPE: trained on {'-'.join(map(str, s['train_years']))}, tested on {s['test_year']}")
ax.legend(fontsize=8, loc="lower left")
fig.tight_layout()
out = root / "docs" / "cpeinfer_precision_recall.png"
fig.savefig(out, dpi=150)
print(f"wrote {out}")
