"""Plot per-tool component and edge precision/recall from results/summary.json into docs/tool_accuracy.png."""

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

root = Path(__file__).resolve().parents[1]
summary = json.loads((root / (sys.argv[1] if len(sys.argv) > 1 else "results/summary.json")).read_text())
tools = [t for t in summary["tools"] if t.endswith("(cdx)")]
metrics = [("components.all", "precision", "Component precision"), ("components.all", "recall", "Component recall"),
           ("edges.all", "precision", "Edge precision"), ("edges.all", "recall", "Edge recall")]
colors = ["#1f77b4", "#aec7e8", "#d62728", "#ff9896"]

fig, ax = plt.subplots(figsize=(9, 4.2))
width = 0.2
for j, (part, kind, label) in enumerate(metrics):
    vals = [100 * (summary["tools"][t][part][kind] or 0) for t in tools]
    bars = ax.bar([i + (j - 1.5) * width for i in range(len(tools))], vals, width, label=label, color=colors[j])
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 1, f"{v:.0f}", ha="center", fontsize=7)
ax.set_xticks(range(len(tools)))
ax.set_xticklabels([f"{t.replace(' (cdx)', '')}\n({summary['tools'][t]['sboms']} SBOMs)" for t in tools])
ax.set_ylabel("% against lockfile ground truth")
ax.set_ylim(0, 112)
ax.set_title("Default-settings SBOMs vs. the shipped dependency graph in the lockfile (CycloneDX output)")
ax.legend(ncol=4, fontsize=8, loc="upper left")
fig.tight_layout()
out = root / "docs" / "tool_accuracy.png"
out.parent.mkdir(exist_ok=True)
fig.savefig(out, dpi=150)
print(f"wrote {out}")
