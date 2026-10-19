"""NF4 quantized-inference study on CPU (no GPU required).

Run:  python scripts/nf4_study.py
Measures relative error / cosine similarity / compression for NF4-quantized
linear layers of several shapes. All numbers are measured by this run.
"""

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zksafeguard.quant.nf4 import nf4_dot_error


def main() -> int:
    rng = np.random.default_rng(0)
    shapes = [(128, 128), (512, 256), (1024, 512)]
    results = []
    print("=== NF4 quantization study (measured) ===")
    print(f"{'shape':>12} {'rel L2 err':>12} {'cosine':>9} {'compression':>12}")
    for shape in shapes:
        W = rng.normal(0, 0.02, size=shape)
        x = rng.normal(0, 1.0, size=shape[1])
        stats = nf4_dot_error(W, x)
        results.append({"shape": shape, **stats})
        print(f"{str(shape):>12} {stats['relative_error_l2']:>12.4f} "
              f"{stats['cosine_similarity']:>9.4f} {stats['compression_ratio']:>11.1f}x")
    out = Path(__file__).resolve().parents[1] / "outputs"
    out.mkdir(exist_ok=True)
    (out / "nf4_study.json").write_text(json.dumps(results, indent=2))
    print("\nFinding: NF4 keeps cosine similarity high for typical weight scales; "
          "exact numbers above are machine-measured, not claimed benchmarks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
