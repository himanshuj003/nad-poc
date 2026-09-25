# Network Anomaly Detector — Proof of Concept

**Simplest variant.** One Python script. No packages, no dashboard, no CLI framework.

Demonstrates:
- Synthetic network flow generation with injected attacks
- Statistical anomaly detection (robust MAD / modified Z-score)
- Rule-based signatures (port scan, SYN flood, large transfer, etc.)
- Basic evaluation (precision / recall / F1)

## Run

```bash
pip install numpy pandas
python anomaly_detector_poc.py
python anomaly_detector_poc.py --samples 5000 --threshold 4.0
```

## Dependencies

Only `numpy` and `pandas`.

## Sibling projects

- [nad-cli](https://github.com/himanshuj003/nad-cli) — full command-line tool
- [nad-dashboard](https://github.com/himanshuj003/nad-dashboard) — Streamlit web UI
- [nad-scaffold](https://github.com/himanshuj003/nad-scaffold) — complete production scaffold
- Combined: [network-anomaly-detector](https://github.com/himanshuj003/network-anomaly-detector)
