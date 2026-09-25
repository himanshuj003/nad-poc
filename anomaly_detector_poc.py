#!/usr/bin/env python3
"""
Network Anomaly Detector — Simple Proof of Concept
====================================================
One script. No package layout. Demonstrates:
  - Synthetic network flow generation with injected attacks
  - Statistical (MAD) anomaly detection
  - Rule-based signatures (port scan, SYN flood, etc.)
  - Quick evaluation when labels exist

Run:
  python anomaly_detector_poc.py
  python anomaly_detector_poc.py --samples 3000 --threshold 4.0
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta

import numpy as np
import pandas as pd


def generate_flows(n: int = 2000, anomaly_ratio: float = 0.05, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    start = datetime.now() - timedelta(hours=1)
    n_anom = max(1, int(n * anomaly_ratio))
    n_norm = n - n_anom

    duration = rng.exponential(2.5, n_norm).clip(0.01, 60)
    packets = rng.lognormal(3.0, 1.0, n_norm).astype(int).clip(1, 3000)
    bytes_ = (packets * rng.uniform(40, 1200, n_norm)).astype(int)

    normal = pd.DataFrame({
        "packet_count": packets,
        "byte_count": bytes_,
        "duration_sec": np.round(duration, 3),
        "packets_per_sec": np.round(packets / duration, 2),
        "bytes_per_sec": np.round(bytes_ / duration, 2),
        "syn_count": rng.integers(0, 3, n_norm),
        "rst_count": rng.integers(0, 2, n_norm),
        "unique_dst_ports": rng.integers(1, 5, n_norm),
        "dst_port": rng.choice([80, 443, 22, 53, 8080, 3306], n_norm),
        "is_anomaly": 0,
    })

    rows = []
    types = rng.choice(["port_scan", "ddos", "exfil", "rare_port", "rst"], n_anom)
    for t in types:
        if t == "port_scan":
            rows.append({
                "packet_count": int(rng.integers(50, 300)),
                "byte_count": int(rng.integers(2000, 15000)),
                "duration_sec": float(rng.uniform(0.5, 4)),
                "syn_count": int(rng.integers(0, 5)),
                "rst_count": int(rng.integers(0, 3)),
                "unique_dst_ports": int(rng.integers(40, 150)),
                "dst_port": int(rng.integers(1, 1024)),
                "is_anomaly": 1,
            })
        elif t == "ddos":
            pk = int(rng.integers(8000, 40000))
            dur = float(rng.uniform(0.1, 1.5))
            rows.append({
                "packet_count": pk,
                "byte_count": pk * int(rng.integers(60, 150)),
                "duration_sec": dur,
                "syn_count": int(rng.integers(100, 800)),
                "rst_count": int(rng.integers(0, 10)),
                "unique_dst_ports": int(rng.integers(1, 3)),
                "dst_port": 80,
                "is_anomaly": 1,
            })
        elif t == "exfil":
            rows.append({
                "packet_count": int(rng.integers(3000, 15000)),
                "byte_count": int(rng.integers(8_000_000, 40_000_000)),
                "duration_sec": float(rng.uniform(40, 200)),
                "syn_count": 1,
                "rst_count": 0,
                "unique_dst_ports": 1,
                "dst_port": 443,
                "is_anomaly": 1,
            })
        elif t == "rare_port":
            rows.append({
                "packet_count": int(rng.integers(10, 200)),
                "byte_count": int(rng.integers(500, 50000)),
                "duration_sec": float(rng.uniform(1, 30)),
                "syn_count": 1,
                "rst_count": 0,
                "unique_dst_ports": 1,
                "dst_port": int(rng.choice([31337, 4444, 6667, 1337])),
                "is_anomaly": 1,
            })
        else:
            rows.append({
                "packet_count": int(rng.integers(100, 800)),
                "byte_count": int(rng.integers(5000, 80000)),
                "duration_sec": float(rng.uniform(0.5, 5)),
                "syn_count": int(rng.integers(10, 100)),
                "rst_count": int(rng.integers(40, 300)),
                "unique_dst_ports": int(rng.integers(1, 4)),
                "dst_port": 22,
                "is_anomaly": 1,
            })

    anom = pd.DataFrame(rows)
    anom["packets_per_sec"] = (anom["packet_count"] / anom["duration_sec"].clip(lower=0.01)).round(2)
    anom["bytes_per_sec"] = (anom["byte_count"] / anom["duration_sec"].clip(lower=0.01)).round(2)

    df = pd.concat([normal, anom], ignore_index=True)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


FEATURES = [
    "packet_count", "byte_count", "duration_sec",
    "packets_per_sec", "bytes_per_sec",
    "syn_count", "rst_count", "unique_dst_ports",
]


def statistical_detect(df: pd.DataFrame, threshold: float = 4.5, min_features: int = 2):
    X = np.log1p(df[FEATURES].fillna(0).astype(float))
    med = X.median()
    mad = (X - med).abs().median().replace(0, 1e-9)
    z = 0.6745 * (X - med) / mad
    scores = z.abs().max(axis=1).values
    n_over = (z.abs() > threshold).sum(axis=1).values
    labels = (n_over >= min_features).astype(int)
    return labels, scores


def rule_detect(df: pd.DataFrame):
    labels = np.zeros(len(df), dtype=int)
    scores = np.zeros(len(df), dtype=float)
    for i, row in df.iterrows():
        hits, sev = [], 0.0
        if row["unique_dst_ports"] >= 30:
            hits.append("port_scan"); sev = max(sev, 0.8)
        if row["syn_count"] >= 50:
            hits.append("syn_flood"); sev = max(sev, 0.9)
        if row["rst_count"] >= 20:
            hits.append("rst_storm"); sev = max(sev, 0.7)
        if row["packets_per_sec"] >= 2000:
            hits.append("high_rate"); sev = max(sev, 0.85)
        if row["byte_count"] >= 5_000_000:
            hits.append("large_transfer"); sev = max(sev, 0.75)
        if row["dst_port"] in {31337, 4444, 6667, 1337, 65535}:
            hits.append("suspicious_port"); sev = max(sev, 0.6)
        if row["duration_sec"] < 1.0 and row["packet_count"] > 500:
            hits.append("short_burst"); sev = max(sev, 0.8)
        if hits:
            labels[i] = 1
            scores[i] = sev
    return labels, scores


def evaluate(y_true, y_pred):
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main():
    parser = argparse.ArgumentParser(description="Network Anomaly Detector POC")
    parser.add_argument("-n", "--samples", type=int, default=2000)
    parser.add_argument("-r", "--ratio", type=float, default=0.05)
    parser.add_argument("--threshold", type=float, default=4.5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print("=" * 55)
    print("  Network Anomaly Detector — Proof of Concept")
    print("=" * 55)

    print(f"\n[1] Generating {args.samples} flows (anomaly ratio={args.ratio}) ...")
    df = generate_flows(args.samples, args.ratio, args.seed)
    print(f"    True anomalies: {df['is_anomaly'].sum()}")

    print("\n[2] Statistical (MAD) detection ...")
    stat_labels, stat_scores = statistical_detect(df, threshold=args.threshold)
    m_stat = evaluate(df["is_anomaly"], stat_labels)
    print(f"    Found {stat_labels.sum()}  |  P={m_stat['precision']:.3f}  R={m_stat['recall']:.3f}  F1={m_stat['f1']:.3f}")

    print("\n[3] Rule-based detection ...")
    rule_labels, rule_scores = rule_detect(df)
    m_rule = evaluate(df["is_anomaly"], rule_labels)
    print(f"    Found {rule_labels.sum()}  |  P={m_rule['precision']:.3f}  R={m_rule['recall']:.3f}  F1={m_rule['f1']:.3f}")

    hybrid = ((stat_labels == 1) | (rule_labels == 1)).astype(int)
    m_hyb = evaluate(df["is_anomaly"], hybrid)
    print(f"\n[4] Hybrid (OR) ...")
    print(f"    Found {hybrid.sum()}  |  P={m_hyb['precision']:.3f}  R={m_hyb['recall']:.3f}  F1={m_hyb['f1']:.3f}")

    df["score"] = np.maximum(stat_scores, rule_scores)
    df["predicted"] = hybrid
    top = df[df["predicted"] == 1].nlargest(5, "score")
    print("\n[5] Top 5 predicted anomalies:")
    cols = ["packet_count", "byte_count", "dst_port", "unique_dst_ports", "syn_count", "rst_count", "score", "is_anomaly"]
    print(top[cols].to_string(index=False))

    print("\n" + "=" * 55)
    print("  Done. Extend this script or use the full CLI / dashboard variants.")
    print("=" * 55)


if __name__ == "__main__":
    main()
