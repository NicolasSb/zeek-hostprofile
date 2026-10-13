#!/usr/bin/env python3
"""Detector comparison on the development days only (Thursday, Friday), to
choose the detector measured on the Wednesday holdout (see README).

Usage: compare.py DATA OUT  (writes OUT/compare.txt)
"""

import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from evaluate import BASELINE, FPRS, SEEDS, day, labels, prep

# Weight of the population statistics in a host's, in windows: a host seen
# in few training windows falls back to the population. Fixed a priori.
SHRINK = 10


def robust_stats(x):
    """Median and robust scale (MAD x 1.4826) per column."""
    med = np.median(x, axis=0)
    return med, 1.4826 * np.median(np.abs(x - med), axis=0)


def zscore(train, test, fs, per_host):
    """Score = largest |z| over the features, z computed against the host's
    own Monday statistics shrunk towards the population (per_host), or
    against the population only."""
    xtr, xte = prep(train, fs), prep(test, fs)
    pop_med, pop_sd = robust_stats(xtr)
    pop_sd = np.where(pop_sd > 0, pop_sd, xtr.std(axis=0))
    pop_sd = np.where(pop_sd > 0, pop_sd, 1.0)
    med = np.tile(pop_med, (len(test), 1))
    sd = np.tile(pop_sd, (len(test), 1))
    if per_host:
        for h, rows in test.groupby("host").indices.items():
            own = xtr[(train.host == h).to_numpy()]
            n = len(own)
            if n == 0:
                continue
            m, s = robust_stats(own)
            w = n / (n + SHRINK)
            med[rows] = w * m + (1 - w) * pop_med
            sd[rows] = np.sqrt(w * s ** 2 + (1 - w) * pop_sd ** 2)
    return [np.abs((xte - med) / sd).max(axis=1)]


def tail_p(ref, x):
    """Two-sided empirical tail probability of x in ref (sorted columns):
    share of ref at least as extreme on the nearer side, smoothed."""
    n = len(ref)
    p = np.empty_like(x)
    for j in range(x.shape[1]):
        below = np.searchsorted(ref[:, j], x[:, j], side="right")
        above = n - np.searchsorted(ref[:, j], x[:, j], side="left")
        p[:, j] = (np.minimum(below, above) + 1) / (n + 1)
    return p


def quantile(train, test, fs, combine):
    """Per feature, -log10 of the tail probability of the window within the
    host's Monday windows, shrunk towards the population's (what the spec's
    per-host quantile sketch would give); combined over features by max or
    sum."""
    xtr, xte = prep(train, fs), prep(test, fs)
    p = tail_p(np.sort(xtr, axis=0), xte)
    for h, rows in test.groupby("host").indices.items():
        own = np.sort(xtr[(train.host == h).to_numpy()], axis=0)
        n = len(own)
        if n:
            p[rows] = (n * tail_p(own, xte[rows]) + SHRINK * p[rows]) / (n + SHRINK)
    s = -np.log10(p)
    return [s.max(axis=1) if combine == "max" else s.sum(axis=1)]


def iforest(train, test, fs):
    out = []
    for seed in SEEDS:
        model = IsolationForest(n_estimators=300, random_state=seed).fit(prep(train, fs))
        out.append(-model.score_samples(prep(test, fs)))
    return out


DETECTORS = {
    "IsolationForest, global": iforest,
    "z-score, global": lambda tr, te, fs: zscore(tr, te, fs, per_host=False),
    "z-score, per host": lambda tr, te, fs: zscore(tr, te, fs, per_host=True),
    "quantile, per host, max": lambda tr, te, fs: quantile(tr, te, fs, "max"),
    "quantile, per host, sum": lambda tr, te, fs: quantile(tr, te, fs, "sum"),
}


def evaluate(scores, test):
    """Per attack: mean AUC and detection at equal false-alarm rates."""
    ben = (test.label == "BENIGN").to_numpy()
    out = {}
    for a in sorted(set(test.label) - {"BENIGN"}):
        att = (test.label == a).to_numpy()
        m = ben | att
        r = {"auc": [], **{f: [] for f in FPRS}}
        for s in scores:
            r["auc"].append(roc_auc_score(att[m], s[m]))
            b = np.sort(s[ben])[::-1]
            for f in FPRS:
                r[f].append((s[att] >= b[max(int(f * ben.sum()), 1) - 1]).mean())
        out[a] = {k: np.mean(v) for k, v in r.items()}
    return out


def main():
    data, out = sys.argv[1], sys.argv[2]
    lab = labels(data)
    train = day(out, "monday", lab)
    dev = pd.concat([day(out, d, lab) for d in ("thursday", "friday")], ignore_index=True)
    cols = [c for c in train.columns if c not in ("ts", "host", "label")]

    res = {(d, fs_name): evaluate(fn(train, dev, fs), dev)
           for d, fn in DETECTORS.items()
           for fs_name, fs in (("Baseline", BASELINE), ("HostProfile", cols))}

    head = "".join(f"{'at ' + format(f, '.1%') + ' FA':>13s}" for f in FPRS)
    lines = ["Development days (Thursday, Friday); every setting learned on Monday.",
             "Values: baseline features -> HostProfile features.", ""]
    for a in res[next(iter(res))]:
        lines.append(f"{a}  ({int((dev.label == a).sum())} windows)")
        lines.append(f"  {'detector':28s}{'AUC':>14s}{head}")
        for d in DETECTORS:
            b, h = res[(d, "Baseline")][a], res[(d, "HostProfile")][a]
            row = f"  {d:28s}{format(b['auc'], '.2f') + ' -> ' + format(h['auc'], '.2f'):>14s}"
            row += "".join(f"{format(b[f], '.0%') + ' -> ' + format(h[f], '.0%'):>13s}" for f in FPRS)
            lines.append(row)
        lines.append("")

    text = "\n".join(lines)
    print(text)
    with open(os.path.join(out, "compare.txt"), "w") as f:
        f.write(text)


if __name__ == "__main__":
    main()
