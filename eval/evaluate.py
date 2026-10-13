#!/usr/bin/env python3
"""Evaluation of hostprofile_features.log on CICIDS-2017 and CTU-13.

Usage: evaluate.py DATA OUT  (writes OUT/results.txt; protocol in README)
"""

import csv
import io
import os
import sys
import zipfile
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

WINDOW = 300
BASELINE = ["n_conns", "bytes_out", "bytes_in"]
SEEDS = range(10)
ADT = timezone(timedelta(hours=-3))  # CICIDS CSV timestamps: local time
CTU_HOST = "147.32.84.165"  # the infected host of every CTU-13 capture

# Attacks the CICIDS CSVs leave unlabelled, from the dataset documentation
# (local time): the infiltrated host scans the internal network.
DOCUMENTED = [("192.168.10.8", "Infiltration", "06/07/2017 15:04", "06/07/2017 15:45")]


def read_zeek(path):
    with open(path) as f:
        lines = f.read().splitlines()
    cols = next(l for l in lines if l.startswith("#fields")).split("\t")[1:]
    df = pd.DataFrame([l.split("\t") for l in lines if not l.startswith("#")], columns=cols)
    for c in cols:
        if c != "host":
            df[c] = pd.to_numeric(df[c])
    # Row order within a window depends on table iteration: make it fixed.
    return df.sort_values(["ts", "host"], ignore_index=True)


def csv_time(s):
    """CICIDS CSV time: day/month/year, 12-hour clock without AM/PM."""
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            t = datetime.strptime(s.strip(), fmt)
            break
        except ValueError:
            continue
    else:
        return None
    if t.hour < 8:  # working hours: 1:00 means 13:00
        t += timedelta(hours=12)
    return t.replace(tzinfo=ADT).timestamp()


def labels(data):
    """(host, window start) -> attack, from the labelled flows' source host."""
    out = {}
    for host, name, start, end in DOCUMENTED:
        t, stop = csv_time(start), csv_time(end)
        while t < stop:
            out[(host, int(t // WINDOW) * WINDOW)] = name
            t += WINDOW
    with zipfile.ZipFile(os.path.join(data, "GeneratedLabelledFlows.zip")) as z:
        for member in sorted(z.namelist()):
            if not member.endswith(".csv"):
                continue
            r = csv.reader(io.TextIOWrapper(z.open(member), encoding="latin-1"))
            h = [x.strip() for x in next(r)]
            si, ti, li = h.index("Source IP"), h.index("Timestamp"), h.index("Label")
            for row in r:
                if len(row) <= li or row[li].strip() in ("BENIGN", ""):
                    continue
                t = csv_time(row[ti])
                if t is not None:
                    # Brute force / XSS / SQL injection: one attacker, one class.
                    name = "Web Attack" if row[li].startswith("Web Attack") else row[li].strip()
                    out[(row[si], int(t // WINDOW) * WINDOW)] = name
    return out


def day(out, name, lab):
    df = read_zeek(os.path.join(out, name, "hostprofile_features.log"))
    df["label"] = [lab.get((h, int(t)), "BENIGN") for h, t in zip(df.host, df.ts)]
    return df


def prep(df, fs):
    # Heavy-tailed counts: log scale, so a few huge hosts don't dominate.
    return np.log1p(df[fs].clip(lower=0).to_numpy(dtype=float))


FPRS = (0.001, 0.005, 0.01)


def detect(train, test, fs):
    """Per attack, mean / min / max over SEEDS of the AUC and of the share of
    attack windows detected at fixed false-alarm rates (FPRS): the threshold
    leaves that share of the test day's benign windows above it. This
    compares feature sets at equal false alarms; it is not a deployable
    threshold (it uses the test labels)."""
    ben = (test.label == "BENIGN").to_numpy()
    attacks = sorted(set(test.label) - {"BENIGN"})
    runs = {a: {k: [] for k in ("auc",) + FPRS} for a in attacks}
    for seed in SEEDS:
        model = IsolationForest(n_estimators=300, random_state=seed).fit(prep(train, fs))
        score = -model.score_samples(prep(test, fs))
        benign_sorted = np.sort(score[ben])[::-1]
        for a in attacks:
            att = (test.label == a).to_numpy()
            m = ben | att
            runs[a]["auc"].append(roc_auc_score(att[m], score[m]))
            for fpr in FPRS:
                thr = benign_sorted[max(int(fpr * ben.sum()), 1) - 1]
                runs[a][fpr].append((score[att] >= thr).mean())
    return {a: {"n": int((test.label == a).sum()),
                **{k: (np.mean(v), min(v), max(v)) for k, v in r.items()}}
            for a, r in runs.items()}


def detection_table(train, test, cols):
    res = {name: detect(train, test, fs) for name, fs in (("Baseline", BASELINE), ("HostProfile", cols))}
    head = "".join(f"{'at ' + format(f, '.1%') + ' FA':>14s}" for f in FPRS)
    lines = [f"  {'attack':14s}{'windows':>8s}   {'AUC':>24s}{head}"]
    for a in res["HostProfile"]:
        b, h = res["Baseline"][a], res["HostProfile"][a]
        row = f"  {a:14s}{h['n']:8d}   {b['auc'][0]:.2f} -> {h['auc'][0]:.2f} ({h['auc'][1]:.2f}-{h['auc'][2]:.2f})"
        row += "".join(f"{format(b[f][0], '.0%') + ' -> ' + format(h[f][0], '.0%'):>14s}" for f in FPRS)
        lines.append(row)
    return lines


def main():
    data, out = sys.argv[1], sys.argv[2]
    lab = labels(data)
    train = day(out, "monday", lab)
    dev = pd.concat([day(out, d, lab) for d in ("thursday", "friday")], ignore_index=True)
    holdout = day(out, "tuesday", lab)
    cols = [c for c in train.columns if c not in ("ts", "host", "label")]
    benign = pd.concat([d[d.label == "BENIGN"] for d in (train, dev, holdout)], ignore_index=True)

    lines = ["Detector trained on Monday (benign); values: baseline -> HostProfile,",
             "mean over 10 seeds (HostProfile AUC range in parentheses); detection",
             "compared at equal false-alarm rates (FA) on the test benign windows.", "",
             "Development days (Thursday, Friday):"]
    lines += detection_table(train, dev, cols)
    lines += ["", "Tuesday (nothing tuned on it; first holdout, see README):"]
    lines += detection_table(train, holdout, cols)
    if os.path.exists(os.path.join(out, "wednesday", "hostprofile_features.log")):
        lines += ["", "Holdout (Wednesday, attacks never seen during development):"]
        lines += detection_table(train, day(out, "wednesday", lab), cols)

    lines += ["", "CTU-13 infected host vs CICIDS benign windows, rhythm features alone",
              "(AUC of \"more regular than benign\"; undefined (-1) counts as irregular):",
              f"  {'botnet':10s}{'windows':>8s}{'start_cv':>10s}{'beacon_cv':>11s}"]
    for d in sorted(x for x in os.listdir(out) if x.startswith("ctu13-")):
        bot = read_zeek(os.path.join(out, d, "hostprofile_features.log"))
        bot = bot[bot.host == CTU_HOST]
        y = np.r_[np.zeros(len(benign)), np.ones(len(bot))]
        aucs = []
        for c in ("start_cv", "beacon_cv"):
            x = np.r_[benign[c], bot[c]]
            aucs.append(roc_auc_score(y, -np.where(x < 0, 1e9, x)))
        lines.append(f"  {d[6:]:10s}{len(bot):8d}{aucs[0]:10.2f}{aucs[1]:11.2f}")

    text = "\n".join(lines) + "\n"
    print(text, end="")
    with open(os.path.join(out, "results.txt"), "w") as f:
        f.write(text)


if __name__ == "__main__":
    main()
