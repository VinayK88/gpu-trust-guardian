"""Build four reader-facing notebooks from checked-in synthetic evidence."""

from __future__ import annotations

import json
from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).resolve().parents[1]
EVALUATION = json.loads((ROOT / "reports" / "evaluation.json").read_text(encoding="utf-8"))
COMPROMISED = json.loads((ROOT / "reports" / "compromised-report.json").read_text(encoding="utf-8"))
POLICY = json.loads((ROOT / "reports" / "policy-matrix.json").read_text(encoding="utf-8"))

NVIDIA = "#76B900"
ORANGE = "#f97316"
BLUE = "#2563eb"
GOLD = "#d9a404"
PINK = "#db2777"
INK = "#172033"
GRID = "#e5e7eb"


def markdown(value: str):
    return nbf.v4.new_markdown_cell(value.strip())


def code(value: str):
    return nbf.v4.new_code_cell(value.strip())


def notebook(cells: list) -> nbf.NotebookNode:
    document = nbf.v4.new_notebook(cells=cells)
    document.metadata.kernelspec = {
        "display_name": "Python 3",
        "language": "python",
        "name": "python3",
    }
    document.metadata.language_info = {"name": "python", "version": "3.11"}
    return document


def common_setup() -> str:
    return f"""
from pathlib import Path
import json
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path.cwd().resolve()
while ROOT != ROOT.parent and not (ROOT / "pyproject.toml").exists():
    ROOT = ROOT.parent
if not (ROOT / "pyproject.toml").exists():
    raise RuntimeError("Run this notebook from the repository or a child directory")
sys.path.insert(0, str(ROOT / "src"))

NVIDIA = "{NVIDIA}"
ORANGE = "{ORANGE}"
BLUE = "{BLUE}"
GOLD = "{GOLD}"
PINK = "{PINK}"
INK = "{INK}"
GRID = "{GRID}"
plt.rcParams.update({{
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": INK,
    "axes.labelcolor": INK,
    "axes.titlecolor": INK,
    "text.color": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "font.size": 11,
    "axes.titlepad": 30,
}})
"""


def build_fingerprint_notebook() -> nbf.NotebookNode:
    supervised = EVALUATION["supervised_random_forest"]
    unsupervised = EVALUATION["benign_only_isolation_forest"]
    population = EVALUATION["population"]
    return notebook(
        [
            markdown("""
            # 01 · GPU Digital Fingerprinting & Threat Classification

            A reproducible comparison of supervised and benign-only anomaly detection for synthetic GPU workload behavior.
            """),
            markdown(f"""
            ## tl;dr

            Across **{population['test_rows']} held-out challenge events**, the bounded Random Forest reaches **{supervised['f1']:.1%} F1** with **{supervised['recall']:.1%} recall**. The benign-only Isolation Forest reaches **{unsupervised['f1']:.1%} F1**. The supervised model catches more known patterns; the anomaly model needs no attack labels but misses more evasive cases.
            """),
            markdown("""
            ## Context & Methods

            We model GPU telemetry as a digital fingerprint: utilization, memory pressure, power, egress, image trust, privilege, host access, and model access. The train/test assignment deliberately holds out some lower-signal attack variants.

            ### Key Assumptions

            - Every row and attack label is synthetic; metrics validate code paths, not production performance.
            - Attestation is excluded from the behavior classifier so hardware trust cannot leak the label.
            - A high anomaly score prioritizes review; it does not prove compromise.
            """),
            markdown("## Data\n\nLoad the versioned corpus and validate its population, split, and label coverage."),
            code(common_setup()),
            code("""
from gpu_trust_guardian.features import FEATURE_COLUMNS, engineer_features

raw = pd.read_csv(ROOT / "data" / "synthetic_gpu_events.csv")
frame = engineer_features(raw)
population = pd.DataFrame({
    "rows": [len(frame)],
    "train": [(frame["split"] == "train").sum()],
    "test": [(frame["split"] == "test").sum()],
    "attack_rows": [frame["is_attack"].sum()],
    "scenarios": [frame["scenario"].nunique()],
})
population
            """),
            code("""
assert frame["event_id"].is_unique
assert set(frame["split"]) == {"train", "test"}
assert frame[FEATURE_COLUMNS].isna().sum().sum() == 0
assert set(frame["scenario"]) == {
    "trusted_training", "benign_inference", "cryptomining",
    "model_exfiltration", "container_escape", "untrusted_gpu",
}
print("Validated", len(frame), "synthetic events with", len(FEATURE_COLUMNS), "behavior features.")
            """),
            markdown("## Results\n\nFit both models on the same training population and evaluate once on the challenge split."),
            code("""
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

train = frame[frame["split"] == "train"].copy()
test = frame[frame["split"] == "test"].copy()

classifier = RandomForestClassifier(
    n_estimators=280, max_depth=6, min_samples_leaf=8,
    class_weight="balanced", random_state=42, n_jobs=1,
)
classifier.fit(train[FEATURE_COLUMNS], train["is_attack"])
rf_probability = classifier.predict_proba(test[FEATURE_COLUMNS])[:, 1]
rf_prediction = (rf_probability >= 0.5).astype(int)

detector = IsolationForest(n_estimators=260, contamination=0.10, random_state=42, n_jobs=1)
benign_train = train[train["is_attack"] == 0]
detector.fit(benign_train[FEATURE_COLUMNS])
if_threshold = np.quantile(-detector.score_samples(benign_train[FEATURE_COLUMNS]), 0.95)
if_score = -detector.score_samples(test[FEATURE_COLUMNS])
if_prediction = (if_score >= if_threshold).astype(int)

metric_rows = []
for model_name, prediction in [("Random Forest", rf_prediction), ("Isolation Forest", if_prediction)]:
    metric_rows.append({
        "model": model_name,
        "precision": precision_score(test["is_attack"], prediction, zero_division=0),
        "recall": recall_score(test["is_attack"], prediction, zero_division=0),
        "f1": f1_score(test["is_attack"], prediction, zero_division=0),
    })
metrics = pd.DataFrame(metric_rows)
metrics
            """),
            code("""
long_metrics = metrics.melt(id_vars="model", var_name="metric", value_name="score")
fig, ax = plt.subplots(figsize=(10, 5.4))
x = np.arange(3)
width = 0.34
for index, (model_name, color) in enumerate([("Random Forest", NVIDIA), ("Isolation Forest", BLUE)]):
    values = long_metrics[long_metrics["model"] == model_name].set_index("metric").loc[["precision", "recall", "f1"], "score"]
    bars = ax.bar(x + (index - .5) * width, values, width, label=model_name, color=color, edgecolor=INK)
    ax.bar_label(bars, labels=[f"{value:.0%}" for value in values], padding=3, fontsize=9)
ax.set_xticks(x, ["Precision", "Recall", "F1"])
ax.set_ylim(0, 1.12)
ax.set_ylabel("Held-out score")
ax.set_title("Threat-classification quality by model", loc="left", fontweight="bold")
ax.text(0, 1.04, f"Synthetic challenge split; n={len(test):,} events", transform=ax.transAxes, color="#596579")
ax.grid(axis="y", color=GRID, linewidth=.8)
ax.legend(frameon=False, ncol=2, loc="upper center")
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
matrices = [
    ("Random Forest", confusion_matrix(test["is_attack"], rf_prediction)),
    ("Isolation Forest", confusion_matrix(test["is_attack"], if_prediction)),
]
fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.4))
for ax, (title, matrix) in zip(axes, matrices):
    image = ax.imshow(matrix, cmap="YlGn", vmin=0, vmax=max(item.max() for _, item in matrices))
    for row in range(2):
        for column in range(2):
            ax.text(column, row, int(matrix[row, column]), ha="center", va="center", fontweight="bold")
    ax.set_title(title, fontweight="bold")
    ax.set_xticks([0, 1], ["Benign", "Attack"])
    ax.set_yticks([0, 1], ["Benign", "Attack"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
fig.suptitle("Held-out confusion matrices", x=.08, ha="left", fontweight="bold")
plt.tight_layout()
plt.show()
            """),
            code("""
importance = pd.DataFrame({"feature": FEATURE_COLUMNS, "importance": classifier.feature_importances_}).sort_values("importance").tail(9)
fig, ax = plt.subplots(figsize=(10, 5.6))
bars = ax.barh(importance["feature"].str.replace("_", " ").str.title(), importance["importance"], color=NVIDIA, edgecolor="#365314")
ax.bar_label(bars, labels=[f"{value:.3f}" for value in importance["importance"]], padding=4, fontsize=9)
ax.set_title("Random Forest feature importance", loc="left", fontweight="bold")
ax.text(0, 1.02, "Relative split importance; not a causal explanation", transform=ax.transAxes, color="#596579")
ax.set_xlabel("Importance")
ax.grid(axis="x", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
test_results = test[["scenario", "is_attack"]].copy()
test_results["rf_prediction"] = rf_prediction
scenario_quality = test_results.groupby("scenario").apply(
    lambda group: pd.Series({
        "events": len(group),
        "attack_recall": recall_score(group["is_attack"], group["rf_prediction"], zero_division=0),
    }), include_groups=False,
).reset_index().sort_values("attack_recall")

fig, ax = plt.subplots(figsize=(10, 5.2))
bars = ax.barh(scenario_quality["scenario"].str.replace("_", " ").str.title(), scenario_quality["attack_recall"], color=ORANGE, edgecolor="#9a3412")
ax.bar_label(bars, labels=[f"{value:.0%}" for value in scenario_quality["attack_recall"]], padding=4)
ax.set_xlim(0, 1.08)
ax.set_xlabel("Attack recall")
ax.set_title("Recall varies by scenario family", loc="left", fontweight="bold")
ax.text(0, 1.02, "Zero means the scenario contains no behavior-model attack labels", transform=ax.transAxes, color="#596579")
ax.grid(axis="x", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            markdown(f"""
            ## Takeaways

            1. **Known patterns benefit from labels.** The Random Forest reaches **{supervised['f1']:.1%} F1**, ahead of the benign-only detector at **{unsupervised['f1']:.1%}**.
            2. **Recall is the main gap.** The supervised model misses **{supervised['confusion_matrix'][1][0]} of {sum(supervised['confusion_matrix'][1])}** held-out attacks, including intentionally evasive variants.
            3. **Hardware trust stays separate.** Attestation is a deterministic policy input, not a shortcut feature for behavior classification.
            4. **Production next step:** validate on real, governed GPU telemetry with workload-aware splits and drift monitoring.
            """),
        ]
    )


def build_graph_notebook() -> nbf.NotebookNode:
    summary = COMPROMISED["summary"]
    graph = COMPROMISED["graph_summary"]
    return notebook(
        [
            markdown("""
            # 02 · Identity-to-GPU Attack-Path Graph

            An evidence graph that connects users, workloads, containers, GPUs, models, and destinations without claiming exploitability.
            """),
            markdown(f"""
            ## tl;dr

            The compromised fixture produces **{summary['attack_paths']} unique evidence paths** across **{graph['nodes']} graph nodes** and **{graph['edges']} edges**. The paths show *where suspicious behavior traveled*; they do not prove a vulnerability was exploited.
            """),
            markdown("""
            ## Context & Methods

            Each telemetry row creates observed relationships: identity → workload → container → GPU → model/destination. Only events flagged by bounded evidence rules become attack-path candidates.

            ### Key Assumptions

            - Graph edges represent observed use or connection, not causal compromise.
            - Destinations ending in `.invalid` are safe synthetic external indicators.
            - Duplicate paths are collapsed to keep analyst review bounded.
            """),
            markdown("## Data\n\nLoad the same compromised fixture and reproduce the graph from source events."),
            code(common_setup()),
            code("""
from collections import Counter
import networkx as nx

from gpu_trust_guardian.graph import build_evidence_graph
from gpu_trust_guardian.pipeline import load_attestation, load_events, analyze_events

events = load_events(ROOT / "data" / "compromised_events.csv")
attestation = load_attestation(ROOT / "attestations" / "untrusted.json")
report = analyze_events(events, attestation, "compromised")
frame = pd.DataFrame([item.to_dict() for item in events])
graph = build_evidence_graph(frame)

pd.DataFrame([{
    "events": len(events), "nodes": graph.number_of_nodes(), "edges": graph.number_of_edges(),
    "unique_attack_paths": len(report.attack_paths), "decision": report.decision,
}])
            """),
            code("""
assert graph.number_of_nodes() == report.graph_summary["nodes"]
assert graph.number_of_edges() == report.graph_summary["edges"]
assert all(path[0].startswith("user:") for path in report.attack_paths)
assert len({tuple(path) for path in report.attack_paths}) == len(report.attack_paths)
print("Graph and report reconcile exactly.")
            """),
            markdown("## Results\n\nStart with graph composition, then inspect the high-signal paths and their terminal resources."),
            code("""
node_counts = Counter(node.split(":", 1)[0] for node in graph.nodes)
node_frame = pd.DataFrame({"node_type": list(node_counts), "nodes": list(node_counts.values())}).sort_values("nodes")
fig, ax = plt.subplots(figsize=(9.5, 5.2))
bars = ax.barh(node_frame["node_type"].str.title(), node_frame["nodes"], color=NVIDIA, edgecolor="#365314")
ax.bar_label(bars, padding=4, fontweight="bold")
ax.set_title("Evidence graph composition", loc="left", fontweight="bold")
ax.text(0, 1.02, "Unique entities in the compromised synthetic scenario", transform=ax.transAxes, color="#596579")
ax.set_xlabel("Nodes")
ax.grid(axis="x", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
color_map = {
    "user": BLUE, "workload": NVIDIA, "container": GOLD, "gpu": ORANGE,
    "model": PINK, "external": "#7f1d1d", "resource": "#94a3b8",
}
positions = nx.spring_layout(graph, seed=42, k=0.72)
colors = [color_map.get(node.split(":", 1)[0], "#cbd5e1") for node in graph.nodes]
sizes = [1250 if node.startswith("gpu:") else 760 for node in graph.nodes]

fig, ax = plt.subplots(figsize=(14, 9))
nx.draw_networkx_edges(graph, positions, ax=ax, edge_color="#cbd5e1", arrows=True, arrowsize=12, width=.9)
nx.draw_networkx_nodes(graph, positions, ax=ax, node_color=colors, node_size=sizes, edgecolors=INK, linewidths=.7)
labels = {node: node.split(":", 1)[1] for node in graph.nodes if node.startswith(("gpu:", "model:", "external:"))}
nx.draw_networkx_labels(graph, positions, labels=labels, ax=ax, font_size=7, font_weight="bold")
ax.set_title("Identity-to-GPU evidence graph", loc="left", fontweight="bold")
ax.text(0, 1.01, "Labels shown for GPUs, models, and external destinations; layout is deterministic", transform=ax.transAxes, color="#596579")
ax.axis("off")
plt.tight_layout()
plt.show()
            """),
            code("""
terminal_counts = Counter(path[-1].split(":", 1)[0] for path in report.attack_paths)
terminal_frame = pd.DataFrame({"terminal": list(terminal_counts), "paths": list(terminal_counts.values())}).sort_values("paths")
fig, ax = plt.subplots(figsize=(8.8, 4.6))
bars = ax.barh(terminal_frame["terminal"].str.title(), terminal_frame["paths"], color=ORANGE, edgecolor="#9a3412")
ax.bar_label(bars, padding=4, fontweight="bold")
ax.set_title("Attack paths by terminal resource", loc="left", fontweight="bold")
ax.text(0, 1.02, f"{len(report.attack_paths)} deduplicated suspicious paths", transform=ax.transAxes, color="#596579")
ax.set_xlabel("Paths")
ax.grid(axis="x", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
terminal_frame
            """),
            code("""
lengths = pd.Series([len(path) for path in report.attack_paths], name="nodes_in_path")
fig, ax = plt.subplots(figsize=(8.8, 4.6))
bins = np.arange(lengths.min() - .5, lengths.max() + 1.5, 1)
ax.hist(lengths, bins=bins, color=BLUE, edgecolor=INK, rwidth=.82)
ax.set_xticks(sorted(lengths.unique()))
ax.set_xlabel("Nodes in evidence path")
ax.set_ylabel("Path count")
ax.set_title("Attack-path length distribution", loc="left", fontweight="bold")
ax.text(0, 1.02, "Longer paths include model access before an external connection", transform=ax.transAxes, color="#596579")
ax.grid(axis="y", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            markdown(f"""
            ## Takeaways

            1. **Graph context makes alerts actionable.** The report preserves **{summary['attack_paths']}** identity-to-resource paths instead of returning isolated scores.
            2. **The graph is evidence, not exploit proof.** Every edge is traceable to synthetic telemetry, but reachability alone does not establish compromise.
            3. **Containment can target the narrowest node.** Analysts can quarantine a workload or identity before considering a broader GPU/node response.
            """),
        ]
    )


def build_attestation_notebook() -> nbf.NotebookNode:
    trusted = next(row for row in POLICY if row["scenario"] == "trusted_training")
    untrusted = next(row for row in POLICY if row["scenario"] == "untrusted_gpu")
    return notebook(
        [
            markdown("""
            # 03 · GPU Attestation & Workload Policy Gate

            A policy simulation that keeps hardware trust, workload behavior, and analyst action separate and auditable.
            """),
            markdown(f"""
            ## tl;dr

            Trusted training behavior receives **{trusted['decision']}** at **{trusted['risk_score']}/100**. Normal behavior on an untrusted GPU receives **{untrusted['decision']}** at **{untrusted['risk_score']}/100** because cryptographic trust is a release prerequisite—not a behavior-model prediction.
            """),
            markdown("""
            ## Context & Methods

            The demo parser consumes NRAS-shaped synthetic evidence: nonce, signature, measurement, and confidential-computing mode. The production boundary is explicit: real deployments must call NVIDIA attestation services and validate freshness and policy.

            ### Key Assumptions

            - Fixture booleans represent already-verified claims; the lab does not implement cryptography.
            - A failed attestation blocks model-key release even if telemetry looks normal.
            - Behavior evidence can independently block a trusted GPU workload.
            """),
            markdown("## Data\n\nRecreate six scenario reports from deterministic inputs and compare them with the checked-in policy matrix."),
            code(common_setup()),
            code("""
from gpu_trust_guardian.pipeline import analyze_events
from gpu_trust_guardian.simulator import SCENARIOS, build_attestation, generate_events

rows = []
for index, scenario in enumerate(SCENARIOS):
    attestation = build_attestation(scenario != "untrusted_gpu")
    report = analyze_events(generate_events(scenario, 260, 210 + index), attestation, scenario)
    rows.append({
        "scenario": scenario,
        "decision": report.decision,
        "risk_score": report.risk_score,
        "findings": len(report.findings),
        "suspicious_events": report.suspicious_events,
        "attack_paths": len(report.attack_paths),
        "attestation_trusted": report.attestation.trusted,
    })
policy = pd.DataFrame(rows)
policy
            """),
            code("""
checked_in = pd.DataFrame(json.loads((ROOT / "reports" / "policy-matrix.json").read_text()))
pd.testing.assert_frame_equal(
    policy.sort_values("scenario").reset_index(drop=True),
    checked_in.sort_values("scenario").reset_index(drop=True),
)
assert set(policy["decision"]) == {"ALLOW", "QUARANTINE", "BLOCK"}
print("Recomputed policy matrix matches the checked-in report.")
            """),
            markdown("## Results\n\nFirst compare scenario risk, then isolate the effect of attestation trust."),
            code("""
decision_colors = {"ALLOW": NVIDIA, "QUARANTINE": GOLD, "BLOCK": ORANGE}
ordered = policy.sort_values("risk_score")
fig, ax = plt.subplots(figsize=(10.5, 5.8))
bars = ax.barh(
    ordered["scenario"].str.replace("_", " ").str.title(),
    ordered["risk_score"],
    color=[decision_colors[value] for value in ordered["decision"]],
    edgecolor=INK,
)
ax.bar_label(bars, labels=[f"{score}/100 · {decision}" for score, decision in zip(ordered["risk_score"], ordered["decision"])], padding=5)
ax.set_xlim(0, 118)
ax.set_xlabel("Policy risk score")
ax.set_title("GPU workload decision by scenario", loc="left", fontweight="bold")
ax.text(0, 1.02, "Synthetic fixtures; color communicates decision and labels preserve meaning", transform=ax.transAxes, color="#596579")
ax.grid(axis="x", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
matrix_rows = []
for index, scenario in enumerate(SCENARIOS):
    events = generate_events(scenario, 260, 210 + index)
    for trusted in [True, False]:
        report = analyze_events(events, build_attestation(trusted), scenario)
        matrix_rows.append({"scenario": scenario, "attestation": "Trusted" if trusted else "Failed", "risk_score": report.risk_score, "decision": report.decision})
trust_matrix = pd.DataFrame(matrix_rows)
pivot = trust_matrix.pivot(index="scenario", columns="attestation", values="risk_score").loc[list(SCENARIOS), ["Trusted", "Failed"]]

fig, ax = plt.subplots(figsize=(7.4, 6.2))
image = ax.imshow(pivot.values, cmap="YlOrRd", vmin=0, vmax=100, aspect="auto")
for row in range(pivot.shape[0]):
    for column in range(pivot.shape[1]):
        value = int(pivot.iloc[row, column])
        ax.text(column, row, value, ha="center", va="center", fontweight="bold", color="white" if value >= 70 else INK)
ax.set_xticks(range(2), pivot.columns)
ax.set_yticks(range(len(pivot)), [value.replace("_", " ").title() for value in pivot.index])
ax.set_title("Risk score under trusted vs failed attestation", loc="left", fontweight="bold")
ax.text(0, 1.02, "Same behavior; only synthetic attestation evidence changes", transform=ax.transAxes, color="#596579")
fig.colorbar(image, ax=ax, label="Risk score")
plt.tight_layout()
plt.show()
            """),
            code("""
compromised_events = generate_events("compromised", 360, 84)
compromised_report = analyze_events(compromised_events, build_attestation(False), "compromised")
finding_frame = pd.DataFrame([item.to_dict() for item in compromised_report.findings]).sort_values("score")
fig, ax = plt.subplots(figsize=(10, 5.2))
bars = ax.barh(finding_frame["category"].str.replace("-", " ").str.title(), finding_frame["score"], color=ORANGE, edgecolor="#9a3412")
ax.bar_label(bars, padding=4, fontweight="bold")
ax.set_title("Evidence contributions before score capping", loc="left", fontweight="bold")
ax.text(0, 1.02, "Additive demo weights; final risk score is capped at 100", transform=ax.transAxes, color="#596579")
ax.set_xlabel("Policy points")
ax.grid(axis="x", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
finding_frame[["severity", "category", "title", "score"]]
            """),
            markdown(f"""
            ## Takeaways

            1. **Attestation is a gate, not an ML feature.** Failed trust evidence independently changes normal behavior from **{trusted['decision']}** to **{untrusted['decision']}**.
            2. **Trusted hardware is not trusted behavior.** Cryptomining, exfiltration, and host access still trigger containment on an attested GPU.
            3. **The production boundary is explicit.** Replace the fixture parser with NVIDIA Remote Attestation Service verification before using real model keys or confidential data.
            """),
        ]
    )


def build_guardrail_notebook() -> nbf.NotebookNode:
    guard = EVALUATION["agent_guardrails"]
    baseline = guard["unguarded_baseline"]
    protected = guard["reference_guard"]
    return notebook(
        [
            markdown("""
            # 04 · Security-Agent Guardrail Red-Team Evaluation

            A deterministic test suite for prompt injection, secret exposure, tool authorization, and human approval around a GPU-security copilot.
            """),
            markdown(f"""
            ## tl;dr

            Across **{guard['population']['cases']} synthetic cases**, the unguarded baseline correctly handles **{baseline['accuracy']:.0%}** while the runnable reference guard handles **{protected['accuracy']:.0%}**. The perfect guarded score is expected for this bounded rule suite; it is a regression test, not evidence of general jailbreak resistance.
            """),
            markdown("""
            ## Context & Methods

            The reference guard is evaluated against versioned benign and adversarial cases. An optional NeMo Guardrails configuration shows how the same control points could wrap an NVIDIA-aligned deployment.

            ### Key Assumptions

            - Cases are hand-authored synthetic regression fixtures, not an adaptive red-team benchmark.
            - Destructive or containment tools require explicit authorization and, where appropriate, human approval.
            - LLM output is treated as untrusted; the deterministic application layer owns enforcement.
            """),
            markdown("## Data\n\nLoad the versioned cases and verify category and expectation coverage."),
            code(common_setup()),
            code("""
from gpu_trust_guardian.guardrails import evaluate_cases

cases = json.loads((ROOT / "data" / "guardrail_cases.json").read_text())
guarded = pd.DataFrame(evaluate_cases(cases, guarded=True))
baseline = pd.DataFrame(evaluate_cases(cases, guarded=False))
coverage = guarded.groupby(["category", "expected_allowed"], as_index=False).size()
coverage
            """),
            code("""
assert guarded["case_id"].is_unique
assert set(guarded["category"]) == {"benign-investigation", "prompt-injection", "unauthorized-tool", "approval-gate", "secret-exposure"}
assert guarded["correct"].all()
assert (baseline.loc[~baseline["expected_allowed"], "actual_allowed"]).all()
print("Validated", len(guarded), "synthetic guardrail cases across", guarded["category"].nunique(), "categories.")
            """),
            markdown("## Results\n\nCompare the unguarded and guarded paths, then inspect category coverage and approval behavior."),
            code("""
def score_rows(frame, name):
    attacks = frame[~frame["expected_allowed"]]
    benign = frame[frame["expected_allowed"]]
    return {
        "configuration": name,
        "accuracy": frame["correct"].mean(),
        "attack_block_rate": (~attacks["actual_allowed"]).mean(),
        "benign_pass_rate": benign["actual_allowed"].mean(),
    }

score_frame = pd.DataFrame([score_rows(baseline, "Unguarded"), score_rows(guarded, "Reference guard")])
score_frame
            """),
            code("""
long_scores = score_frame.melt(id_vars="configuration", var_name="metric", value_name="score")
fig, ax = plt.subplots(figsize=(10.2, 5.4))
x = np.arange(3)
width = .34
for index, (configuration, color) in enumerate([("Unguarded", "#94a3b8"), ("Reference guard", NVIDIA)]):
    values = long_scores[long_scores["configuration"] == configuration].set_index("metric").loc[["accuracy", "attack_block_rate", "benign_pass_rate"], "score"]
    bars = ax.bar(x + (index - .5) * width, values, width, color=color, edgecolor=INK, label=configuration)
    ax.bar_label(bars, labels=[f"{value:.0%}" for value in values], padding=3)
ax.set_xticks(x, ["Accuracy", "Attack block rate", "Benign pass rate"])
ax.set_ylim(0, 1.14)
ax.set_ylabel("Case-level rate")
ax.set_title("Guardrail regression-suite outcomes", loc="left", fontweight="bold")
ax.text(0, 1.04, f"{len(guarded)} bounded synthetic cases; deterministic policy evaluation", transform=ax.transAxes, color="#596579")
ax.grid(axis="y", color=GRID, linewidth=.8)
ax.legend(frameon=False, ncol=2, loc="upper center")
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
category_quality = guarded.groupby("category", as_index=False).agg(cases=("case_id", "count"), accuracy=("correct", "mean")).sort_values("cases")
fig, ax = plt.subplots(figsize=(10, 5.3))
bars = ax.barh(category_quality["category"].str.replace("-", " ").str.title(), category_quality["cases"], color=BLUE, edgecolor=INK)
ax.bar_label(bars, labels=[f"{count} cases · {accuracy:.0%} correct" for count, accuracy in zip(category_quality["cases"], category_quality["accuracy"])], padding=5)
ax.set_xlim(0, category_quality["cases"].max() + 4)
ax.set_xlabel("Regression cases")
ax.set_title("Guardrail test coverage by failure mode", loc="left", fontweight="bold")
ax.text(0, 1.02, "Counts show coverage, not real-world prevalence", transform=ax.transAxes, color="#596579")
ax.grid(axis="x", color=GRID, linewidth=.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
expected = guarded["expected_allowed"].astype(int)
actual = guarded["actual_allowed"].astype(int)
matrix = pd.crosstab(expected, actual).reindex(index=[0, 1], columns=[0, 1], fill_value=0)
fig, ax = plt.subplots(figsize=(5.6, 4.6))
image = ax.imshow(matrix.values, cmap="YlGn", vmin=0, vmax=matrix.values.max())
for row in range(2):
    for column in range(2):
        ax.text(column, row, int(matrix.iloc[row, column]), ha="center", va="center", fontweight="bold")
ax.set_xticks([0, 1], ["Blocked", "Allowed"])
ax.set_yticks([0, 1], ["Should block", "Should allow"])
ax.set_xlabel("Reference guard")
ax.set_ylabel("Expected policy")
ax.set_title("Guardrail decision matrix", loc="left", fontweight="bold")
plt.tight_layout()
plt.show()
            """),
            code("""
approval = guarded[guarded["category"] == "approval-gate"][
    ["case_id", "human_approved", "expected_allowed", "actual_allowed", "reason"]
].copy()
approval
            """),
            markdown(f"""
            ## Takeaways

            1. **Application policy owns enforcement.** The guarded path blocks **{protected['attack_block_rate']:.0%}** of its bounded adversarial fixtures while retaining **{protected['benign_pass_rate']:.0%}** benign pass-through.
            2. **The 100% result is intentionally narrow.** These exact cases are deterministic regression tests; adaptive prompts and model-specific evaluation remain future work.
            3. **Containment requires approval.** The LLM can recommend quarantine, but the application decides whether the action is authorized.
            4. **NeMo is an integration path, not a benchmark claim.** The checked-in configuration maps these controls to input and execution rails without implying NVIDIA endorsement.
            """),
        ]
    )


def main() -> None:
    notebooks = {
        "01_gpu_digital_fingerprinting.ipynb": build_fingerprint_notebook(),
        "02_identity_to_gpu_attack_paths.ipynb": build_graph_notebook(),
        "03_gpu_attestation_policy_gate.ipynb": build_attestation_notebook(),
        "04_security_agent_guardrail_eval.ipynb": build_guardrail_notebook(),
    }
    output_dir = ROOT / "notebooks"
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, document in notebooks.items():
        nbf.write(document, output_dir / filename)
        print("Built", filename)


if __name__ == "__main__":
    main()
