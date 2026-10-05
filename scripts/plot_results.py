#!/usr/bin/env python3
"""
QR-DLT Empirical Visualization & Academic Graph Generator
Generates publication-quality charts from empirical_results.json.
Outputs standalone SVG vector graphics (resolution-independent for IEEE/ACM LaTeX papers).
"""

import json
import os
import sys

def load_data(json_path):
    with open(json_path, "r") as f:
        return json.load(f)

def generate_payload_chart(schemes, output_path):
    """Figure 1: Cryptographic Payload Overhead (The Lattice Tax)"""
    width = 700
    height = 420
    margin = {"top": 60, "right": 40, "bottom": 70, "left": 100}
    chart_w = width - margin["left"] - margin["right"]
    chart_h = height - margin["top"] - margin["bottom"]

    max_bytes = 4000

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">',
        f'  <text x="{width/2}" y="35" text-anchor="middle" font-size="18" font-weight="bold" fill="#1e293b">Figure 1: Cryptographic Payload Overhead (The Lattice Tax)</text>',
        f'  <g transform="translate({margin["left"]}, {margin["top"]})">',
    ]

    # Grid lines & Y-axis labels
    for val in range(0, max_bytes + 1, 1000):
        y = chart_h - (val / max_bytes * chart_h)
        svg.append(f'    <line x1="0" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'    <text x="-12" y="{y + 4}" text-anchor="end" font-size="12" fill="#64748b">{val} B</text>')

    # Axis lines
    svg.append(f'    <line x1="0" y1="0" x2="0" y2="{chart_h}" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append(f'    <line x1="0" y1="{chart_h}" x2="{chart_w}" y2="{chart_h}" stroke="#94a3b8" stroke-width="1.5"/>')

    # Bars
    bar_width = 50
    spacing = chart_w / len(schemes)

    colors = {
        "Ed25519": {"pk": "#3b82f6", "sig": "#1d4ed8"},
        "Falcon-512": {"pk": "#10b981", "sig": "#047857"},
        "ML-DSA-44": {"pk": "#f59e0b", "sig": "#b45309"},
    }

    for idx, s in enumerate(schemes):
        name = s["name"]
        pk = s["public_key_bytes"]
        sig = s["signature_bytes"]
        total = pk + sig
        col = colors.get(name, {"pk": "#6366f1", "sig": "#4338ca"})

        center_x = (idx + 0.5) * spacing
        x = center_x - bar_width / 2

        pk_h = (pk / max_bytes) * chart_h
        sig_h = (sig / max_bytes) * chart_h
        total_h = pk_h + sig_h
        y_top = chart_h - total_h

        # Sig bar (bottom)
        svg.append(f'    <rect x="{x}" y="{chart_h - sig_h}" width="{bar_width}" height="{sig_h}" fill="{col["sig"]}" rx="2"/>')
        # PK bar (top)
        svg.append(f'    <rect x="{x}" y="{y_top}" width="{bar_width}" height="{pk_h}" fill="{col["pk"]}" rx="2"/>')

        # Total label above bar
        mult_str = f"({s['lattice_tax_multiplier']:.1f}x)" if s['lattice_tax_multiplier'] > 1.0 else "(1.0x baseline)"
        svg.append(f'    <text x="{center_x}" y="{y_top - 18}" text-anchor="middle" font-size="12" font-weight="bold" fill="#0f172a">{total} B</text>')
        svg.append(f'    <text x="{center_x}" y="{y_top - 5}" text-anchor="middle" font-size="10" fill="#64748b">{mult_str}</text>')

        # X-axis label
        svg.append(f'    <text x="{center_x}" y="{chart_h + 25}" text-anchor="middle" font-size="13" font-weight="600" fill="#334155">{name}</text>')
        svg.append(f'    <text x="{center_x}" y="{chart_h + 42}" text-anchor="middle" font-size="11" fill="#64748b">PK: {pk}B | Sig: {sig}B</text>')

    # Legend
    legend_x = chart_w - 180
    svg.append(f'    <rect x="{legend_x}" y="10" width="14" height="14" fill="#3b82f6" rx="2"/>')
    svg.append(f'    <text x="{legend_x + 20}" y="22" font-size="11" fill="#334155">Public Key (Bytes)</text>')
    svg.append(f'    <rect x="{legend_x}" y="32" width="14" height="14" fill="#1d4ed8" rx="2"/>')
    svg.append(f'    <text x="{legend_x + 20}" y="44" font-size="11" fill="#334155">Digital Signature</text>')

    svg.append('  </g>')
    svg.append('</svg>')

    with open(output_path, "w") as f:
        f.write("\n".join(svg))
    print(f"Figure 1 saved to: {output_path}")

def generate_throughput_chart(scaling, output_path):
    """Figure 2: Batch Verification Throughput Scaling (TPS)"""
    width = 720
    height = 420
    margin = {"top": 60, "right": 50, "bottom": 60, "left": 90}
    chart_w = width - margin["left"] - margin["right"]
    chart_h = height - margin["top"] - margin["bottom"]

    max_tps = max(item["throughput_tps"] for item in scaling) * 1.15

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">',
        f'  <text x="{width/2}" y="35" text-anchor="middle" font-size="18" font-weight="bold" fill="#1e293b">Figure 2: Parallel Batch Verification Scaling (Throughput)</text>',
        f'  <g transform="translate({margin["left"]}, {margin["top"]})">',
    ]

    # Grid lines
    step = int(max_tps / 5 / 1000) * 1000 or 5000
    for val in range(0, int(max_tps), max(step, 5000)):
        y = chart_h - (val / max_tps * chart_h)
        svg.append(f'    <line x1="0" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'    <text x="-12" y="{y + 4}" text-anchor="end" font-size="12" fill="#64748b">{val:,.0f}</text>')

    svg.append(f'    <line x1="0" y1="0" x2="0" y2="{chart_h}" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append(f'    <line x1="0" y1="{chart_h}" x2="{chart_w}" y2="{chart_h}" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append(f'    <text x="-45" y="{chart_h/2}" text-anchor="middle" transform="rotate(-90, -45, {chart_h/2})" font-size="12" fill="#475569">Throughput (Transactions / Sec)</text>')

    # Group by batch size
    batch_sizes = sorted(list(set(item["batch_size"] for item in scaling)))
    spacing = chart_w / len(batch_sizes)

    colors = {
        "Ed25519": "#3b82f6",
        "Falcon-512": "#10b981",
        "ML-DSA-44": "#f59e0b",
    }

    bar_width = 30
    offsets = {"Ed25519": -35, "Falcon-512": 0, "ML-DSA-44": 35}

    for idx, b_size in enumerate(batch_sizes):
        center_x = (idx + 0.5) * spacing
        svg.append(f'    <text x="{center_x}" y="{chart_h + 25}" text-anchor="middle" font-size="13" font-weight="600" fill="#334155">{b_size} tx batch</text>')

        for item in scaling:
            if item["batch_size"] == b_size:
                scheme = item["scheme"]
                tps = item["throughput_tps"]
                col = colors.get(scheme, "#64748b")
                bx = center_x + offsets[scheme] - bar_width / 2
                bh = (tps / max_tps) * chart_h
                by = chart_h - bh

                svg.append(f'    <rect x="{bx}" y="{by}" width="{bar_width}" height="{bh}" fill="{col}" rx="3"/>')
                svg.append(f'    <text x="{bx + bar_width/2}" y="{by - 6}" text-anchor="middle" font-size="10" font-weight="600" fill="#1e293b">{tps:,.0f}</text>')

    # Legend
    leg_x = chart_w - 220
    for idx, (sch, col) in enumerate(colors.items()):
        ly = 15 + idx * 20
        svg.append(f'    <rect x="{leg_x}" y="{ly}" width="14" height="14" fill="{col}" rx="2"/>')
        svg.append(f'    <text x="{leg_x + 22}" y="{ly + 11}" font-size="12" fill="#334155">{sch}</text>')

    svg.append('  </g>')
    svg.append('</svg>')

    with open(output_path, "w") as f:
        f.write("\n".join(svg))
    print(f"Figure 2 saved to: {output_path}")

def generate_pruning_chart(pruning, output_path):
    """Figure 3: Epoch-Based Witness Pruning Storage Reduction"""
    width = 680
    height = 360
    margin = {"top": 60, "right": 50, "bottom": 50, "left": 70}

    witness_kb = pruning["unpruned_witness_bytes"] / 1024.0
    intent_kb = pruning["retained_intent_bytes"] / 1024.0
    total_kb = witness_kb + intent_kb
    reclaimed_pct = pruning["reclaimed_space_percent"]

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;">',
        f'  <text x="{width/2}" y="35" text-anchor="middle" font-size="18" font-weight="bold" fill="#1e293b">Figure 3: Epoch-Based Witness Pruning Storage Reduction</text>',
        f'  <g transform="translate({margin["left"]}, {margin["top"]})">',
    ]

    # Bar 1: Archival Node (Full History)
    svg.append('    <text x="140" y="25" text-anchor="middle" font-size="14" font-weight="bold" fill="#1e293b">Full Archival Node</text>')
    svg.append(f'    <text x="140" y="45" text-anchor="middle" font-size="12" fill="#64748b">Total: {total_kb:.1f} KB</text>')
    svg.append(f'    <rect x="60" y="60" width="160" height="150" fill="#ef4444" rx="4"/>')
    svg.append(f'    <text x="140" y="130" text-anchor="middle" font-size="12" font-weight="bold" fill="#ffffff">Witness Payload</text>')
    svg.append(f'    <text x="140" y="150" text-anchor="middle" font-size="11" fill="#fee2e2">{witness_kb:.1f} KB ({reclaimed_pct:.1f}%)</text>')
    svg.append(f'    <rect x="60" y="215" width="160" height="25" fill="#3b82f6" rx="4"/>')
    svg.append(f'    <text x="140" y="232" text-anchor="middle" font-size="11" font-weight="bold" fill="#ffffff">Intents: {intent_kb:.1f} KB</text>')

    # Arrow
    svg.append('    <path d="M 270 145 L 340 145 M 330 135 L 340 145 L 330 155" stroke="#64748b" stroke-width="2.5" fill="none"/>')
    svg.append(f'    <text x="305" y="125" text-anchor="middle" font-size="12" font-weight="bold" fill="#10b981">Epoch Pruned</text>')
    svg.append(f'    <text x="305" y="170" text-anchor="middle" font-size="13" font-weight="bold" fill="#047857">-{reclaimed_pct:.1f}%</text>')

    # Bar 2: Pruned Validating Node
    svg.append('    <text x="450" y="25" text-anchor="middle" font-size="14" font-weight="bold" fill="#1e293b">Pruned Validating Node</text>')
    svg.append(f'    <text x="450" y="45" text-anchor="middle" font-size="12" fill="#64748b">Retained: {intent_kb:.1f} KB</text>')
    svg.append(f'    <rect x="370" y="215" width="160" height="25" fill="#3b82f6" rx="4"/>')
    svg.append(f'    <text x="450" y="232" text-anchor="middle" font-size="11" font-weight="bold" fill="#ffffff">Intents + Commitments</text>')
    svg.append('    <rect x="370" y="60" width="160" height="150" fill="none" stroke="#cbd5e1" stroke-dasharray="6,4" stroke-width="2" rx="4"/>')
    svg.append('    <text x="450" y="135" text-anchor="middle" font-size="12" fill="#94a3b8">Witness Data Purged</text>')
    svg.append('    <text x="450" y="155" text-anchor="middle" font-size="11" fill="#94a3b8">(Commitment Root Retained)</text>')

    svg.append('  </g>')
    svg.append('</svg>')

    with open(output_path, "w") as f:
        f.write("\n".join(svg))
    print(f"Figure 3 saved to: {output_path}")

def main():
    json_path = sys.argv[1] if len(sys.argv) > 1 else "empirical_results.json"
    if not os.path.exists(json_path):
        print(f"Error: {json_path} not found. Run 'qr-dlt-node evaluate' first.")
        sys.exit(1)

    data = load_data(json_path)
    out_dir = os.path.dirname(json_path) or "."

    fig1 = os.path.join(out_dir, "figure1_crypto_payloads.svg")
    fig2 = os.path.join(out_dir, "figure2_batch_throughput.svg")
    fig3 = os.path.join(out_dir, "figure3_storage_pruning.svg")

    generate_payload_chart(data["schemes"], fig1)
    generate_throughput_chart(data["batch_scaling"], fig2)
    generate_pruning_chart(data["pruning"], fig3)

    print("\nAll publication charts successfully generated!")

if __name__ == "__main__":
    main()
