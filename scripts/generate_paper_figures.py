#!/usr/bin/env python3
"""
QR-DLT Academic Paper Figure Generator
Generates high-resolution academic vector SVGs and pixel-perfect PNGs for paper.tex.
"""

import json
import os
import subprocess
import sys

FIGURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "paper", "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

def render_svg_to_png(svg_path, png_path, width=1400, height=840):
    """Uses headless Google Chrome to render crisp 300-DPI equivalent PNG."""
    cmd = [
        "google-chrome",
        "--headless",
        "--disable-gpu",
        f"--window-size={width},{height}",
        f"--screenshot={png_path}",
        svg_path
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Rendered: {png_path}")

def generate_fig1():
    """Figure 2: The Lattice Tax Cryptographic Payload Overhead."""
    svg_path = os.path.join(FIGURES_DIR, "fig2_lattice_tax.svg")
    png_path = os.path.join(FIGURES_DIR, "fig2_lattice_tax.png")
    
    width = 750
    height = 430
    margin = {"top": 60, "right": 50, "bottom": 70, "left": 100}
    chart_w = width - margin["left"] - margin["right"]
    chart_h = height - margin["top"] - margin["bottom"]
    max_val = 4800

    schemes = [
        {"name": "Ed25519 (Baseline)", "pk": 32, "sig": 64, "tax": "1.0x baseline", "color_pk": "#38bdf8", "color_sig": "#0284c7"},
        {"name": "Falcon-512 (FIPS 206)", "pk": 897, "sig": 666, "tax": "16.3x Lattice Tax", "color_pk": "#34d399", "color_sig": "#059669"},
        {"name": "ML-DSA-44 (FIPS 204)", "pk": 1312, "sig": 2420, "tax": "38.9x Lattice Tax", "color_pk": "#fbbf24", "color_sig": "#d97706"},
    ]

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, sans-serif;">',
        f'  <text x="{width/2}" y="36" text-anchor="middle" font-size="15" font-weight="bold" fill="#0f172a">Cryptographic Witness Payload Overhead (The Lattice Tax)</text>',
        f'  <g transform="translate({margin["left"]}, {margin["top"]})">',
    ]

    # Grid
    for v in [0, 1000, 2000, 3000, 4000]:
        y = chart_h - (v / max_val * chart_h)
        svg.append(f'    <line x1="0" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'    <text x="-12" y="{y + 4}" text-anchor="end" font-size="12" fill="#64748b">{v} B</text>')

    # Axis
    svg.append(f'    <line x1="0" y1="0" x2="0" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')
    svg.append(f'    <line x1="0" y1="{chart_h}" x2="{chart_w}" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')

    spacing = chart_w / len(schemes)
    bar_w = 64

    for i, s in enumerate(schemes):
        cx = (i + 0.5) * spacing
        x = cx - bar_w / 2
        total = s["pk"] + s["sig"]
        sig_h = (s["sig"] / max_val) * chart_h
        pk_h = (s["pk"] / max_val) * chart_h
        y_top = chart_h - (sig_h + pk_h)

        # Signature bottom
        svg.append(f'    <rect x="{x}" y="{chart_h - sig_h}" width="{bar_w}" height="{sig_h}" fill="{s["color_sig"]}" rx="2"/>')
        # Public key top
        svg.append(f'    <rect x="{x}" y="{y_top}" width="{bar_w}" height="{pk_h}" fill="{s["color_pk"]}" rx="2"/>')

        # Text labels
        svg.append(f'    <text x="{cx}" y="{y_top - 18}" text-anchor="middle" font-size="13" font-weight="bold" fill="#0f172a">{total} Bytes</text>')
        svg.append(f'    <text x="{cx}" y="{y_top - 4}" text-anchor="middle" font-size="11" font-weight="600" fill="#475569">{s["tax"]}</text>')

        # X-label
        svg.append(f'    <text x="{cx}" y="{chart_h + 24}" text-anchor="middle" font-size="12" font-weight="bold" fill="#1e293b">{s["name"]}</text>')
        svg.append(f'    <text x="{cx}" y="{chart_h + 40}" text-anchor="middle" font-size="11" fill="#64748b">PK: {s["pk"]} B | Sig: {s["sig"]} B</text>')

    # Legend placed at top-left (x=20, y=10) completely clear of all bars
    svg.append('    <rect x="15" y="8" width="180" height="48" fill="#ffffff" stroke="#e2e8f0" stroke-width="1" rx="4"/>')
    svg.append('    <rect x="25" y="16" width="14" height="14" fill="#34d399" rx="2"/>')
    svg.append('    <text x="47" y="28" font-size="11" font-weight="600" fill="#334155">Public Key Payload (Top)</text>')
    svg.append('    <rect x="25" y="34" width="14" height="14" fill="#059669" rx="2"/>')
    svg.append('    <text x="47" y="46" font-size="11" font-weight="600" fill="#334155">Signature Payload (Base)</text>')

    svg.append('  </g>')
    svg.append('</svg>')

    with open(svg_path, "w") as f:
        f.write("\n".join(svg))
    render_svg_to_png(svg_path, png_path, 750, 430)
    # backward-compatible copy
    legacy_png = os.path.join(FIGURES_DIR, "fig1_lattice_tax.png")
    render_svg_to_png(svg_path, legacy_png, 750, 430)

def generate_fig2():
    """Figure 3: Batch Verification Throughput Scaling across Threads."""
    svg_path = os.path.join(FIGURES_DIR, "fig3_throughput_scaling.svg")
    png_path = os.path.join(FIGURES_DIR, "fig3_throughput_scaling.png")

    width = 760
    height = 430
    margin = {"top": 60, "right": 50, "bottom": 60, "left": 100}
    chart_w = width - margin["left"] - margin["right"]
    chart_h = height - margin["top"] - margin["bottom"]
    max_tps = 40000

    batches = ["100 Txs", "500 Txs", "1,000 Txs"]
    data = {
        "Ed25519 (Baseline)": [440, 486, 501],
        "Falcon-512 (AVX2)": [27617, 23737, 20402],
        "ML-DSA-44 (AVX2)": [30721, 32365, 34662]
    }
    colors = {"Ed25519 (Baseline)": "#64748b", "Falcon-512 (AVX2)": "#059669", "ML-DSA-44 (AVX2)": "#d97706"}

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, sans-serif;">',
        f'  <text x="{width/2}" y="36" text-anchor="middle" font-size="15" font-weight="bold" fill="#0f172a">Rayon Multi-Core Batch Verification Throughput Scaling (TPS)</text>',
        f'  <g transform="translate({margin["left"]}, {margin["top"]})">',
    ]

    for val in range(0, max_tps + 1, 10000):
        y = chart_h - (val / max_tps * chart_h)
        svg.append(f'    <line x1="0" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'    <text x="-12" y="{y + 4}" text-anchor="end" font-size="12" fill="#64748b">{val:,} TPS</text>')

    svg.append(f'    <line x1="0" y1="0" x2="0" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')
    svg.append(f'    <line x1="0" y1="{chart_h}" x2="{chart_w}" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')

    group_w = chart_w / len(batches)
    sub_w = 40
    schemes_keys = list(data.keys())

    for b_idx, b_name in enumerate(batches):
        cx = (b_idx + 0.5) * group_w
        for s_idx, s_key in enumerate(schemes_keys):
            tps = data[s_key][b_idx]
            bar_h = (tps / max_tps) * chart_h
            bx = cx - 1.5 * sub_w + (s_idx * sub_w) + 4
            by = chart_h - bar_h

            svg.append(f'    <rect x="{bx}" y="{by}" width="{sub_w - 8}" height="{bar_h}" fill="{colors[s_key]}" rx="2"/>')
            if tps > 2000:
                svg.append(f'    <text x="{bx + (sub_w-8)/2}" y="{by - 6}" text-anchor="middle" font-size="10" font-weight="bold" fill="#0f172a">{int(tps/1000)}k</text>')
            else:
                svg.append(f'    <text x="{bx + (sub_w-8)/2}" y="{by - 6}" text-anchor="middle" font-size="10" font-weight="bold" fill="#0f172a">{tps}</text>')

        svg.append(f'    <text x="{cx}" y="{chart_h + 24}" text-anchor="middle" font-size="12" font-weight="bold" fill="#1e293b">{b_name}</text>')

    # Legend
    svg.append(f'    <rect x="{chart_w - 220}" y="10" width="14" height="14" fill="#64748b" rx="2"/>')
    svg.append(f'    <text x="{chart_w - 200}" y="22" font-size="11" font-weight="600" fill="#334155">Ed25519 (Baseline)</text>')
    svg.append(f'    <rect x="{chart_w - 220}" y="30" width="14" height="14" fill="#059669" rx="2"/>')
    svg.append(f'    <text x="{chart_w - 200}" y="42" font-size="11" font-weight="600" fill="#334155">Falcon-512 (AVX2)</text>')
    svg.append(f'    <rect x="{chart_w - 220}" y="50" width="14" height="14" fill="#d97706" rx="2"/>')
    svg.append(f'    <text x="{chart_w - 200}" y="62" font-size="11" font-weight="600" fill="#334155">ML-DSA-44 (AVX2)</text>')

    svg.append('  </g>')
    svg.append('</svg>')

    with open(svg_path, "w") as f:
        f.write("\n".join(svg))
    render_svg_to_png(svg_path, png_path, 760, 430)
    # backward-compatible copy
    legacy_png = os.path.join(FIGURES_DIR, "fig2_throughput_scaling.png")
    render_svg_to_png(svg_path, legacy_png, 760, 430)

def generate_fig3():
    """Figure 4: Segregated Witness Storage Growth & Epoch Pruning Reclamation."""
    svg_path = os.path.join(FIGURES_DIR, "fig4_storage_pruning.svg")
    png_path = os.path.join(FIGURES_DIR, "fig4_storage_pruning.png")

    width = 750
    height = 420
    margin = {"top": 60, "right": 50, "bottom": 60, "left": 100}
    chart_w = width - margin["left"] - margin["right"]
    chart_h = height - margin["top"] - margin["bottom"]
    max_kb = 2000

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, sans-serif;">',
        f'  <text x="{width/2}" y="36" text-anchor="middle" font-size="15" font-weight="bold" fill="#0f172a">Epoch Segregated Witness Pruning Space Recovery</text>',
        f'  <g transform="translate({margin["left"]}, {margin["top"]})">',
    ]

    for val in range(0, max_kb + 1, 500):
        y = chart_h - (val / max_kb * chart_h)
        svg.append(f'    <line x1="0" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'    <text x="-12" y="{y + 4}" text-anchor="end" font-size="12" fill="#64748b">{val} KB</text>')

    svg.append(f'    <line x1="0" y1="0" x2="0" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')
    svg.append(f'    <line x1="0" y1="{chart_h}" x2="{chart_w}" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')

    # Colored bars for Unpruned Archival vs Pruned Validating
    configs = [
        {"name": "Unpruned Archival Node", "witness": 1832.0, "intent": 31.25, "total": 1863.28, "color_w": "#ef4444", "color_i": "#3b82f6", "sub": "Raw proofs retained on disk"},
        {"name": "Pruned Validating Node", "witness": 0.0, "intent": 31.25, "total": 31.25, "color_w": "#ef4444", "color_i": "#10b981", "sub": "Witnesses purged after epoch (98.3% saved)"}
    ]

    spacing = chart_w / len(configs)
    bar_w = 90

    for i, c in enumerate(configs):
        cx = (i + 0.5) * spacing
        x = cx - bar_w / 2
        w_h = (c["witness"] / max_kb) * chart_h
        i_h = (c["intent"] / max_kb) * chart_h
        y_top = chart_h - (w_h + i_h)

        if c["witness"] > 0:
            svg.append(f'    <rect x="{x}" y="{chart_h - w_h}" width="{bar_w}" height="{w_h}" fill="{c["color_w"]}" rx="2"/>')
        svg.append(f'    <rect x="{x}" y="{y_top}" width="{bar_w}" height="{i_h}" fill="{c["color_i"]}" rx="2"/>')

        svg.append(f'    <text x="{cx}" y="{y_top - 12}" text-anchor="middle" font-size="13" font-weight="bold" fill="#0f172a">{c["total"]:.1f} KB</text>')
        svg.append(f'    <text x="{cx}" y="{chart_h + 24}" text-anchor="middle" font-size="13" font-weight="bold" fill="#1e293b">{c["name"]}</text>')
        svg.append(f'    <text x="{cx}" y="{chart_h + 40}" text-anchor="middle" font-size="11" fill="#64748b">{c["sub"]}</text>')

    # Legend
    svg.append(f'    <rect x="{chart_w - 240}" y="10" width="14" height="14" fill="#ef4444" rx="2"/>')
    svg.append(f'    <text x="{chart_w - 220}" y="22" font-size="11" font-weight="600" fill="#334155">Witness Space (Falcon/ML-DSA)</text>')
    svg.append(f'    <rect x="{chart_w - 240}" y="30" width="14" height="14" fill="#10b981" rx="2"/>')
    svg.append(f'    <text x="{chart_w - 220}" y="42" font-size="11" font-weight="600" fill="#334155">Execution Intent State</text>')

    svg.append('  </g>')
    svg.append('</svg>')

    with open(svg_path, "w") as f:
        f.write("\n".join(svg))
    render_svg_to_png(svg_path, png_path, 750, 420)
    # backward-compatible copy
    legacy_png = os.path.join(FIGURES_DIR, "fig3_storage_pruning.png")
    render_svg_to_png(svg_path, legacy_png, 750, 420)

def generate_fig4():
    """Figure 5: Head-to-Head Comparative Benchmarking (Falcon-EVM vs Normal EVM)."""
    svg_path = os.path.join(FIGURES_DIR, "fig5_evm_comparison.svg")
    png_path = os.path.join(FIGURES_DIR, "fig5_evm_comparison.png")

    width = 820
    height = 440
    margin = {"top": 60, "right": 50, "bottom": 70, "left": 90}
    chart_w = width - margin["left"] - margin["right"]
    chart_h = height - margin["top"] - margin["bottom"]

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, sans-serif;">',
        f'  <text x="{width/2}" y="36" text-anchor="middle" font-size="15" font-weight="bold" fill="#0f172a">Head-to-Head Empirical Comparison: Falcon-EVM vs. Normal EVM</text>',
        f'  <g transform="translate({margin["left"]}, {margin["top"]})">',
    ]

    # Sub-chart 1: Verification Throughput (TPS)
    col1_w = chart_w * 0.44
    col2_x = chart_w * 0.56
    col2_w = chart_w * 0.44

    max_tps = 60000
    for v in [0, 20000, 40000, 60000]:
        y = chart_h - (v / max_tps * chart_h)
        svg.append(f'    <line x1="0" y1="{y}" x2="{col1_w}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'    <text x="-10" y="{y + 4}" text-anchor="end" font-size="11" fill="#64748b">{v:,}</text>')

    svg.append(f'    <line x1="0" y1="0" x2="0" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')
    svg.append(f'    <line x1="0" y1="{chart_h}" x2="{col1_w}" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')
    svg.append(f'    <text x="{col1_w/2}" y="{chart_h + 30}" text-anchor="middle" font-size="13" font-weight="bold" fill="#1e293b">Verification Throughput (TPS)</text>')

    # Normal EVM TPS: 26,817 | Falcon EVM TPS: 53,321
    b1_h = (26817 / max_tps) * chart_h
    b2_h = (53321 / max_tps) * chart_h
    svg.append(f'    <rect x="{col1_w*0.18}" y="{chart_h - b1_h}" width="{col1_w*0.28}" height="{b1_h}" fill="#64748b" rx="2"/>')
    svg.append(f'    <text x="{col1_w*0.32}" y="{chart_h - b1_h - 8}" text-anchor="middle" font-size="11" font-weight="bold" fill="#0f172a">26,817</text>')
    svg.append(f'    <text x="{col1_w*0.32}" y="{chart_h + 16}" text-anchor="middle" font-size="10" fill="#475569">Normal EVM</text>')

    svg.append(f'    <rect x="{col1_w*0.54}" y="{chart_h - b2_h}" width="{col1_w*0.28}" height="{b2_h}" fill="#059669" rx="2"/>')
    svg.append(f'    <text x="{col1_w*0.68}" y="{chart_h - b2_h - 8}" text-anchor="middle" font-size="11" font-weight="bold" fill="#047857">53,321</text>')
    svg.append(f'    <text x="{col1_w*0.68}" y="{chart_h + 16}" text-anchor="middle" font-size="10" font-weight="bold" fill="#047857">Falcon-EVM (1.99x)</text>')

    # Sub-chart 2: Block Propagation under WAN Delay (100 Mbps, 100ms RTT)
    max_ms = 300
    for v in [0, 100, 200, 300]:
        y = chart_h - (v / max_ms * chart_h)
        svg.append(f'    <line x1="{col2_x}" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'    <text x="{col2_x - 10}" y="{y + 4}" text-anchor="end" font-size="11" fill="#64748b">{v} ms</text>')

    svg.append(f'    <line x1="{col2_x}" y1="0" x2="{col2_x}" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')
    svg.append(f'    <line x1="{col2_x}" y1="{chart_h}" x2="{chart_w}" y2="{chart_h}" stroke="#64748b" stroke-width="1.5"/>')
    svg.append(f'    <text x="{col2_x + col2_w/2}" y="{chart_h + 30}" text-anchor="middle" font-size="13" font-weight="bold" fill="#1e293b">1k Tx Block WAN Delay (100ms RTT)</text>')

    # Delays: Normal: 108.8 ms | Falcon Unpruned: 233.6 ms | Falcon Pruned: 108.56 ms
    d1_h = (108.8 / max_ms) * chart_h
    d2_h = (233.6 / max_ms) * chart_h
    d3_h = (108.56 / max_ms) * chart_h

    w_sub = col2_w * 0.26
    svg.append(f'    <rect x="{col2_x + col2_w*0.06}" y="{chart_h - d1_h}" width="{w_sub}" height="{d1_h}" fill="#64748b" rx="2"/>')
    svg.append(f'    <text x="{col2_x + col2_w*0.06 + w_sub/2}" y="{chart_h - d1_h - 6}" text-anchor="middle" font-size="10" font-weight="bold" fill="#0f172a">108.8ms</text>')
    svg.append(f'    <text x="{col2_x + col2_w*0.06 + w_sub/2}" y="{chart_h + 16}" text-anchor="middle" font-size="9" fill="#475569">Normal</text>')

    svg.append(f'    <rect x="{col2_x + col2_w*0.37}" y="{chart_h - d2_h}" width="{w_sub}" height="{d2_h}" fill="#ef4444" rx="2"/>')
    svg.append(f'    <text x="{col2_x + col2_w*0.37 + w_sub/2}" y="{chart_h - d2_h - 6}" text-anchor="middle" font-size="10" font-weight="bold" fill="#b91c1c">233.6ms</text>')
    svg.append(f'    <text x="{col2_x + col2_w*0.37 + w_sub/2}" y="{chart_h + 16}" text-anchor="middle" font-size="9" font-weight="600" fill="#b91c1c">Unpruned</text>')

    svg.append(f'    <rect x="{col2_x + col2_w*0.68}" y="{chart_h - d3_h}" width="{w_sub}" height="{d3_h}" fill="#059669" rx="2"/>')
    svg.append(f'    <text x="{col2_x + col2_w*0.68 + w_sub/2}" y="{chart_h - d3_h - 6}" text-anchor="middle" font-size="10" font-weight="bold" fill="#047857">108.6ms</text>')
    svg.append(f'    <text x="{col2_x + col2_w*0.68 + w_sub/2}" y="{chart_h + 16}" text-anchor="middle" font-size="9" font-weight="bold" fill="#047857">SegWit</text>')

    svg.append('  </g>')
    svg.append('</svg>')

    with open(svg_path, "w") as f:
        f.write("\n".join(svg))
    render_svg_to_png(svg_path, png_path, 820, 440)
    # backward-compatible copy
    legacy_png = os.path.join(FIGURES_DIR, "fig4_evm_comparison.png")
    render_svg_to_png(svg_path, legacy_png, 820, 440)

def generate_fig5():
    """Figure 1: Falcon-EVM Sovereign Execution & Dual-Root Storage Architecture (Formal Academic Monochrome/Slate)."""
    svg_path = os.path.join(FIGURES_DIR, "fig1_architecture.svg")
    png_path = os.path.join(FIGURES_DIR, "fig1_architecture.png")

    width = 920
    height = 470

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif;">',
        '  <defs>',
        '    <marker id="arrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#1e293b"/>',
        '    </marker>',
        '  </defs>',
        
        # Row 1: Pipeline Ingress (3 stages)
        # Box 1: Client / Signer Layer
        '  <rect x="25" y="25" width="255" height="110" fill="#ffffff" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <rect x="25" y="25" width="255" height="26" fill="#f1f5f9" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <text x="152" y="42" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0f172a">Client / Signer Layer</text>',
        '  <text x="38" y="68" font-size="10" font-weight="600" fill="#1e293b">• CLI Signer: falcon-signer</text>',
        '  <text x="38" y="85" font-size="9.5" fill="#334155">• Envelope: EIP-2718 Type 0x46</text>',
        '  <text x="38" y="101" font-size="9" fill="#475569">• Addr: Keccak-256(pk)[12..31] (20 B)</text>',
        '  <text x="38" y="117" font-size="9" fill="#475569">• Witness: [pk: 897 B, sig: ~666 B]</text>',

        # Arrow 1 -> Box 2
        '  <line x1="280" y1="80" x2="328" y2="80" stroke="#1e293b" stroke-width="1.2" marker-end="url(#arrow)"/>',
        '  <rect x="286" y="69" width="36" height="16" fill="#ffffff" stroke="#94a3b8" stroke-width="0.8" rx="2"/>',
        '  <text x="304" y="81" text-anchor="middle" font-size="8" font-weight="600" fill="#334155">RPC</text>',

        # Box 2: JSON-RPC & Mempool
        '  <rect x="332" y="25" width="256" height="110" fill="#ffffff" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <rect x="332" y="25" width="256" height="26" fill="#f1f5f9" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <text x="460" y="42" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0f172a">JSON-RPC &amp; Mempool</text>',
        '  <text x="345" y="68" font-size="10" font-weight="600" fill="#1e293b">• Ingress Nonce &amp; Solvency Gate</text>',
        '  <text x="345" y="85" font-size="9.5" fill="#334155">• Parallel Rayon Batch Verifier</text>',
        '  <text x="345" y="101" font-size="9" fill="#475569">• Hardware AVX2 Integer NTT</text>',
        '  <text x="345" y="117" font-size="9" fill="#475569">• Throughput: &gt; 27,000 TPS Batch</text>',

        # Arrow 2 -> Box 3
        '  <line x1="588" y1="80" x2="636" y2="80" stroke="#1e293b" stroke-width="1.2" marker-end="url(#arrow)"/>',
        '  <rect x="591" y="69" width="42" height="16" fill="#ffffff" stroke="#94a3b8" stroke-width="0.8" rx="2"/>',
        '  <text x="612" y="81" text-anchor="middle" font-size="8" font-weight="600" fill="#334155">Verified</text>',

        # Box 3: Consensus Engine
        '  <rect x="640" y="25" width="255" height="110" fill="#ffffff" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <rect x="640" y="25" width="255" height="26" fill="#f1f5f9" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <text x="767" y="42" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0f172a">Consensus Engine (PoA)</text>',
        '  <text x="653" y="68" font-size="10" font-weight="600" fill="#1e293b">• Deterministic Leader Schedule</text>',
        '  <text x="653" y="85" font-size="9.5" fill="#334155">• Dual-Root Block Assembly</text>',
        '  <text x="653" y="101" font-size="9" fill="#475569">• Slot Duration: 1.0s Fixed Window</text>',
        '  <text x="653" y="117" font-size="9" fill="#475569">• Commits state_root &amp; witness_root</text>',

        # Arrow from Box 3 down to EVM Engine
        '  <line x1="767" y1="135" x2="767" y2="175" stroke="#1e293b" stroke-width="1.2" marker-end="url(#arrow)"/>',

        # Row 2: EVM Execution Engine (revm)
        '  <rect x="25" y="175" width="870" height="130" fill="#f8fafc" stroke="#1e293b" stroke-width="1.4" rx="4"/>',
        '  <rect x="25" y="175" width="870" height="28" fill="#e2e8f0" stroke="#1e293b" stroke-width="1.4" rx="4"/>',
        '  <text x="460" y="194" text-anchor="middle" font-size="12.5" font-weight="700" fill="#0f172a">revm Embedded Execution Pipeline (Sequential State Transition)</text>',

        # Inner Precompile Box
        '  <rect x="50" y="215" width="820" height="48" fill="#ffffff" stroke="#334155" stroke-width="1.2" rx="3"/>',
        '  <text x="460" y="234" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0f172a">Native Precompile 0x15 (Address: 0x0000000000000000000000000000000000000015)</text>',
        '  <text x="460" y="251" text-anchor="middle" font-size="10" fill="#334155">Deterministic AVX2 Montgomery Integer NTT (FIPS 206) | Gas Calibration: Exactly 3,000 gas (Parity with ecrecover)</text>',

        # Contracts Text
        '  <text x="460" y="287" text-anchor="middle" font-size="10" font-weight="600" fill="#475569">Validated Contract Deployments: ERC-20 Fungible Token | Constant-Product AMM DEX (x · y = k) | Post-Quantum ERC-4337 Smart Wallet</text>',

        # Arrow from EVM Engine down to Storage Row
        '  <line x1="460" y1="305" x2="460" y2="345" stroke="#1e293b" stroke-width="1.2" marker-end="url(#arrow)"/>',

        # Row 3: Dual-Root Storage & SegWit Pruning
        # Left: Dual-Root Commitments
        '  <rect x="25" y="345" width="415" height="105" fill="#ffffff" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <rect x="25" y="345" width="415" height="26" fill="#f1f5f9" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <text x="232" y="362" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0f172a">Dual-Root Consensus Commitments</text>',
        '  <text x="40" y="388" font-size="10" font-weight="600" fill="#1e293b">• state_root: Standard EVM Modified Merkle Patricia Trie (MPT)</text>',
        '  <text x="40" y="405" font-size="10" font-weight="600" fill="#1e293b">• receipts_root: Transaction Execution Event Logs (MPT)</text>',
        '  <text x="40" y="422" font-size="10" font-weight="600" fill="#1e293b">• witness_root: BLAKE3 Merkle Tree of Falcon-512 Proofs (32 B)</text>',
        '  <text x="40" y="438" font-size="9" fill="#64748b">→ Execution intents decouple cryptographic witnesses into auxiliary storage</text>',

        # Arrow between Dual Root and Pruning
        '  <line x1="440" y1="397" x2="475" y2="397" stroke="#1e293b" stroke-width="1.2" marker-end="url(#arrow)"/>',
        '  <rect x="444" y="387" width="28" height="18" fill="#ffffff" stroke="#94a3b8" stroke-width="0.8" rx="2"/>',
        '  <text x="458" y="399" text-anchor="middle" font-size="8" font-weight="700" fill="#0f172a">k&gt;100</text>',

        # Right: SegWit Pruning
        '  <rect x="480" y="345" width="415" height="105" fill="#ffffff" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <rect x="480" y="345" width="415" height="26" fill="#f1f5f9" stroke="#334155" stroke-width="1.2" rx="4"/>',
        '  <text x="687" y="362" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0f172a">Epoch Segregated Witness Pruning</text>',
        '  <text x="495" y="388" font-size="10" font-weight="600" fill="#1e293b">• Purges Raw 1.56 KB Falcon Witnesses after Epoch Depth k</text>',
        '  <text x="495" y="405" font-size="10" font-weight="600" fill="#1e293b">• Reclaims 93.6% Disk Bloat (Matches Classical EVM Footprint)</text>',
        '  <text x="495" y="422" font-size="10" fill="#334155">• Preserves Complete Cryptographic Auditability via witness_root</text>',
        '  <text x="495" y="438" font-size="9" fill="#64748b">→ Bounds validating node storage growth to a strict constant line</text>',

        '</svg>'
    ]

    with open(svg_path, "w") as f:
        f.write("\n".join(svg))
    render_svg_to_png(svg_path, png_path, width, height)
    # Also sync fig5 copies for backwards compatibility
    fig5_svg = os.path.join(FIGURES_DIR, "fig5_architecture.svg")
    fig5_png = os.path.join(FIGURES_DIR, "fig5_architecture.png")
    with open(fig5_svg, "w") as f:
        f.write("\n".join(svg))
    render_svg_to_png(fig5_svg, fig5_png, width, height)

def main():
    print("Generating Academic Figures for paper.tex...")
    generate_fig1()
    generate_fig2()
    generate_fig3()
    generate_fig4()
    generate_fig5()
    print("All 5 academic figures generated successfully in figures/")

if __name__ == "__main__":
    main()
