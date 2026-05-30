# Capframe demo — Find → Bind → Guard end-to-end on a known surface.
#
# Run with: vhs examples/demo.tape  → produces examples/demo.gif
# Requires:
#   - VHS (https://github.com/charmbracelet/vhs)
#   - capframe, mcp-recon, capnagent installed (capframe.ai/install)
#   - jq for inline output filtering
#
# This tape is the SCRIPT, not the recording. Recording produces the
# real terminal capture each time; the gif is regenerated, never
# hand-edited.

Output examples/demo.gif

# Slow enough that a non-Rust-pilled viewer can follow.
Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1200
Set Height 720
Set PlaybackSpeed 1.0
Set TypingSpeed 50ms
Set Padding 20

# Banner
Type "# Capframe — Find → Bind → Guard, in under a minute" Sleep 600ms Enter
Type "# Scanning a shopify-style MCP server end-to-end." Sleep 600ms Enter
Sleep 1s
Type "clear" Enter
Sleep 500ms

# ─── FIND ─────────────────────────────────────────────────────────────
Type "# 1. FIND — read the tool surface, run R1-R7 rules, emit findings.v1" Sleep 400ms Enter
Sleep 800ms

Type "capframe find examples/shopify-mcp.inventory.json --out findings.json --pretty" Enter
Sleep 2s

Type "jq '.summary' findings.json" Enter
Sleep 2s

Type "jq '[.findings[] | {id, severity, category, title}]' findings.json | head -40" Enter
Sleep 3s

# ─── BIND ─────────────────────────────────────────────────────────────
Type "" Enter
Type "# 2. BIND — turn authority-relevant findings into capability caveats" Sleep 400ms Enter
Sleep 800ms

Type "capframe bind examples/shopify-mcp.inventory.json --out caveats.json --pretty" Enter
Sleep 2s

Type "jq '.plans[] | {tool, recommend, caveats: [.caveats[].dsl]}' caveats.json" Enter
Sleep 3s

# capnagent issues the actual token. Show the verb, don't unpack the bytes.
Type "capnagent issue --plan caveats.json --out token.bin" Enter
Sleep 1s
Type "file token.bin && stat -c '%s bytes' token.bin" Enter
Sleep 2s

# ─── GUARD ────────────────────────────────────────────────────────────
Type "" Enter
Type "# 3. GUARD — evaluate the token against an attempted call" Sleep 400ms Enter
Sleep 800ms

# A call that respects the caveat (within max_amount) — ALLOWED.
Type "capframe guard --token token.bin --tool order.refund --args '{\"order_id\":\"123\",\"amount\":47.50}'" Enter
Sleep 2s

# A call that exceeds it — DENIED with the rule citation.
Type "capframe guard --token token.bin --tool order.refund --args '{\"order_id\":\"123\",\"amount\":9999.00}'" Enter
Sleep 3s

Type "" Enter
Type "# Whole pipeline: deterministic. Same inputs → same outputs, every run." Sleep 400ms Enter
Sleep 1500ms
