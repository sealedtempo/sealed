// Served as /assets/app.css so the CSP can forbid inline styles.
export const STYLESHEET = `
:root { color-scheme: light dark; --fg: #1d2330; --muted: #5f6b7a; --bg: #f7f8fa; --card: #ffffff; --line: #dde2e8;
  --accent: #2f5bd3; --ok: #1f7a46; --bad: #b42318; --warn: #9a6700; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6e9ee; --muted: #9aa5b4; --bg: #12151b; --card: #1a1f27; --line: #2c333e; --accent: #7ea2ff;
    --ok: #4cc38a; --bad: #ff7b72; --warn: #e3b341; }
}
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
header { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--line); background: var(--card); }
.brand { font-weight: 650; color: var(--fg); text-decoration: none; font-size: 17px; }
.tag { font-size: 12px; color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 1px 8px; }
main { max-width: 1100px; margin: 0 auto; padding: 16px; }
section { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; margin-bottom: 16px; }
h1 { font-size: 20px; margin: 0 0 12px; display: flex; align-items: center; gap: 10px; }
h2 { font-size: 16px; margin: 0 0 10px; }
h2 small { color: var(--muted); font-weight: 400; }
label { display: block; margin: 0 0 12px; font-weight: 550; }
label small { display: block; font-weight: 400; color: var(--muted); }
label.check { font-weight: 400; display: flex; gap: 8px; align-items: center; }
textarea, input, select { width: 100%; font: inherit; color: inherit; background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 7px 9px; margin-top: 4px; }
textarea { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
input[type=checkbox] { width: auto; margin: 0; }
.row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
button, .button { display: inline-block; font: inherit; font-weight: 550; border: 1px solid var(--accent); background: var(--accent); color: #fff;
  border-radius: 6px; padding: 7px 14px; cursor: pointer; text-decoration: none; }
button.secondary, .button { background: transparent; color: var(--accent); }
button.danger { background: transparent; border-color: var(--bad); color: var(--bad); }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.actions form { margin: 0; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 550; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.url { word-break: break-all; }
.scroll { overflow-x: auto; }
.muted { color: var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0 0 14px; }
dt { color: var(--muted); }
dd { margin: 0; }
.badge { font-size: 12px; font-weight: 600; border-radius: 999px; padding: 1px 9px; border: 1px solid currentColor; }
.badge.succeeded { color: var(--ok); }
.badge.failed { color: var(--bad); }
.badge.running, .badge.queued { color: var(--accent); }
.badge.cancelled { color: var(--warn); }
.errors { border: 1px solid var(--bad); color: var(--bad); border-radius: 8px; padding: 8px 12px; margin-bottom: 12px; }
.errors p { margin: 0; font-weight: 600; }
.errors ul { margin: 4px 0 0; padding-left: 18px; }
footer { max-width: 1100px; margin: 0 auto; padding: 0 16px 24px; color: var(--muted); font-size: 13px; }
`;
