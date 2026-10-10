using System.Net;
using System.Text;
using System.Text.Json;

namespace PsDeobfuscator.Core;

public static class ReportExporter
{
    public static string ToText(AnalysisResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== {r.File.Name} ===");
        sb.AppendLine($"SHA256: {r.File.Sha256}  크기: {r.File.Size:N0}  엔트로피: {r.File.Entropy:F2}");
        sb.AppendLine($"위험도: {r.RiskScore} ({r.RiskLevel})  유형: {r.Classification}  소요: {r.Elapsed.TotalMilliseconds:N0}ms");
        sb.AppendLine("\n[요약]");
        foreach (var l in r.SummaryLines) sb.AppendLine(" - " + l);
        sb.AppendLine("\n[레이어]");
        foreach (var l in r.AllLayers) sb.AppendLine($"{new string(' ', l.Depth * 2)}L{l.Depth} {l.Title} | {l.Method} | {l.SizeText}");
        sb.AppendLine("\n[행위]");
        foreach (var f in r.Findings) sb.AppendLine($" [{f.SeverityText}] {f.Category} / {f.Name} {f.Mitre}  ← L{f.LayerDepth}: {f.Evidence}");
        sb.AppendLine("\n[IOC]");
        foreach (var i in r.Iocs) sb.AppendLine($" {i.Type,-10} {i.Value}{(i.Benign ? "  (정상)" : "")}");
        sb.AppendLine("\n[명령어]");
        foreach (var c in r.Commands) sb.AppendLine($" {(c.Suspicious ? "!" : " ")} {c.Name} x{c.Count}");
        sb.AppendLine("\n[진단 - 해독 상태]");
        foreach (var w in r.Warnings) sb.AppendLine($" [{w.LevelText}] L{w.LayerDepth} {w.Reason}{(string.IsNullOrEmpty(w.Evidence) ? "" : "  ← " + w.Evidence)}");
        sb.AppendLine("\n[진단 - 엔진 미지원 항목]");
        foreach (var g in r.Gaps) sb.AppendLine($" [{g.KindText}] {g.Detail} x{g.Count} ({g.LayersText})  예: {g.Example}");
        foreach (var l in r.AllLayers)
        {
            sb.AppendLine($"\n----- L{l.Depth} {l.Title} ({l.Method}) — 정리본 -----");
            var c = l.CleanContent ?? "";
            sb.AppendLine(c.Length > 12000 ? c[..12000] + "\n...(생략)" : c);
        }
        return sb.ToString();
    }

    public static string ToIocCsv(AnalysisResult r)
    {
        var sb = new StringBuilder("type,value,defanged,layer,note,context\r\n");
        foreach (var i in r.Iocs)
            sb.AppendLine(string.Join(",", new[] { i.Type, i.Value, i.Defanged, "L" + i.LayerDepth, i.Note, i.Context }.Select(Csv)));
        return sb.ToString();
    }

    static string Csv(string s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";

    public static string ToJson(AnalysisResult r)
    {
        var obj = new
        {
            file = r.File,
            risk = new { score = r.RiskScore, level = r.RiskLevel, classification = r.Classification },
            summary = r.SummaryLines,
            obfuscation = r.ObfuscationTechniques,
            layers = r.AllLayers.Select(l => new { depth = l.Depth, title = l.Title, method = l.Method, size = l.Length, binary = l.IsBinary }),
            findings = r.Findings.Select(f => new { f.Category, f.Name, f.Mitre, severity = f.Severity.ToString(), f.Evidence, layer = f.LayerDepth }),
            iocs = r.Iocs.Select(i => new { i.Type, i.Value, i.Defanged, i.Benign, layer = i.LayerDepth }),
            mitre = r.Mitre.Select(m => new { m.Id, m.Name, m.Tactic }),
            diagnostics = new
            {
                warnings = r.Warnings.Select(w => new { layer = w.LayerDepth, w.Suspicious, w.Reason, w.Evidence }),
                engineGaps = r.Gaps.Select(g => new { kind = g.Kind.ToString(), g.Detail, g.Count, layers = g.Layers, g.Example }),
            },
        };
        return JsonSerializer.Serialize(obj, new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
    }

    static string H(string s) => WebUtility.HtmlEncode(s ?? "");

    public static string ToHtml(AnalysisResult r)
    {
        var sevColor = new Dictionary<Severity, string>
        {
            [Severity.Critical] = "#ff4d6d", [Severity.High] = "#ff8c42", [Severity.Medium] = "#f7c948",
            [Severity.Low] = "#4cc9f0", [Severity.Info] = "#8d99ae"
        };
        string riskColor = r.RiskScore >= 75 ? "#ff4d6d" : r.RiskScore >= 50 ? "#ff8c42" : r.RiskScore >= 25 ? "#f7c948" : "#2ec4b6";
        var sb = new StringBuilder();
        sb.Append($@"<!doctype html><html lang=""ko""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width,initial-scale=1"">
<title>PowerShell 분석 보고서 - {H(r.File.Name)}</title>
<style>
:root{{--bg:#0f1220;--card:#171b2e;--line:#262b45;--text:#e6e8f2;--muted:#8a90ad;--accent:#7c5cff;--accent2:#00d4ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 'Segoe UI','Malgun Gothic',sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:32px 16px}}
h1{{margin:0 0 4px;font-size:26px;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;color:transparent}}
h2{{font-size:17px;margin:0 0 12px;color:#fff}}
.sub{{color:var(--muted)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin:16px 0}}
.grid{{display:grid;grid-template-columns:200px 1fr;gap:16px}}
.risk{{text-align:center;border-radius:14px;padding:20px;background:var(--card);border:1px solid var(--line)}}
.risk .n{{font-size:54px;font-weight:700;color:{riskColor}}}
.chip{{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;margin:2px;background:#262b45;color:#cfd3ea}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600}}code,pre{{font-family:Consolas,'Cascadia Mono',monospace}}
pre{{background:#0b0e1a;border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto;max-height:520px;font-size:12.5px;white-space:pre-wrap;word-break:break-all}}
.sev{{font-weight:700;padding:2px 8px;border-radius:6px;color:#111;font-size:12px}}
.kv td:first-child{{color:var(--muted);width:90px}}
li{{margin:4px 0}}a{{color:var(--accent2)}}
@media(max-width:700px){{.grid{{grid-template-columns:1fr}}}}
</style></head><body><div class=""wrap"">
<h1>PowerShell 난독화 분석 보고서</h1>
<div class=""sub"">{H(r.File.Name)} · 생성 {DateTime.Now:yyyy-MM-dd HH:mm} · PS Deobfuscator</div>
<div class=""grid"" style=""margin-top:20px"">
<div class=""risk""><div class=""sub"">위험도</div><div class=""n"">{r.RiskScore}</div><div style=""color:{riskColor};font-weight:700"">{H(r.RiskLevel)}</div></div>
<div class=""card"" style=""margin:0""><h2>분류: {H(r.Classification)}</h2><table class=""kv"">
<tr><td>SHA256</td><td><code>{r.File.Sha256}</code></td></tr><tr><td>MD5</td><td><code>{r.File.Md5}</code></td></tr>
<tr><td>크기</td><td>{r.File.Size:N0} bytes · 엔트로피 {r.File.Entropy:F2}</td></tr></table>
<div style=""margin-top:8px"">{string.Join("", r.ObfuscationTechniques.Select(t => $"<span class=chip>{H(t)}</span>"))}</div></div></div>");

        sb.Append(@"<div class=""card""><h2>요약</h2><ul>");
        foreach (var l in r.SummaryLines) sb.Append($"<li>{H(l)}</li>");
        sb.Append("</ul></div>");

        sb.Append(@"<div class=""card""><h2>행위 분석</h2><table><tr><th>심각도</th><th>행위</th><th>설명 / 증거</th><th>ATT&amp;CK</th></tr>");
        foreach (var f in r.Findings)
            sb.Append($@"<tr><td><span class=sev style=""background:{sevColor[f.Severity]}"">{H(f.SeverityText)}</span></td><td><b>{H(f.Name)}</b><div class=sub>{H(f.Category)}</div></td><td>{H(f.Description)}<pre style=""margin:6px 0 0;max-height:120px"">L{f.LayerDepth}: {H(f.Evidence)}</pre></td><td>{(f.Mitre == "" ? "" : $"<a href=\"{f.MitreUrl}\">{f.Mitre}</a><div class=sub>{H(f.MitreName)}</div>")}</td></tr>");
        sb.Append("</table></div>");

        sb.Append(@"<div class=""card""><h2>IOC (침해 지표)</h2><table><tr><th>유형</th><th>값 (디팽)</th><th>비고</th></tr>");
        foreach (var i in r.Iocs)
            sb.Append($"<tr><td>{H(i.Type)}</td><td><code>{H(i.Defanged)}</code></td><td class=sub>{H(i.Note)}</td></tr>");
        sb.Append("</table></div>");

        sb.Append(@"<div class=""card""><h2>사용된 명령어 / API 설명</h2><table><tr><th>이름</th><th>종류</th><th>설명</th></tr>");
        foreach (var c in r.Commands)
            sb.Append($"<tr><td><b>{H(c.Name)}</b>{(c.Suspicious ? " <span class=chip style='background:#4a1d2a;color:#ff9fb2'>의심</span>" : "")}</td><td class=sub>{H(c.Kind)}</td><td>{H(c.Description)}</td></tr>");
        sb.Append("</table></div>");

        if (r.Warnings.Count > 0 || r.Gaps.Any(g => g.Actionable))
        {
            sb.Append(@"<div class=""card""><h2>진단 (해독 상태 · 엔진 미지원)</h2><table><tr><th>구분</th><th>내용</th></tr>");
            foreach (var w in r.Warnings)
                sb.Append($"<tr><td>{H(w.LevelText)}<div class=sub>L{w.LayerDepth}</div></td><td>{H(w.Reason)}{(string.IsNullOrEmpty(w.Evidence) ? "" : $"<pre style='margin:6px 0 0'>{H(w.Evidence)}</pre>")}</td></tr>");
            foreach (var g in r.Gaps.Where(g => g.Actionable))
                sb.Append($"<tr><td>{H(g.KindText)}<div class=sub>×{g.Count} {H(g.LayersText)}</div></td><td><code>{H(g.Detail)}</code><pre style='margin:6px 0 0'>{H(g.Example)}</pre></td></tr>");
            sb.Append("</table></div>");
        }

        sb.Append(@"<div class=""card""><h2>난독화 레이어</h2>");
        foreach (var l in r.AllLayers)
        {
            var c = l.CleanContent ?? "";
            if (c.Length > 60000) c = c[..60000] + "\n... (생략)";
            sb.Append($@"<details {(l == r.FinalLayer ? "open" : "")}><summary><b>L{l.Depth} · {H(l.Title)}</b> <span class=sub>{H(l.Method)} · {l.SizeText}</span></summary><pre>{H(c)}</pre></details>");
        }
        sb.Append("</div><div class=sub style='text-align:center;margin-top:24px'>본 보고서는 스크립트를 실행하지 않고 정적 분석으로 생성되었습니다.</div></div></body></html>");
        return sb.ToString();
    }
}
