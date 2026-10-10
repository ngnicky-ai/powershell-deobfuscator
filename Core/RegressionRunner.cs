using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace PsDeobfuscator.Core;

/// <summary>
/// 회귀 테스트. Tests\regression.json 의 샘플마다 "반드시 나와야 하는 결과"를 정해 두고,
/// 엔진·규칙을 고칠 때마다 전체를 다시 돌려 기존 탐지가 깨지지 않았는지 확인한다.
/// 기대값은 "최소 조건"으로 적는다 (개선되면 통과, 나빠지면 실패).
/// </summary>
public static class RegressionRunner
{
    public sealed class Case
    {
        public string Name { get; set; } = "";
        /// <summary>regression.json 기준 상대 경로 (또는 절대 경로)</summary>
        public string File { get; set; } = "";
        /// <summary>파일 SHA256 — 다른 파일로 바뀌었는지 확인</summary>
        public string Sha256 { get; set; }
        public int MinDepth { get; set; }
        public int MinLayers { get; set; }
        public int MinRisk { get; set; }
        public List<string> ClassificationContains { get; set; } = new();
        /// <summary>탐지되어야 하는 행위 규칙 ID</summary>
        public List<string> Rules { get; set; } = new();
        /// <summary>추출되어야 하는 IOC 값 (대소문자 무시)</summary>
        public List<string> Iocs { get; set; } = new();
        /// <summary>추출되면 안 되는 값 (과거 오탐 재발 방지)</summary>
        public List<string> ForbiddenIocs { get; set; } = new();
        /// <summary>어떤 레이어의 정리본에든 들어 있어야 하는 문자열</summary>
        public List<string> LayerContains { get; set; } = new();
        /// <summary>'엔진 확장 필요' 항목 최대 개수 (엔진 퇴행 감지)</summary>
        public int? MaxEngineGaps { get; set; }
        public string Note { get; set; }
    }

    public sealed class Suite
    {
        public int Version { get; set; } = 1;
        public List<Case> Cases { get; set; } = new();
    }

    public enum Outcome { Pass, Fail, Skip }

    public sealed class CaseResult
    {
        public Case Case { get; init; }
        public Outcome Outcome { get; set; }
        public List<string> Failures { get; } = new();
        public List<string> Notes { get; } = new();
        public TimeSpan Elapsed { get; set; }
    }

    public sealed class Report
    {
        public string Path { get; init; } = "";
        public List<CaseResult> Results { get; } = new();
        public TimeSpan Elapsed { get; set; }
        public int Passed => Results.Count(r => r.Outcome == Outcome.Pass);
        public int Failed => Results.Count(r => r.Outcome == Outcome.Fail);
        public int Skipped => Results.Count(r => r.Outcome == Outcome.Skip);
        public bool Success => Failed == 0;

        public string ToText()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== 회귀 테스트 ===");
            sb.AppendLine($"파일: {RuleStore.Friendly(Path)}");
            sb.AppendLine($"결과: {(Success ? "통과" : "실패")} — 통과 {Passed} · 실패 {Failed} · 건너뜀 {Skipped} · {Elapsed.TotalSeconds:N1}s");
            sb.AppendLine();
            foreach (var r in Results)
            {
                var tag = r.Outcome switch { Outcome.Pass => "PASS", Outcome.Fail => "FAIL", _ => "SKIP" };
                sb.AppendLine($"[{tag}] {r.Case.Name}  ({r.Elapsed.TotalMilliseconds:N0}ms)");
                foreach (var f in r.Failures) sb.AppendLine("       ✗ " + f);
                foreach (var n in r.Notes) sb.AppendLine("       · " + n);
            }
            return sb.ToString();
        }
    }

    /// <summary>회귀 테스트 파일 위치: 프로젝트 원본 Tests\regression.json (개발 환경) → 실행 폴더.</summary>
    public static string DefaultPath =>
        RuleStore.ProjectDir is { } pd ? Path.Combine(pd, "Tests", "regression.json")
                                       : Path.Combine(RuleStore.AppDir, "Tests", "regression.json");

    public static Suite Load(string path) =>
        System.IO.File.Exists(path)
            ? JsonSerializer.Deserialize<Suite>(System.IO.File.ReadAllText(path), RuleStore.JsonOptions) ?? new Suite()
            : new Suite();

    public static void Save(string path, Suite suite)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        System.IO.File.WriteAllText(path, JsonSerializer.Serialize(suite, RuleStore.JsonOptions), new UTF8Encoding(false));
    }

    public static string ResolveFile(string suitePath, string file) =>
        System.IO.Path.IsPathRooted(file) ? file : System.IO.Path.GetFullPath(System.IO.Path.Combine(System.IO.Path.GetDirectoryName(suitePath)!, file));

    public static Report Run(string path = null, Action<string> progress = null)
    {
        path ??= DefaultPath;
        var sw = Stopwatch.StartNew();
        var rep = new Report { Path = path };
        var suite = Load(path);
        foreach (var c in suite.Cases)
        {
            progress?.Invoke(c.Name);
            rep.Results.Add(RunCase(path, c));
        }
        rep.Elapsed = sw.Elapsed;
        return rep;
    }

    static CaseResult RunCase(string suitePath, Case c)
    {
        var res = new CaseResult { Case = c };
        var sw = Stopwatch.StartNew();
        var file = ResolveFile(suitePath, c.File);
        if (!System.IO.File.Exists(file))
        {
            // 백신이 샘플을 격리하면 파일이 사라진다 — 실패가 아니라 건너뜀으로 표시
            res.Outcome = Outcome.Skip;
            res.Notes.Add($"샘플 파일이 없습니다 (백신 격리 여부 확인): {RuleStore.Friendly(file)}");
            return res;
        }

        AnalysisResult r;
        byte[] bytes;
        try
        {
            bytes = System.IO.File.ReadAllBytes(file);
            r = Deobfuscator.Analyze(App.DecodeFileText(bytes), System.IO.Path.GetFileName(file), file, bytes);
        }
        catch (Exception ex)
        {
            res.Outcome = Outcome.Fail;
            res.Failures.Add("분석 중 예외: " + ex.Message);
            return res;
        }

        if (!string.IsNullOrEmpty(c.Sha256) && !c.Sha256.Equals(r.File.Sha256, StringComparison.OrdinalIgnoreCase))
            res.Notes.Add("샘플 내용이 기록 당시와 다릅니다 (SHA256 불일치).");

        int depth = r.AllLayers.Max(l => l.Depth);
        if (depth < c.MinDepth) res.Failures.Add($"해제 단계 {depth} < 기대 {c.MinDepth}");
        if (r.AllLayers.Count < c.MinLayers) res.Failures.Add($"레이어 수 {r.AllLayers.Count} < 기대 {c.MinLayers}");
        if (r.RiskScore < c.MinRisk) res.Failures.Add($"위험도 {r.RiskScore} < 기대 {c.MinRisk}");
        foreach (var cls in c.ClassificationContains)
            if (!r.Classification.Contains(cls, StringComparison.OrdinalIgnoreCase))
                res.Failures.Add($"유형에 '{cls}' 없음 (실제: {r.Classification})");

        var ruleIds = r.Findings.Select(f => f.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var missingRules = c.Rules.Where(id => !ruleIds.Contains(id)).ToList();
        if (missingRules.Count > 0) res.Failures.Add("미탐 규칙: " + string.Join(", ", missingRules));

        var iocValues = r.Iocs.Select(i => i.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var missingIoc = c.Iocs.Where(v => !iocValues.Contains(v)).ToList();
        if (missingIoc.Count > 0) res.Failures.Add("누락 IOC: " + string.Join(", ", missingIoc));
        var forbidden = c.ForbiddenIocs.Where(v => iocValues.Contains(v)).ToList();
        if (forbidden.Count > 0) res.Failures.Add("오탐 IOC 재발: " + string.Join(", ", forbidden));

        foreach (var s in c.LayerContains)
            if (!r.AllLayers.Any(l => (l.CleanContent ?? "").Contains(s, StringComparison.OrdinalIgnoreCase) ||
                                      (l.RawContent ?? "").Contains(s, StringComparison.OrdinalIgnoreCase)))
                res.Failures.Add($"어느 레이어에도 '{s}' 가 없음 (해독 퇴행)");

        int gaps = r.Gaps.Count(g => g.Kind == GapKind.NeedsEngine);
        if (c.MaxEngineGaps is int max && gaps > max)
            res.Failures.Add($"'엔진 확장 필요' 항목 {gaps}개 > 허용 {max}개: " + string.Join(", ", r.Gaps.Where(g => g.Kind == GapKind.NeedsEngine).Select(g => g.Detail).Take(5)));

        // 새로 생긴 정보 (실패는 아님): 기대값에 없는 규칙/IOC — 스냅샷 갱신 후보
        var extraRules = ruleIds.Except(c.Rules, StringComparer.OrdinalIgnoreCase).ToList();
        if (extraRules.Count > 0) res.Notes.Add("기대값에 없는 추가 탐지: " + string.Join(", ", extraRules));

        res.Outcome = res.Failures.Count == 0 ? Outcome.Pass : Outcome.Fail;
        res.Elapsed = sw.Elapsed;
        return res;
    }

    /// <summary>현재 분석 결과를 기대값으로 기록한다 (같은 파일의 기존 항목은 교체).</summary>
    public static Case Snapshot(AnalysisResult r, string suitePath)
    {
        var dir = System.IO.Path.GetDirectoryName(suitePath)!;
        var file = string.IsNullOrEmpty(r.File.Path) ? r.File.Name : r.File.Path;
        var rel = System.IO.Path.IsPathRooted(file) && System.IO.Path.GetPathRoot(file) == System.IO.Path.GetPathRoot(dir)
            ? System.IO.Path.GetRelativePath(dir, file) : file;
        var label = r.Classification.Split('+')[0].Trim();
        return new Case
        {
            Name = $"{r.File.Name} — {label}",
            File = rel.Replace('\\', '/'),
            Sha256 = r.File.Sha256,
            MinDepth = r.AllLayers.Max(l => l.Depth),
            MinLayers = r.AllLayers.Count,
            MinRisk = Math.Max(0, r.RiskScore - 10),
            ClassificationContains = r.Classification.Split('+').Select(s => s.Trim()).Where(s => s.Length > 0).Take(2)
                .Select(s => s.Split(' ')[0]).ToList(),
            // 중간 이상 규칙만 고정 (낮음/정보 규칙은 다듬는 과정에서 바뀌기 쉬움)
            Rules = r.Findings.Where(f => f.Severity >= Severity.Medium).Select(f => f.RuleId).Distinct().OrderBy(x => x).ToList(),
            Iocs = r.Iocs.Where(i => !i.Benign && i.Type is "URL" or "도메인" or "IP" or "채굴 풀" or "지갑/계정" or "레지스트리")
                .Select(i => i.Value).Distinct().ToList(),
            LayerContains = new(),
            MaxEngineGaps = r.Gaps.Count(g => g.Kind == GapKind.NeedsEngine),
        };
    }

    public static void AddOrReplace(string suitePath, Case c)
    {
        var suite = Load(suitePath);
        suite.Cases.RemoveAll(x => x.File.Equals(c.File, StringComparison.OrdinalIgnoreCase) ||
                                   (!string.IsNullOrEmpty(x.Sha256) && x.Sha256.Equals(c.Sha256, StringComparison.OrdinalIgnoreCase)));
        suite.Cases.Add(c);
        Save(suitePath, suite);
    }
}
