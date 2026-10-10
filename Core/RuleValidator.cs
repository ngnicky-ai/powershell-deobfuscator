using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

/// <summary>
/// rules.json 자체 테스트. 규칙을 추가/수정한 뒤 배포 전에 실행해 다음을 막는다.
///  - 문법 오류 (필수 필드 누락, 중복 ID, 잘못된 심각도/정규식/ATT&amp;CK ID)
///  - 미탐: examples 가 탐지되지 않음
///  - 오탐: counterExamples 가 탐지됨
///  - 성능: 큰 입력에서 느려지는 정규식 (ReDoS)
/// </summary>
public static class RuleValidator
{
    public enum Level { Error, Warning, Info }

    public sealed class Issue
    {
        public Level Level { get; init; }
        public string Rule { get; init; } = "";
        public string Message { get; init; } = "";
        public string LevelText => Level switch { Level.Error => "오류", Level.Warning => "경고", _ => "정보" };
    }

    public sealed class Report
    {
        public string Path { get; init; } = "";
        public List<Issue> Issues { get; } = new();
        public int BehaviorCount { get; set; }
        public int CommandCount { get; set; }
        public int ExamplesChecked { get; set; }
        public int CounterExamplesChecked { get; set; }
        public int RulesWithExamples { get; set; }
        public TimeSpan Elapsed { get; set; }
        public int Errors => Issues.Count(i => i.Level == Level.Error);
        public int Warnings => Issues.Count(i => i.Level == Level.Warning);
        public bool Passed => Errors == 0;

        public string ToText()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== 규칙 자체 테스트 ===");
            sb.AppendLine($"파일: {RuleStore.Friendly(Path)}");
            sb.AppendLine($"행위 규칙 {BehaviorCount}개 (예시 보유 {RulesWithExamples}개) · 명령어 설명 {CommandCount}개");
            sb.AppendLine($"예시 {ExamplesChecked}건 · 반례 {CounterExamplesChecked}건 검사 · {Elapsed.TotalMilliseconds:N0}ms");
            sb.AppendLine($"결과: {(Passed ? "통과" : "실패")} — 오류 {Errors} · 경고 {Warnings}");
            sb.AppendLine();
            foreach (var g in Issues.OrderBy(i => i.Level).GroupBy(i => i.Level))
            {
                sb.AppendLine($"[{g.First().LevelText}]");
                foreach (var i in g) sb.AppendLine($"  {i.Rule,-8} {i.Message}");
                sb.AppendLine();
            }
            return sb.ToString();
        }
    }

    static readonly Regex MitreId = new(@"^T\d{4}(\.\d{3})?$", RegexOptions.Compiled);
    static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(300);

    // ReDoS 점검용 입력: 반복 문자, Base64 덩어리, 긴 코드 한 줄
    static readonly Lazy<string[]> StressInputs = new(() =>
    {
        var rnd = new Random(1);
        var b64 = new StringBuilder();
        const string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 200_000; i++) b64.Append(alpha[rnd.Next(alpha.Length)]);
        return new[]
        {
            new string('a', 100_000) + "!",
            new string(' ', 50_000) + "-" + new string('w', 50_000),
            b64.ToString(),
            string.Concat(Enumerable.Repeat("$a='x'+'y'; ", 15_000)),
            string.Concat(Enumerable.Repeat("\\\\", 50_000)),
        };
    });

    public static Report Validate(string path = null)
    {
        path ??= RuleStore.RulePath;
        var sw = Stopwatch.StartNew();
        var rep = new Report { Path = path };
        RuleStore.RuleFile file;
        try
        {
            file = RuleStore.ReadRaw(path);
        }
        catch (Exception ex)
        {
            rep.Issues.Add(new Issue { Level = Level.Error, Rule = "(파일)", Message = "JSON 을 읽을 수 없습니다: " + ex.Message });
            return rep;
        }

        rep.BehaviorCount = file.Behaviors.Count;
        rep.CommandCount = file.Commands.Count;

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in file.Behaviors)
        {
            var id = string.IsNullOrWhiteSpace(b.Id) ? "(ID없음)" : b.Id;
            void Add(Level l, string msg) => rep.Issues.Add(new Issue { Level = l, Rule = id, Message = msg });

            if (string.IsNullOrWhiteSpace(b.Id)) Add(Level.Error, "id 가 없습니다.");
            else if (!ids.Add(b.Id)) Add(Level.Error, "id 가 중복됩니다.");
            if (string.IsNullOrWhiteSpace(b.Name)) Add(Level.Error, "name 이 없습니다.");
            if (string.IsNullOrWhiteSpace(b.Description)) Add(Level.Warning, "description 이 없습니다 (사용자에게 설명이 표시되지 않음).");
            if (!Enum.TryParse<Severity>(b.Severity, true, out _))
                Add(Level.Error, $"severity '{b.Severity}' 는 Critical/High/Medium/Low/Info 중 하나여야 합니다.");
            if (!string.IsNullOrEmpty(b.Mitre))
            {
                if (!MitreId.IsMatch(b.Mitre)) Add(Level.Warning, $"mitre '{b.Mitre}' 형식이 올바르지 않습니다 (예: T1059.001).");
                if (string.IsNullOrEmpty(b.Tactic)) Add(Level.Warning, "mitre 가 있지만 tactic 이 비어 있습니다.");
            }

            var rx = CheckPattern(b.Pattern, Add);
            if (rx == null) continue;
            CheckExamples(rx, b.Examples, b.CounterExamples, Add, rep);
            if (b.Examples.Count == 0) Add(Level.Warning, "examples 가 없습니다 — 규칙이 깨져도 알아챌 수 없습니다.");
            else rep.RulesWithExamples++;
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in file.Commands)
        {
            var id = string.IsNullOrWhiteSpace(c.Name) ? "(이름없음)" : "cmd:" + c.Name;
            void Add(Level l, string msg) => rep.Issues.Add(new Issue { Level = l, Rule = id, Message = msg });
            if (string.IsNullOrWhiteSpace(c.Name)) Add(Level.Error, "name 이 없습니다.");
            else if (!names.Add(c.Name)) Add(Level.Warning, "같은 이름의 명령어 설명이 이미 있습니다.");
            if (string.IsNullOrWhiteSpace(c.Description)) Add(Level.Warning, "description 이 없습니다.");
            var rx = CheckPattern(c.Pattern, Add);
            if (rx != null) CheckExamples(rx, c.Examples, c.CounterExamples, Add, rep);
        }

        sw.Stop();
        rep.Elapsed = sw.Elapsed;
        return rep;
    }

    static Regex CheckPattern(string pattern, Action<Level, string> add)
    {
        if (string.IsNullOrEmpty(pattern)) { add(Level.Error, "pattern 이 없습니다."); return null; }
        Regex rx;
        try { rx = new Regex(pattern, Analyzer.RuleRegexOptions, MatchTimeout); }
        catch (ArgumentException ex) { add(Level.Error, "정규식 오류: " + ex.Message); return null; }

        try
        {
            if (rx.IsMatch("")) add(Level.Error, "빈 문자열과 일치합니다 — 모든 입력에서 탐지됩니다.");
            else if (rx.IsMatch("x") || rx.IsMatch(" ")) add(Level.Error, "한 글자 입력과도 일치합니다 — 지나치게 넓은 패턴입니다.");
        }
        catch (RegexMatchTimeoutException) { }

        foreach (var s in StressInputs.Value)
        {
            var sw = Stopwatch.StartNew();
            try { rx.Matches(s).Count.ToString(); }
            catch (RegexMatchTimeoutException)
            {
                add(Level.Warning, $"큰 입력({s.Length:N0}자)에서 {MatchTimeout.TotalMilliseconds:N0}ms 안에 끝나지 않습니다 — 역추적 폭주(ReDoS) 위험.");
                break;
            }
            if (sw.ElapsedMilliseconds > 150)
            {
                add(Level.Warning, $"큰 입력({s.Length:N0}자)에서 {sw.ElapsedMilliseconds}ms 걸립니다 — 패턴 최적화를 검토하세요.");
                break;
            }
        }
        return rx;
    }

    static void CheckExamples(Regex rx, List<string> examples, List<string> counters, Action<Level, string> add, Report rep)
    {
        foreach (var ex in examples ?? new())
        {
            rep.ExamplesChecked++;
            bool hit;
            try { hit = rx.IsMatch(ex); } catch (RegexMatchTimeoutException) { hit = false; }
            if (!hit) add(Level.Error, $"미탐 — 예시가 탐지되지 않습니다: {Short(ex)}");
        }
        foreach (var ce in counters ?? new())
        {
            rep.CounterExamplesChecked++;
            bool hit;
            try { hit = rx.IsMatch(ce); } catch (RegexMatchTimeoutException) { hit = true; }
            if (hit) add(Level.Error, $"오탐 — 반례가 탐지됩니다: {Short(ce)}");
        }
    }

    static string Short(string s)
    {
        s = s.Replace("\r", " ").Replace("\n", " ");
        return s.Length <= 120 ? s : s[..120] + "…";
    }
}
