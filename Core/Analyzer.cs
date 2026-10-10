using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

/// <summary>복호화된 레이어들로부터 IOC·행위·명령어·위험도·요약을 만든다.</summary>
public static class Analyzer
{
    sealed record Rule(string Id, string Category, string Name, string Desc, string Mitre, string MitreName, string Tactic, Severity Sev, Regex Rx);

    static Rule R(string id, string cat, string name, string desc, string mitre, string mitreName, string tactic, Severity sev, string pattern) =>
        new(id, cat, name, desc, mitre, mitreName, tactic, sev, new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled));

    static Rule[] _rules;
    static int _rulesGeneration = -1;

    /// <summary>Rules/rules.json 에서 읽은 행위 탐지 규칙 (규칙을 다시 읽으면 재컴파일).</summary>
    static Rule[] Rules
    {
        get
        {
            if (_rules == null || _rulesGeneration != RuleStore.Generation)
            {
                _rules = RuleStore.Data.Behaviors
                    .Select(b => R(b.Id, b.Category, b.Name, b.Description, b.Mitre ?? "", b.MitreName ?? "", b.Tactic ?? "",
                        Enum.TryParse<Severity>(b.Severity, true, out var sv) ? sv : Severity.Info, b.Pattern))
                    .ToArray();
                _rulesGeneration = RuleStore.Generation;
            }
            return _rules;
        }
    }

    /// <summary>규칙 검증기와 분석기가 같은 옵션으로 정규식을 만들도록 공유</summary>
    public const RegexOptions RuleRegexOptions = RegexOptions.IgnoreCase;

    static readonly Dictionary<Severity, int> Weight = new()
    {
        [Severity.Critical] = 25, [Severity.High] = 14, [Severity.Medium] = 6, [Severity.Low] = 2, [Severity.Info] = 0
    };

    public static void Analyze(AnalysisResult r)
    {
        var textLayers = r.AllLayers.Where(l => !l.IsBinary).ToList();

        // ---------- 행위 규칙 ----------
        var found = new Dictionary<string, BehaviorFinding>();
        foreach (var rule in Rules)
        {
            // 깊은 레이어(실제 페이로드) 우선으로 증거를 고른다
            foreach (var layer in textLayers.OrderByDescending(l => l.Depth))
            {
                var src = layer.Depth == 0 ? layer.RawContent : layer.CleanContent + "\n" + layer.RawContent;
                var m = rule.Rx.Match(src);
                if (!m.Success) continue;
                found[rule.Id] = new BehaviorFinding
                {
                    RuleId = rule.Id, Category = rule.Category, Name = rule.Name, Description = rule.Desc,
                    Mitre = rule.Mitre, MitreName = rule.MitreName, Severity = rule.Sev,
                    Evidence = LineAround(src, m.Index), LayerDepth = layer.Depth
                };
                break;
            }
        }

        // ---------- IOC ----------
        IocExtractor.Extract(r);

        // 다중 URL 순회 (백업 유포지)
        int urlCount = r.Iocs.Count(i => i.Type == "URL");
        if (urlCount >= 3 && (found.ContainsKey("DLF") || found.ContainsKey("DLS") || found.ContainsKey("IWR")))
        {
            found["FBK"] = new BehaviorFinding
            {
                RuleId = "FBK", Category = "통신", Name = $"다중 유포지 순회 ({urlCount}개 URL)",
                Description = "여러 개의 다운로드 URL 을 순서대로 시도하여 일부 서버가 차단돼도 감염이 성공하도록 합니다 (Emotet 계열 다운로더의 전형적 특징).",
                Mitre = "T1008", MitreName = "Fallback Channels", Severity = Severity.High,
                Evidence = string.Join("\n", r.Iocs.Where(i => i.Type == "URL").Take(6).Select(i => i.Defanged)),
                LayerDepth = r.Iocs.First(i => i.Type == "URL").LayerDepth
            };
        }

        r.Findings.AddRange(found.Values.OrderByDescending(f => f.Severity).ThenBy(f => f.Category));

        // ---------- 난독화 기법 ----------
        DetectObfuscation(r);

        // ---------- MITRE ----------
        var tacticOf = Rules.Where(x => x.Mitre != "").GroupBy(x => x.Mitre).ToDictionary(g => g.Key, g => g.First().Tactic);
        tacticOf["T1008"] = "Command and Control";
        foreach (var g in r.Findings.Where(f => !string.IsNullOrEmpty(f.Mitre)).GroupBy(f => f.Mitre))
            r.Mitre.Add(new MitreItem { Id = g.Key, Name = g.First().MitreName, Tactic = tacticOf.GetValueOrDefault(g.Key, ""), Count = g.Count() });
        r.Mitre.Sort((a, b) => TacticOrder(a.Tactic).CompareTo(TacticOrder(b.Tactic)));

        // ---------- 명령어 설명 ----------
        var allClean = string.Join("\n", textLayers.Select(l => l.CleanContent));
        var allRaw = string.Join("\n", textLayers.Select(l => l.RawContent));
        foreach (var e in RuleStore.Data.Commands)
        {
            var rx = new Regex(e.Pattern, RegexOptions.IgnoreCase);
            int n = Math.Max(rx.Matches(allClean).Count, rx.Matches(allRaw).Count);
            if (n == 0) continue;
            r.Commands.Add(new CommandExplanation { Name = e.Name, Kind = e.Kind, Description = e.Description, Count = n, Suspicious = e.Suspicious });
        }
        r.Commands.Sort((a, b) => a.Suspicious != b.Suspicious ? (a.Suspicious ? -1 : 1) : b.Count.CompareTo(a.Count));

        // ---------- 위험도 ----------
        int score = r.Findings.Sum(f => Weight[f.Severity]);
        score += Math.Min(15, (r.AllLayers.Max(l => l.Depth)) * 3);
        score += Math.Min(10, r.Iocs.Count(i => i.Type is "URL" or "도메인" or "IP" && !i.Benign) * 2);
        r.RiskScore = Math.Min(100, score);
        r.RiskLevel = r.RiskScore switch
        {
            >= 75 => "매우 위험",
            >= 50 => "위험",
            >= 25 => "주의",
            > 0 => "낮음",
            _ => "탐지 없음"
        };

        Classify(r, found);
        Summarize(r, found);
    }

    static int TacticOrder(string t) => t switch
    {
        "Execution" => 1, "Persistence" => 2, "Privilege Escalation" => 3, "Defense Evasion" => 4, "Credential Access" => 5,
        "Discovery" => 6, "Collection" => 7, "Command and Control" => 8, "Exfiltration" => 9, "Impact" => 10, _ => 11
    };

    static string LineAround(string text, int index)
    {
        int s = text.LastIndexOf('\n', Math.Max(0, index - 1)) + 1;
        int e = text.IndexOf('\n', index);
        if (e < 0) e = text.Length;
        var line = text.Substring(s, e - s).Trim();
        if (line.Length > 220)
        {
            int rel = index - s;
            int from = Math.Max(0, Math.Min(line.Length - 220, rel - 80));
            line = (from > 0 ? "…" : "") + line.Substring(from, Math.Min(220, line.Length - from)) + "…";
        }
        return line;
    }

    static void DetectObfuscation(AnalysisResult r)
    {
        var t = r.ObfuscationTechniques;
        foreach (var l in r.AllLayers.Skip(1))
        {
            var m = l.Method;
            string label = m switch
            {
                _ when m.Contains("EncodedCommand") => "Base64(UTF-16LE) -EncodedCommand",
                _ when m.Contains("-Command") || m.Contains("명령줄") => "명령줄 인자 래핑",
                _ when m.Contains("Invoke-Expression") => "Invoke-Expression 동적 실행",
                _ when m.Contains("ScriptBlock") => "ScriptBlock 동적 생성",
                _ when m.Contains("파일 쓰기") => "디스크 드롭 후 재실행 (다단계)",
                _ when m.Contains("-File") => "디스크 드롭 후 재실행 (다단계)",
                _ when m.Contains("압축") || m.Contains("GZip") || m.Contains("Deflate") => "압축(Deflate/GZip)",
                _ when m.Contains("SecureString") => "SecureString(AES) 암호화",
                _ when m.Contains("Base64") || m.Contains("GetString") => "Base64 인코딩",
                _ when m.Contains("PE") || l.IsBinary => "내장 바이너리 페이로드",
                _ => null
            };
            if (label != null && !t.Contains(label)) t.Add(label);
        }
        var raw = string.Join("\n", r.AllLayers.Where(l => !l.IsBinary).Select(l => l.RawContent));
        void Add(bool cond, string label) { if (cond && !t.Contains(label)) t.Add(label); }
        Add(Regex.Matches(raw, @"'\s*\+\s*'").Count >= 8, "문자열 분할·결합 ('ne'+'w-ob'+'ject')");
        Add(Regex.IsMatch(raw, @"[A-Za-z]`[A-Za-z]"), "백틱(`) 이스케이프 삽입");
        Add(Regex.Matches(raw, @"\b[a-z][A-Z][A-Za-z]|[a-z][A-Z]{2,}[a-z]|[a-z]{2}[A-Z]{2}\b").Count >= 3, "대소문자 무작위화");
        Add(Regex.IsMatch(raw, @"[.&]\s*\(\s*'[^']*'\s*\+"), "문자열로 조립한 명령 호출 (&('ne'+'w-object'))");
        Add(Regex.IsMatch(raw, @"\[char\]\s*\d+", RegexOptions.IgnoreCase), "[char] 코드 변환");
        Add(Regex.IsMatch(raw, @"-f\s*'|""\s*-f\s", RegexOptions.IgnoreCase) && Regex.IsMatch(raw, @"\{\d+\}\{\d+\}"), "포맷 연산자 재배열 (-f)");
        Add(Regex.IsMatch(raw, @"-bxor", RegexOptions.IgnoreCase), "XOR 암호화");
        Add(Regex.IsMatch(raw, @"\$\w+\[\$\w+\]\s*-\s*\$\w+\s*\+\s*256", RegexOptions.IgnoreCase), "바이트 시프트(카이사르) 암호화");
        Add(Regex.IsMatch(raw, @"\.replace\(|-replace", RegexOptions.IgnoreCase) && Regex.Matches(raw, @"\.replace\(|-replace", RegexOptions.IgnoreCase).Count >= 2, "문자열 치환으로 쓰레기 문자 제거");
        Add(Regex.IsMatch(raw, @"\$env:\w+\s*\+\s*\$env:", RegexOptions.IgnoreCase), "환경 변수 분할 저장");
        Add(Regex.IsMatch(raw, @"while\s*\(\s*\$true\s*\)\s*\{\s*switch\s*\(", RegexOptions.IgnoreCase), "제어 흐름 평탄화 (switch 상태 머신)");
        Add(Regex.IsMatch(raw, @"\$(ShellId|PSHome|env:ComSpec|VerbosePreference)\b[^;\r\n]{0,30}\[\d+\]", RegexOptions.IgnoreCase), "자동 변수 문자 조합 ($ShellId[1]+$ShellId[13]+'x' = iex)");
        Add(Regex.IsMatch(raw, @"\[char\[\]\]\s*\$\w+\s*-join|-join\s*\(?\s*\[char\[\]\]", RegexOptions.IgnoreCase), "문자 코드 배열 → 문자열 조합");
        Add(r.AllLayers.Any(l => l.ObservedStrings.Any(s => s.Contains("//:"))), "역순 문자열 (URL 뒤집기)");
        Add(Regex.IsMatch(raw, @"\$\w+\s*=\s*\(\s*'[A-Za-z0-9_]{4,12}'\s*(\+\s*'[A-Za-z0-9_]{1,12}'\s*)*\)\s*;"), "의미 없는 더미 변수 삽입");
    }

    static void Classify(AnalysisResult r, Dictionary<string, BehaviorFinding> f)
    {
        var labels = new List<string>();
        if (f.ContainsKey("MIN")) labels.Add("크립토마이너 (Cryptojacking)");
        if (f.ContainsKey("RAN")) labels.Add("랜섬웨어 의심");
        if (f.ContainsKey("CRD") || f.ContainsKey("KEY")) labels.Add("정보 탈취형 (Infostealer)");
        if (f.ContainsKey("SOC")) labels.Add("원격 제어 (RAT/백도어)");
        if (f.ContainsKey("REF") || f.ContainsKey("INJ")) labels.Add("파일리스 로더");
        bool dl = f.ContainsKey("DLF") || f.ContainsKey("DLS") || f.ContainsKey("IWR") || f.ContainsKey("BIT");
        if (dl && (f.ContainsKey("IVI") || f.ContainsKey("EXF") || f.ContainsKey("SPR") || f.ContainsKey("IEX") || f.ContainsKey("WSH") || f.ContainsKey("SBC")))
            labels.Add("다운로더 / 드로퍼");
        else if (dl) labels.Add("다운로더");
        if (labels.Count == 0 && (f.ContainsKey("WRT") && f.ContainsKey("CPS"))) labels.Add("다단계 드로퍼");
        if (labels.Count == 0 && r.Findings.Any(x => x.Severity >= Severity.High)) labels.Add("악성 의심 스크립트");
        if (labels.Count == 0) labels.Add(r.Findings.Count > 0 ? "의심 요소 있음" : "특이사항 없음");
        r.Classification = string.Join(" + ", labels);
    }

    static void Summarize(AnalysisResult r, Dictionary<string, BehaviorFinding> f)
    {
        var s = r.SummaryLines;
        int depth = r.AllLayers.Max(l => l.Depth);
        var tech = r.ObfuscationTechniques;
        if (depth > 0)
            s.Add($"총 {depth}단계({r.AllLayers.Count - 1}개 레이어)의 난독화를 정적으로 해제했습니다. 사용된 기법: {string.Join(", ", tech.Take(7))}.");
        else
            s.Add("추가로 해제할 난독화 레이어를 찾지 못했습니다. 원본 스크립트를 정리(상수 접기·포맷)한 결과를 기준으로 분석했습니다.");

        s.Add($"이 스크립트는 '{r.Classification}' 유형으로 판단되며, 위험도는 {r.RiskScore}/100 ({r.RiskLevel}) 입니다.");

        var urls = r.Iocs.Where(i => i.Type == "URL" && !i.Value.StartsWith("stratum", StringComparison.OrdinalIgnoreCase)).ToList();
        var domains = r.Iocs.Where(i => i.Type == "도메인" && !i.Benign).Select(i => i.Value).ToList();

        // 실행 흐름 서술
        var flow = new List<string>();
        if (f.ContainsKey("HID") || f.ContainsKey("EPB")) flow.Add("숨김 창·실행 정책 우회 옵션으로 PowerShell 을 몰래 실행");
        if (f.ContainsKey("SLP")) flow.Add("일정 시간 대기(샌드박스 회피)");
        if (f.ContainsKey("VMD")) flow.Add("가상머신/샌드박스 환경인지 확인하여 분석 환경이면 종료");
        if (f.ContainsKey("NET")) flow.Add("네트워크 설정(IP/Winsock) 초기화");
        if (f.ContainsKey("CLR")) flow.Add("명령 기록 삭제로 흔적 은폐");
        if (f.ContainsKey("GPU")) flow.Add("그래픽카드(GPU) 정보 수집");
        if (f.ContainsKey("TLS")) flow.Add("TLS 프로토콜 설정");
        if (urls.Count > 0 && (f.ContainsKey("DLF") || f.ContainsKey("DLS") || f.ContainsKey("IWR")))
            flow.Add($"{urls.Count}개 URL 에서 페이로드 다운로드" + (urls.Count >= 3 ? " (차단 대비 순차 시도)" : ""));
        if (f.ContainsKey("ARC")) flow.Add("내려받은 압축 파일 해제");
        if (f.ContainsKey("WRT")) flow.Add("다음 단계 스크립트를 디스크에 기록");
        if (f.ContainsKey("MAS")) flow.Add("정상 프로그램 이름/경로로 위장");
        if (f.ContainsKey("REF")) flow.Add(".NET 어셈블리를 메모리에 직접 로드 (파일리스)");
        if (f.ContainsKey("INJ")) flow.Add("메모리에 쉘코드 주입·실행");
        if (f.ContainsKey("IVI") || f.ContainsKey("EXF") || f.ContainsKey("SPR") || f.ContainsKey("WSH") || f.ContainsKey("CPS")) flow.Add("드롭한 파일/스크립트 실행");
        if (f.ContainsKey("RUN") || f.ContainsKey("SCH") || f.ContainsKey("STU") || f.ContainsKey("WMI")) flow.Add("재부팅 후에도 실행되도록 자동 실행 등록 (지속성)");
        if (f.ContainsKey("MIN")) flow.Add("채굴 풀에 접속해 암호화폐 채굴");
        if (f.ContainsKey("CRD")) flow.Add("자격 증명/브라우저 데이터 탈취");
        if (f.ContainsKey("UPL")) flow.Add("데이터 외부 전송");
        if (flow.Count > 0) s.Add("실행 흐름: " + string.Join(" → ", flow) + ".");

        if (domains.Count > 0)
            s.Add($"주요 네트워크 지표: 도메인 {domains.Count}개 ({string.Join(", ", domains.Take(6).Select(Defang))}{(domains.Count > 6 ? " 외" : "")}).");
        var pool = r.Iocs.FirstOrDefault(i => i.Type == "채굴 풀");
        if (pool != null) s.Add($"채굴 풀 주소: {pool.Defanged}" + (r.Iocs.FirstOrDefault(i => i.Type == "지갑/계정") is { } w ? $", 지갑/계정: {Shorten(w.Value, 24)}" : ""));
        var reg = r.Iocs.Where(i => i.Type == "레지스트리").Select(i => i.Value).Take(2).ToList();
        if (reg.Count > 0) s.Add("변경 레지스트리: " + string.Join(", ", reg));
        var paths = r.Iocs.Where(i => i.Type == "파일 경로").Select(i => i.Value).Take(4).ToList();
        if (paths.Count > 0) s.Add("관련 파일 경로: " + string.Join(", ", paths));
        if (f.ContainsKey("ENV"))
            s.Add("※ 핵심 페이로드가 환경 변수(예: $env:P1~P7)에 분산 저장되어 이 스크립트만으로는 복원할 수 없습니다. 실행 당시 프로세스 환경 변수나 부모 프로세스(배치/LNK) 를 함께 수집해야 합니다.");
        if (r.AllLayers.Any(l => l.IsBinary))
            s.Add("※ 내장된 바이너리 페이로드가 발견되었습니다. '레이어' 목록에서 해시를 확인하고 필요 시 격리 환경에서 별도 분석하세요.");

        // 권고
        var rec = new List<string>();
        if (domains.Count > 0 || urls.Count > 0) rec.Add("IOC 탭의 도메인/URL 을 방화벽·프록시에서 차단");
        if (paths.Count > 0) rec.Add("관련 경로의 파일 존재 여부 확인 및 삭제");
        if (reg.Count > 0 || f.ContainsKey("SCH")) rec.Add("자동 실행 등록(Run 키/예약 작업) 점검·제거");
        if (f.ContainsKey("MIN")) rec.Add("CPU/GPU 사용률 이상 여부와 채굴 프로세스 확인");
        if (f.ContainsKey("CRD")) rec.Add("저장된 비밀번호·세션 즉시 변경");
        if (rec.Count == 0 && r.Findings.Count > 0) rec.Add("스크립트 출처 확인 후 실행 차단");
        if (rec.Count > 0) s.Add("권장 조치: " + string.Join(" / ", rec) + ".");
    }

    static string Shorten(string s, int n) => s.Length <= n ? s : s[..n] + "…";
    public static string Defang(string s) => s.Replace("http", "hxxp", StringComparison.OrdinalIgnoreCase).Replace(".", "[.]");
}
