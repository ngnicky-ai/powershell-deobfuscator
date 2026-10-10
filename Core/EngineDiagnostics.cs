using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

/// <summary>
/// 엔진이 처리하지 못한 항목을 분류하고, 레이어 해독이 덜 된 정황을 찾아낸다.
/// "다음에 엔진/규칙의 무엇을 고쳐야 하는가"를 알려 주는 피드백 루프의 출발점.
/// </summary>
public static class EngineDiagnostics
{
    // 실제 시스템 상태·외부 자원에 의존하므로 정적 분석기가 의도적으로 실행하지 않는 cmdlet
    static readonly HashSet<string> EnvironmentCmdlets = new(StringComparer.OrdinalIgnoreCase)
    {
        "Get-CimInstance","gcim","Get-WmiObject","gwmi","Invoke-WmiMethod","Invoke-CimMethod","Set-WmiInstance","Register-WmiEvent",
        "Test-Path","Get-Process","gps","ps","Stop-Process","kill","spps","Wait-Process","Get-Service","Start-Service","Stop-Service",
        "New-Service","Set-Service","Get-ItemProperty","gp","Set-ItemProperty","sp","New-ItemProperty","Remove-ItemProperty",
        "Remove-Item","rm","del","ri","erase","rd","Copy-Item","cp","copy","cpi","Move-Item","mv","move","mi","Rename-Item",
        "Expand-Archive","Compress-Archive","Invoke-WebRequest","iwr","curl","wget","Invoke-RestMethod","irm","Start-BitsTransfer",
        "Register-ScheduledTask","New-ScheduledTaskAction","New-ScheduledTaskTrigger","Unregister-ScheduledTask","Set-MpPreference",
        "Add-MpPreference","Get-MpPreference","Get-MpComputerStatus","Clear-History","Clear-EventLog","Get-Date","Get-Random","Get-Host",
        "Get-Culture","Get-Location","Set-Location","cd","sl","Get-ComputerInfo","Add-Type","Import-Module","ipmo","Unblock-File",
        "Get-Acl","Set-Acl","Restart-Computer","Stop-Computer","Get-NetIPAddress","Get-NetAdapter","Get-Clipboard","Set-Clipboard",
        "Send-MailMessage","Get-FileHash","Get-LocalUser","New-LocalUser","Add-LocalGroupMember","Enable-PSRemoting","Get-PSDrive",
        "Set-ExecutionPolicy","Get-ExecutionPolicy","Get-History","Out-GridView","Read-Host","Get-Credential","Invoke-Item","ii",
    };

    static readonly string[] ExternalPrograms =
    {
        "ipconfig","netsh","cmd","reg","schtasks","wscript","cscript","mshta","rundll32","regsvr32","msiexec","certutil","bitsadmin",
        "vssadmin","wbadmin","bcdedit","wevtutil","taskkill","tasklist","whoami","systeminfo","net","net1","sc","attrib","icacls",
        "takeown","timeout","ping","nslookup","curl.exe","explorer","notepad","conhost","wmic","msbuild","installutil","regasm",
    };

    // 시스템 상태·네트워크·리플렉션 계열 .NET 형식 (정적으로 흉내 내지 않음)
    static readonly string[] EnvironmentTypePrefixes =
    {
        "net.", "diagnostics.", "management.automation", "microsoft.win32", "environment", "io.directory", "io.driveinfo",
        "io.fileinfo", "threading", "windows.", "appdomain", "activator", "gc", "security.principal", "runtime.interopservices",
        "reflection.", "ref", "net.sockets", "web.", "xml.", "datetime", "guid", "random", "io.file",
    };

    public static (GapKind kind, string detail) Classify(string message)
    {
        var m = message ?? "";
        string Arg(string prefix) => m.Length > prefix.Length ? m[prefix.Length..].Trim() : "";

        if (m.StartsWith("limit ") || m is "loop limit" or "string too large" or "array too large" or "range too large" or "recursion" or "string repeat")
            return (GapKind.Limit, m switch
            {
                "limit steps" => "평가 단계 한도 초과",
                "limit time" => "평가 시간 한도 초과",
                "loop limit" => "반복 횟수 한도 초과",
                "recursion" => "재귀 깊이 한도 초과",
                _ => "크기 한도 초과 (" + m + ")"
            });

        if (m.StartsWith("unknown value $")) return (GapKind.Cascade, "값을 모르는 변수 " + Arg("unknown value "));
        if (m.StartsWith("runtime ")) return (GapKind.Cascade, "런타임 오류 — " + Shorten(Arg("runtime "), 90));
        if (m is "method on null" or "index null" or "static on non-type" or "static call on non-type" or "not a number"
            || m.StartsWith("not a number") || m is "char cast" or "byte range" or "long")
            return (GapKind.Cascade, "입력 값 오류 (" + m + ")");

        if (m.StartsWith("command "))
        {
            var name = Arg("command ");
            var bare = System.IO.Path.GetFileNameWithoutExtension(name.ToLowerInvariant());
            if (EnvironmentCmdlets.Contains(name)) return (GapKind.Environment, "시스템/외부 cmdlet " + name);
            if (ExternalPrograms.Contains(bare) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return (GapKind.Environment, "외부 프로그램 " + name);
            if (name.Contains('\\') || name.Contains('/') || Regex.IsMatch(name, @"\.\w{2,4}$"))
                return (GapKind.Environment, "파일 직접 실행 " + name);
            if (Regex.IsMatch(name, @"^[A-Za-z]+-[A-Za-z]+$")) return (GapKind.NeedsEngine, "cmdlet " + name);
            return (GapKind.Environment, "스크립트 밖에 정의된 명령/함수 " + name);
        }
        if (m.StartsWith("stub method ")) return (GapKind.Environment, "네트워크/COM 객체 호출 " + Arg("stub method "));
        if (m.StartsWith("get-item ") || m == "get-content real file" || m.StartsWith("io.file ") || m.StartsWith("drive variable "))
            return (GapKind.Environment, "실제 파일·드라이브 접근 (" + m + ")");
        if (m == "DPAPI securestring") return (GapKind.Environment, "DPAPI SecureString (작성자 PC 의 키 필요)");
        if (m.StartsWith("blocked ") || m is "gettype" or "ast") return (GapKind.Environment, "의도적으로 차단한 리플렉션/시스템 호출 (" + m + ")");

        var st = Regex.Match(m, @"^static (?:call|member) \[(.+?)\]::(.+)$");
        if (st.Success)
        {
            var type = st.Groups[1].Value;
            var detail = $"[{type}]::{st.Groups[2].Value}";
            return (IsEnvironmentType(type) ? GapKind.Environment : GapKind.NeedsEngine, ".NET 정적 " + detail);
        }
        var meth = Regex.Match(m, @"^method (.+) on (.+)$");
        if (meth.Success)
            return (meth.Groups[2].Value == nameof(StubObject) ? GapKind.Environment : GapKind.NeedsEngine,
                $".NET 메서드 {meth.Groups[2].Value}.{meth.Groups[1].Value}()");
        var mem = Regex.Match(m, @"^member (.+) on (.+)$");
        if (mem.Success)
        {
            var owner = mem.Groups[2].Value;
            if (owner == nameof(TypeRef)) return (GapKind.Environment, $"리플렉션 형식 멤버 .{mem.Groups[1].Value} (의도적 차단)");
            return (owner is nameof(StubObject) or nameof(ExecContextStub) ? GapKind.Environment : GapKind.NeedsEngine,
                $"속성 {owner}.{mem.Groups[1].Value}");
        }
        if (m.StartsWith("new-object "))
        {
            var t = Arg("new-object ");
            return (IsEnvironmentType(t) ? GapKind.Environment : GapKind.NeedsEngine, "New-Object " + t);
        }
        if (m.StartsWith("cast ")) return (GapKind.NeedsEngine, "형변환 [" + Arg("cast ") + "]");
        if (m.StartsWith("no method ") || m.StartsWith("no overload ")) return (GapKind.NeedsEngine, "메서드 오버로드 " + m);
        if (m.StartsWith("expr ") || m.StartsWith("unary ") || m.StartsWith("binary ") || m.StartsWith("assign ") || m.EndsWith("Ast"))
            return (GapKind.NeedsEngine, "문법 요소 " + m);
        return (GapKind.NeedsEngine, m);
    }

    static bool IsEnvironmentType(string type)
    {
        var t = type.Trim('[', ']').ToLowerInvariant();
        if (t.StartsWith("system.")) t = t[7..];
        return EnvironmentTypePrefixes.Any(p => t == p.TrimEnd('.') || t.StartsWith(p));
    }

    static string Shorten(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    static readonly Regex SinkRx = new(
        @"\b(?:Invoke-Expression|iex)\b|ScriptBlock\]::Create|InvokeScript|NewScriptBlock|Assembly\]::Load|\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static readonly Regex ExternalInputRx = new(
        @"Download(?:String|Data|File)|Invoke-(?:WebRequest|RestMethod)|\biwr\b|\birm\b|Get-Content|ReadAll(?:Text|Bytes|Lines)|\$env:\w+\s*\+\s*\$env:|GetEnvironmentVariable|Net\.Sockets|Read-Host|Get-Clipboard|GetResponse",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static readonly Regex B64Blob = new(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.Compiled);

    /// <summary>레이어별 미지원 항목을 합산하고, 해독 실패 정황을 판정한다.</summary>
    public static void Build(AnalysisResult r)
    {
        var merged = new Dictionary<string, EngineGap>();
        foreach (var l in r.AllLayers)
            foreach (var g in l.Gaps)
            {
                var key = (int)g.Kind + "|" + g.Detail;
                if (!merged.TryGetValue(key, out var m))
                    m = merged[key] = new EngineGap { Kind = g.Kind, Detail = g.Detail, Example = g.Example };
                m.Count += g.Count;
                m.Layers.Add(l.Depth);
            }
        r.Gaps.AddRange(merged.Values.OrderBy(g => g.Kind).ThenByDescending(g => g.Count));

        foreach (var l in r.AllLayers.Where(l => !l.IsBinary))
        {
            var text = string.IsNullOrEmpty(l.CleanContent) ? l.RawContent : l.CleanContent;
            if (string.IsNullOrEmpty(text)) continue;
            bool leaf = l.Children.Count == 0;
            bool external = ExternalInputRx.IsMatch(text);

            if (l.BudgetHit)
                r.Warnings.Add(new DecodeWarning
                {
                    LayerDepth = l.Depth, LayerTitle = l.Title, Suspicious = true,
                    Reason = "평가 한도(단계 수 또는 시간)에 도달해 일부만 해독되었을 수 있습니다. 반복문이 매우 크거나 엔진이 반복을 잘못 따라간 경우입니다."
                });

            if (leaf)
            {
                var sink = SinkRx.Match(text);
                if (sink.Success)
                {
                    r.Warnings.Add(new DecodeWarning
                    {
                        LayerDepth = l.Depth, LayerTitle = l.Title, Suspicious = !external,
                        Evidence = LineAt(text, sink.Index),
                        Reason = external
                            ? "실행 지점이 있지만 실행될 코드가 네트워크·파일·환경 변수 등 외부 입력에서 오므로 정적으로 복원할 수 없습니다."
                            : "실행 지점(iex/ScriptBlock/Load 등)이 있는데 실행될 내용을 계산하지 못했습니다. '엔진 확장 필요' 항목을 확인하세요."
                    });
                }
            }

            // 하위 레이어가 이미 나온 레이어의 Base64 조각은 정상 해독된 것이므로 보지 않는다
            if (!leaf) continue;
            foreach (Match b in B64Blob.Matches(text))
            {
                var dec = TryDecode(b.Value);
                if (dec == null) continue;
                // 이미 하위 레이어로 풀린 데이터면 생략
                if (Deobfuscator.DecodeBytes(dec, out _) is { } ok && (ok.Bytes != null || ok.Text != null)) continue;
                double ent = Deobfuscator.Entropy(dec);
                r.Warnings.Add(new DecodeWarning
                {
                    LayerDepth = l.Depth, LayerTitle = l.Title, Suspicious = ent < 7.2,
                    Evidence = Shorten(b.Value, 80),
                    Reason = ent >= 7.2
                        ? $"해석되지 않은 Base64 데이터 {b.Length:N0}자 (디코딩 엔트로피 {ent:F2}) — 암호화되어 있어 키 없이는 복원할 수 없는 것으로 보입니다."
                        : $"해석되지 않은 Base64 데이터 {b.Length:N0}자 (디코딩 엔트로피 {ent:F2}) — 지원하지 않는 인코딩/압축일 수 있습니다."
                });
                if (r.Warnings.Count > 40) break;
            }
        }
    }

    static byte[] TryDecode(string s)
    {
        try
        {
            if (s.Length % 4 == 1) return null;
            var pad = s.Length % 4 == 0 ? s : s + new string('=', 4 - s.Length % 4);
            return Convert.FromBase64String(pad);
        }
        catch { return null; }
    }

    static string LineAt(string text, int index)
    {
        int s = text.LastIndexOf('\n', Math.Max(0, index - 1)) + 1;
        int e = text.IndexOf('\n', index);
        if (e < 0) e = text.Length;
        return Shorten(text[s..e].Trim(), 200);
    }
}
