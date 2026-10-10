using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

public static class IocExtractor
{
    const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.Compiled;

    // PowerShell 은 “ ” ‘ ’ 도 따옴표로 취급하므로 값의 끝으로 본다
    static readonly Regex UrlRx = new(@"\b(?:https?|ftp|stratum\+(?:tcp|ssl|tls))://[^\s'""“”‘’<>`\)\]\}\|,;*\\^]+", O);
    static readonly Regex IpRx = new(@"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?(?![\d.])", O);
    static readonly Regex DomainRx = new(@"(?<![\w.@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?![\w-]|\.[a-z0-9])", O);
    static readonly Regex EmailRx = new(@"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b", O);
    static readonly Regex RegRx = new(@"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS))(?::)?\\[^'""\r\n;)|]+", O);
    static readonly Regex PathRx = new(@"(?:\b[a-z]:\\|%[a-z_]+%\\|\$env:[a-z_]+\\|\$\{env:[a-z_]+\}\\)[^\s'""“”‘’<>|\r\n;)*?,]*", O);
    static readonly Regex FileRx = new(@"(?<![\w.-])[\w\-]{1,64}\.(?:exe|dll|ps1|psm1|vbs|vbe|js|jse|hta|bat|cmd|scr|lnk|msi|jar|zip|rar|7z|iso|lock|sys)\b", O);
    static readonly Regex WalletUserRx = new(@"--user\s+([A-Za-z0-9._-]{25,})", O);
    static readonly Regex EthRx = new(@"\b0x[a-f0-9]{40}\b", O);
    static readonly Regex XmrRx = new(@"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", RegexOptions.Compiled);
    static readonly Regex Sha256Rx = new(@"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", O);

    static readonly HashSet<string> Tlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "com","net","org","info","biz","io","co","me","ru","cn","kz","kr","jp","de","uk","fr","it","nl","pl","br","in","us","ca","au",
        "es","se","no","fi","ch","at","be","cz","ua","by","tr","ir","vn","th","id","my","sg","hk","tw","mx","ar","cl","za","ng","eg",
        "xyz","top","online","site","club","store","shop","live","app","dev","link","click","space","website","tech","pw","cc","tk",
        "ml","ga","cf","gq","su","ws","network","cloud","fun","icu","buzz","rest","bar","work","today","world","life","pro","name",
        "mobi","tv","asia","eu","lt","lv","ee","ro","bg","hu","gr","pt","sk","si","hr","rs","ge","am","az","uz","kg","md","is","ie",
        "nz","ph","pk","bd","lk","sa","ae","il","to","vip","win","bid","download","racing","party","review","trade","date","stream",
        "gdn","loan","men","host","press","digital","email","run","page","cyou","sbs","lol","monster","quest",
    };

    /// <summary>파일 확장자/코드 식별자와 겹쳐 단독 도메인으로는 신뢰하기 어려운 TLD (URL 안에서는 허용)</summary>
    static readonly HashSet<string> AmbiguousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "md","sh","py","pl","rs","cs","cc","ws","run","app","dev","name","date","host","page","link","zip","mov","to","is","in","me","id","am","at","be","do","it","no","so","us",
    };

    static readonly HashSet<string> SystemBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","rundll32.exe","mshta.exe","regsvr32.exe","msiexec.exe",
        "schtasks.exe","certutil.exe","bitsadmin.exe","reg.exe","netsh.exe","ipconfig.exe","conhost.exe","explorer.exe",
    };

    static readonly HashSet<string> NotDomainFirstLabel = new(StringComparer.OrdinalIgnoreCase)
    {
        "system","net","io","text","security","reflection","management","runtime","collections","win32","diagnostics","microsoft.powershell",
        "threading","componentmodel","windows","globalization","data","xml","web","convert","string","environment",
    };

    static readonly string[] BenignDomains =
    {
        "microsoft.com","windows.com","windowsupdate.com","office.com","live.com","google.com","googleapis.com","gstatic.com","w3.org",
        "github.com","githubusercontent.com","mozilla.org","apple.com","amazonaws.com","azure.com","digicert.com","verisign.com",
        "any.run","hybrid-analysis.com","virustotal.com",
    };

    static readonly string[] AbusableServices = { "github.com", "githubusercontent.com", "pastebin.com", "discord.com", "discordapp.com", "transfer.sh", "dropbox.com", "drive.google.com", "telegram.org" };

    public static void Extract(AnalysisResult r)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = r.Iocs;

        void Add(string type, string value, string ctx, int depth, string note = "")
        {
            value = value.Trim().TrimEnd('.', ',', ')', '\'', '"', '`', ':');
            if (value.Length < 4) return;
            // $env:TEMP\x 와 %TEMP%\x 는 같은 값으로 취급
            var norm = Regex.Replace(value, @"\$\{?env:(\w+)\}?", m => "%" + m.Groups[1].Value + "%", RegexOptions.IgnoreCase);
            if (!seen.Add(type + "|" + norm)) return;
            var ioc = new Ioc { Type = type, Value = value, Context = ctx, LayerDepth = depth, Note = note };
            ioc.Defanged = type switch
            {
                "URL" or "채굴 풀" => DefangUrl(value),
                "도메인" or "IP" or "이메일" => value.Replace(".", "[.]").Replace("@", "[@]"),
                _ => value
            };
            if (type is "도메인" or "URL")
            {
                var host = type == "URL" ? HostOf(value) : value;
                if (BenignDomains.Any(b => host.Equals(b, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + b, StringComparison.OrdinalIgnoreCase)))
                {
                    ioc.Benign = !AbusableServices.Any(a => host.EndsWith(a, StringComparison.OrdinalIgnoreCase));
                    ioc.Note = ioc.Benign ? "정상 도메인" : "정상 서비스 (악용 가능)";
                }
            }
            list.Add(ioc);
        }

        // 깊은 레이어부터 (복호화된 결과가 가장 의미 있음)
        foreach (var layer in r.AllLayers.OrderByDescending(l => l.Depth))
        {
            var texts = new List<string>();
            if (layer.IsBinary)
            {
                if (layer.Bytes != null) texts.Add(string.Join("\n", Deobfuscator.ExtractStrings(layer.Bytes, 6).Take(4000)));
            }
            else
            {
                // 정리본(상수 접기 결과)만 사용: 원시본의 'C:\Users\Pub'+'lic' 같은 조각 오탐 방지
                texts.Add(string.IsNullOrEmpty(layer.CleanContent) ? layer.RawContent ?? "" : layer.CleanContent);
            }

            foreach (var text in texts)
            {
                if (string.IsNullOrEmpty(text)) continue;
                // EncodedCommand 원본 같은 거대 Base64 는 IOC 추출에서 제외 (오탐 방지)
                foreach (Match m in UrlRx.Matches(text))
                {
                    var u = m.Value.TrimEnd('.', ')', '\'');
                    var host = HostOf(u);
                    if (host.Length < 3) continue;
                    bool pool = u.StartsWith("stratum", StringComparison.OrdinalIgnoreCase);
                    Add(pool ? "채굴 풀" : "URL", u, Ctx(text, m.Index), layer.Depth);
                    if (IpRx.IsMatch(host)) Add("IP", host, Ctx(text, m.Index), layer.Depth);
                    else Add("도메인", host.ToLowerInvariant(), Ctx(text, m.Index), layer.Depth);
                }
                foreach (Match m in DomainRx.Matches(text))
                {
                    var d = m.Value.ToLowerInvariant();
                    var tld = m.Groups[1].Value;
                    if (!Tlds.Contains(tld)) continue;
                    // 코드의 멤버 접근(sh.Run, $x.Name.Length)이나 파일명(readme.md)과 겹치는 경우 제외
                    if (tld.Any(char.IsUpper) && m.Value.Any(char.IsLower)) continue;
                    if (AmbiguousTlds.Contains(tld)) continue;
                    var first = d.Split('.')[0];
                    if (NotDomainFirstLabel.Contains(first)) continue;
                    if (d.Length > 80) continue;
                    // 파일명 (svchost.exe 등) 은 TLD 목록에 없으므로 자동 제외
                    if (m.Index > 0 && text[m.Index - 1] == '[') continue;
                    Add("도메인", d, Ctx(text, m.Index), layer.Depth);
                }
                foreach (Match m in IpRx.Matches(text))
                {
                    var ip = m.Value;
                    if (ip.StartsWith("0.") || ip.StartsWith("255.") || ip.StartsWith("1.0.0") || ip.StartsWith("2.0.0")) continue;
                    if (Regex.IsMatch(text.Substring(Math.Max(0, m.Index - 2), Math.Min(2, m.Index)), @"[vV]\s?$")) continue;
                    Add("IP", ip, Ctx(text, m.Index), layer.Depth);
                }
                foreach (Match m in EmailRx.Matches(text)) Add("이메일", m.Value, Ctx(text, m.Index), layer.Depth);
                foreach (Match m in RegRx.Matches(text)) Add("레지스트리", m.Value.TrimEnd(), Ctx(text, m.Index), layer.Depth);
                foreach (Match m in PathRx.Matches(text))
                {
                    var p = m.Value.TrimEnd('\\', ' ', '.');
                    if (p.Length < 8) continue;
                    if (p.Contains("WindowsPowerShell\\v1.0", StringComparison.OrdinalIgnoreCase)) continue;
                    Add("파일 경로", p, Ctx(text, m.Index), layer.Depth);
                }
                foreach (Match m in FileRx.Matches(text))
                {
                    var fn = m.Value;
                    if (SystemBinaries.Contains(fn)) continue;
                    Add("파일명", fn, Ctx(text, m.Index), layer.Depth);
                }
                foreach (Match m in WalletUserRx.Matches(text)) Add("지갑/계정", m.Groups[1].Value, Ctx(text, m.Index), layer.Depth, "채굴 보상 수령 지갑/계정");
                foreach (Match m in EthRx.Matches(text)) Add("지갑/계정", m.Value, Ctx(text, m.Index), layer.Depth, "Ethereum 주소 형식");
                foreach (Match m in XmrRx.Matches(text)) Add("지갑/계정", m.Value, Ctx(text, m.Index), layer.Depth, "Monero 주소 형식");
                if (layer.Depth > 0)
                    foreach (Match m in Sha256Rx.Matches(text)) Add("해시(SHA256)", m.Value.ToLowerInvariant(), Ctx(text, m.Index), layer.Depth);
            }
        }

        // 런타임에 계산된 문자열 + Base64/역순으로 숨긴 URL
        foreach (var layer in r.AllLayers.OrderByDescending(l => l.Depth))
        {
            var pool = new List<(string text, string how)>();
            foreach (var s in layer.ObservedStrings) pool.Add((s, "실행 중 계산된 값"));
            if (!layer.IsBinary)
                foreach (Match m in B64Token.Matches(layer.CleanContent ?? "")) pool.Add((m.Value, "Base64 문자열"));
            foreach (var (text, how) in pool)
            {
                foreach (var (hidden, note) in Reveal(text, how))
                {
                    foreach (Match m in UrlRx.Matches(hidden))
                    {
                        var u = m.Value.TrimEnd('.', ')', '\'');
                        var host = HostOf(u);
                        if (host.Length < 4 || !host.Contains('.')) continue;
                        bool isPool = u.StartsWith("stratum", StringComparison.OrdinalIgnoreCase);
                        Add(isPool ? "채굴 풀" : "URL", u, Ctx(hidden, m.Index), layer.Depth, note);
                        if (IpRx.IsMatch(host)) Add("IP", host, u, layer.Depth, note);
                        else Add("도메인", host.ToLowerInvariant(), u, layer.Depth, note);
                    }
                    if (how == "실행 중 계산된 값")
                    {
                        foreach (Match m in PathRx.Matches(hidden))
                        {
                            var p = m.Value.TrimEnd('\\', ' ', '.');
                            if (p.Length >= 8) Add("파일 경로", p, Ctx(hidden, m.Index), layer.Depth, note);
                        }
                    }
                }
            }
        }

        // 다른 경로의 접두어일 뿐인 경로 조각 제거 (예: C:\Users\Pub)
        var paths = list.Where(i => i.Type == "파일 경로").ToList();
        foreach (var p in paths)
            if (paths.Any(o => o != p && o.Value.Length > p.Value.Length && o.Value.StartsWith(p.Value, StringComparison.OrdinalIgnoreCase)))
                list.Remove(p);

        // 바이너리 레이어 해시
        foreach (var l in r.AllLayers.Where(l => l.IsBinary && l.Bytes != null))
        {
            var h = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(l.Bytes)).ToLowerInvariant();
            Add("해시(SHA256)", h, "추출된 바이너리 페이로드", l.Depth, "내장 페이로드");
        }

        var order = new[] { "URL", "도메인", "IP", "채굴 풀", "지갑/계정", "레지스트리", "파일 경로", "파일명", "이메일", "해시(SHA256)" };
        var sorted = list.OrderBy(i => Array.IndexOf(order, i.Type)).ThenBy(i => i.Benign).ToList();
        list.Clear();
        list.AddRange(sorted);
    }

    static readonly Regex B64Token = new(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.Compiled);

    /// <summary>문자열에서 Base64 디코딩 / 역순 뒤집기로 숨긴 내용을 드러낸다.</summary>
    static IEnumerable<(string text, string note)> Reveal(string s, string how)
    {
        yield return (s, how);
        if (s.Contains("//:")) yield return (Reverse(s), how + " (역순 문자열 복원)");
        foreach (Match m in B64Token.Matches(s))
        {
            var tok = m.Value;
            if (tok.Length % 4 == 1) continue;
            string dec;
            try
            {
                var pad = tok.Length % 4 == 0 ? tok : tok + new string('=', 4 - tok.Length % 4);
                var bytes = Convert.FromBase64String(pad);
                dec = bytes.Length > 2 && bytes[1] == 0 ? System.Text.Encoding.Unicode.GetString(bytes) : System.Text.Encoding.UTF8.GetString(bytes);
            }
            catch { continue; }
            if (CommandLineUnwrapper.Printable(dec) < 0.95) continue;
            yield return (dec, "Base64 디코딩으로 복원");
            if (dec.Contains("//:")) yield return (Reverse(dec), "Base64 + 역순 문자열에서 복원");
        }
    }

    static string Reverse(string s)
    {
        var a = s.ToCharArray();
        Array.Reverse(a);
        return new string(a);
    }

    static string Ctx(string text, int index)
    {
        int s = text.LastIndexOf('\n', Math.Max(0, index - 1)) + 1;
        int e = text.IndexOf('\n', index);
        if (e < 0) e = text.Length;
        var line = text.Substring(s, e - s).Trim();
        if (line.Length > 160)
        {
            int rel = index - s;
            int from = Math.Max(0, Math.Min(line.Length - 160, rel - 60));
            line = (from > 0 ? "…" : "") + line.Substring(from, Math.Min(160, line.Length - from)) + "…";
        }
        return line;
    }

    public static string HostOf(string url)
    {
        var i = url.IndexOf("://", StringComparison.Ordinal);
        var rest = i >= 0 ? url[(i + 3)..] : url;
        var end = rest.IndexOfAny(new[] { '/', '?', '#' });
        if (end >= 0) rest = rest[..end];
        var at = rest.LastIndexOf('@');
        if (at >= 0) rest = rest[(at + 1)..];
        var colon = rest.LastIndexOf(':');
        if (colon >= 0) rest = rest[..colon];
        return rest;
    }

    public static string DefangUrl(string u)
    {
        var host = HostOf(u);
        var res = Regex.Replace(u, @"^http", "hxxp", RegexOptions.IgnoreCase);
        res = res.Replace("://", "[://]");
        if (host.Length > 0) res = res.Replace(host, host.Replace(".", "[.]"));
        return res;
    }
}
