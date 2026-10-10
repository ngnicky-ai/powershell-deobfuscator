using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

/// <summary>레이어를 재귀적으로 벗겨내는 오케스트레이터.</summary>
public static class Deobfuscator
{
    const int MaxDepth = 15;
    const int MaxLayers = 80;

    sealed class Ctx
    {
        public HashSet<string> Seen { get; } = new();
        public int Count;
        public AnalysisResult Result;
    }

    public static AnalysisResult Analyze(string text, string fileName = "", string filePath = "", byte[] fileBytes = null)
    {
        // 깊게 중첩된 AST 를 다루기 위해 큰 스택을 가진 스레드에서 실행
        AnalysisResult res = null;
        Exception err = null;
        var th = new Thread(() =>
        {
            try { res = AnalyzeCore(text, fileName, filePath, fileBytes); }
            catch (Exception ex) { err = ex; }
        }, 512 * 1024 * 1024);
        th.Start();
        th.Join();
        if (err != null) throw new InvalidOperationException("분석 중 오류: " + err.Message, err);
        return res;
    }

    static AnalysisResult AnalyzeCore(string text, string fileName, string filePath, byte[] fileBytes)
    {
        var sw = Stopwatch.StartNew();
        text ??= "";
        text = text.TrimStart('﻿');
        var result = new AnalysisResult
        {
            File = BuildFileInfo(fileName, filePath, fileBytes ?? Encoding.UTF8.GetBytes(text))
        };
        var root = new Layer { Depth = 0, Title = "원본 입력", Method = "입력 파일", RawContent = text };
        result.Root = root;
        var ctx = new Ctx { Result = result };
        ctx.Seen.Add(Key(text));
        Process(root, ctx);

        Flatten(root, result.AllLayers);
        Analyzer.Analyze(result);
        EngineDiagnostics.Build(result);
        sw.Stop();
        result.Elapsed = sw.Elapsed;
        return result;
    }

    static void Flatten(Layer l, List<Layer> list)
    {
        list.Add(l);
        foreach (var c in l.Children) Flatten(c, list);
    }

    static string Key(string s) => Regex.Replace(s ?? "", @"\s+", "").ToLowerInvariant().GetHashCode().ToString() + ":" + (s?.Length ?? 0) / 50;

    static readonly string[] SinkWords = { "Invoke-Expression", "ScriptBlock", "파일 쓰기", "powershell", "InvokeScript", "NewScriptBlock", "Invoke-Command", "자식 프로세스", "Start-Process", "IO.File", "Assembly" };
    static bool IsSink(string kind) => SinkWords.Any(w => kind.Contains(w, StringComparison.OrdinalIgnoreCase));

    static void Process(Layer layer, Ctx ctx)
    {
        if (layer.IsBinary)
        {
            return;
        }
        try { layer.CleanContent = Beautifier.Clean(layer.RawContent); }
        catch { layer.CleanContent = layer.RawContent; }

        if (layer.Depth >= MaxDepth || ctx.Count >= MaxLayers) return;

        var candidates = new List<CapturedPayload>();

        // 1) 프로세스 명령줄 래퍼
        var cl = CommandLineUnwrapper.TryUnwrap(layer.RawContent);
        if (cl != null && !string.IsNullOrWhiteSpace(cl.Script))
        {
            candidates.Add(new CapturedPayload { Kind = cl.Method, Text = cl.Script });
        }
        else
        {
            // 2) 안전 인터프리터 (URL 한 줄 같은 데이터 파일은 스크립트로 평가하지 않음)
            if (!IsDataOnly(layer.RawContent))
            try
            {
                var ast = SafeEvaluator.Parse(layer.RawContent, out _, out _);
                var ev = new SafeEvaluator();
                var t = new Thread(() => ev.Run(ast), 256 * 1024 * 1024);
                t.Start();
                if (!t.Join(TimeSpan.FromSeconds(25)))
                {
                    // 시간 초과: 중단시키고 지금까지의 캡처만 사용
                    ev.Cancel = true;
                    t.Join(TimeSpan.FromSeconds(5));
                }
                candidates.AddRange(ev.Captures.ToList());
                layer.ObservedStrings.AddRange(ev.ObservedStrings.ToList());
                layer.Gaps.AddRange(ev.Gaps.Values.ToList());
                layer.BudgetHit = ev.BudgetHit;
            }
            catch { }

            // 3) 남아있는 Base64 덩어리 자동 디코딩 (인터프리터가 실행 지점을 찾지 못한 경우에만)
            if (!candidates.Any(c => IsSink(c.Kind)))
                candidates.AddRange(ScanBase64Blobs(layer.RawContent));
        }

        // 싱크(실행/저장 지점) 우선
        var ordered = candidates
            .Select((c, i) => (c, i))
            .OrderBy(x => IsSink(x.c.Kind) ? 0 : 1)
            .ThenBy(x => x.i)
            .Select(x => x.c)
            .ToList();

        var accepted = new List<CapturedPayload>();
        foreach (var c in ordered)
        {
            if (ctx.Count >= MaxLayers) break;
            if (c.Bytes != null)
            {
                var k = "b:" + Convert.ToHexString(SHA256.HashData(c.Bytes));
                if (!ctx.Seen.Add(k)) continue;
                accepted.Add(c);
                continue;
            }
            var text = c.Text?.Trim('\0', ' ', '\r', '\n', '\t');
            if (string.IsNullOrWhiteSpace(text)) continue;
            if (text == layer.RawContent.Trim()) continue;
            if (!ctx.Seen.Add(Key(text))) continue;
            // 이미 채택된 싱크와 거의 같은 디코딩 문자열은 생략
            if (!IsSink(c.Kind) && accepted.Any(a => a.Text != null && NearDuplicate(a.Text, text))) continue;
            // 상위 레이어 본문에 그대로 들어있는 짧은 문자열은 의미 없음
            if (text.Length < 400 && layer.RawContent.Contains(text, StringComparison.Ordinal)) continue;
            c.Text = text;
            accepted.Add(c);
        }

        foreach (var c in accepted)
        {
            ctx.Count++;
            var child = new Layer
            {
                Depth = layer.Depth + 1,
                Parent = layer,
                Method = c.Kind,
                Title = TitleFor(c),
            };
            if (c.Bytes != null)
            {
                child.IsBinary = true;
                child.Bytes = c.Bytes;
                child.BinaryInfo = DescribeBinary(c.Bytes);
                child.RawContent = child.BinaryInfo;
                child.CleanContent = child.BinaryInfo + "\r\n\r\n" + HexDump(c.Bytes, 1024);
            }
            else child.RawContent = c.Text;
            layer.Children.Add(child);
        }
        foreach (var child in layer.Children) Process(child, ctx);
    }

    /// <summary>공백 없는 한 덩어리(URL, Base64, 숫자 나열 등)는 코드가 아니라 데이터로 본다.</summary>
    static bool IsDataOnly(string text)
    {
        var t = text.Trim();
        return t.Length > 0 && !t.Any(char.IsWhiteSpace) && !t.Contains(';') && !t.Contains('(') && !t.Contains('$');
    }

    static bool NearDuplicate(string a, string b)
    {
        int min = Math.Min(a.Length, b.Length);
        if (min == 0) return false;
        if (Math.Abs(a.Length - b.Length) > Math.Max(64, min / 10)) return false;
        int p = 0;
        while (p < min && a[p] == b[p]) p++;
        return p >= Math.Min(300, min / 2);
    }

    static string TitleFor(CapturedPayload c)
    {
        var k = c.Kind;
        if (c.Bytes != null) return "바이너리 페이로드";
        if (k.Contains("EncodedCommand")) return "EncodedCommand 디코딩";
        if (k.Contains("Command") && k.Contains("추출")) return "명령줄 스크립트";
        if (k.Contains("Invoke-Expression")) return "iex 실행 코드";
        if (k.Contains("ScriptBlock")) return "ScriptBlock 동적 코드";
        if (k.Contains("파일 쓰기") || k.Contains("IO.File")) return "드롭된 스크립트 파일";
        if (k.Contains("-File")) return "-File 실행 스크립트";
        if (k.Contains("자식 프로세스") || k.Contains("Start-Process")) return "자식 PowerShell 명령";
        if (k.Contains("Base64")) return "Base64 자동 디코딩";
        if (k.Contains("GetString")) return "디코딩된 문자열";
        if (k.Contains("압축")) return "압축 해제 결과";
        if (k.Contains("SecureString")) return "SecureString 복호화";
        return "추출된 코드";
    }

    static readonly Regex B64Blob = new(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.Compiled);

    public static IEnumerable<CapturedPayload> ScanBase64Blobs(string text)
    {
        var list = new List<CapturedPayload>();
        foreach (Match m in B64Blob.Matches(text))
        {
            var s = m.Value;
            if (s.Length % 4 == 1) continue;
            byte[] bytes;
            try
            {
                var pad = s.Length % 4 == 0 ? s : s + new string('=', 4 - s.Length % 4);
                bytes = Convert.FromBase64String(pad);
            }
            catch { continue; }

            var p = DecodeBytes(bytes, out var how);
            if (p != null && p.Text != null && !LooksMeaningful(p.Text)) p = null;
            if (p != null)
            {
                p.Kind = "Base64 자동 디코딩 (" + how + ")";
                list.Add(p);
            }
            if (list.Count > 10) break;
        }
        return list;
    }

    /// <summary>숫자 나열 같은 조각이 아닌, 사람이 읽을 의미 있는 텍스트인지.</summary>
    static bool LooksMeaningful(string s)
    {
        if (s.Length < 16) return false;
        int letters = s.Count(char.IsLetter);
        if (letters < s.Length * 0.3) return false;
        // 스크립트/URL/경로 단서가 하나라도 있어야 함
        return Regex.IsMatch(s, @"[\$;=\(\)\{\}]|https?://|\\|\b(function|param|New-Object|Invoke|Write|Start|Get-|Set-)\b", RegexOptions.IgnoreCase);
    }

    /// <summary>바이트 배열을 텍스트/압축/PE 로 판별해 해석한다.</summary>
    public static CapturedPayload DecodeBytes(byte[] bytes, out string how)
    {
        how = "";
        if (bytes.Length >= 2 && bytes[0] == 'M' && bytes[1] == 'Z')
        {
            how = "PE 실행 파일";
            return new CapturedPayload { Bytes = bytes };
        }
        if (bytes.Length > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b)
        {
            try
            {
                using var gz = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
                using var ms = new MemoryStream();
                gz.CopyTo(ms);
                var inner = DecodeBytes(ms.ToArray(), out var h2);
                how = "GZip → " + h2;
                return inner;
            }
            catch { }
        }
        // UTF-16LE 텍스트
        if (bytes.Length >= 8 && bytes.Length % 2 == 0 && bytes[1] == 0 && bytes[3] == 0)
        {
            var s = Encoding.Unicode.GetString(bytes);
            if (CommandLineUnwrapper.Printable(s) > 0.9) { how = "UTF-16LE"; return new CapturedPayload { Text = s }; }
        }
        var u = Encoding.UTF8.GetString(bytes);
        if (CommandLineUnwrapper.Printable(u) > 0.92) { how = "UTF-8"; return new CapturedPayload { Text = u }; }
        // Raw Deflate
        try
        {
            using var df = new DeflateStream(new MemoryStream(bytes), CompressionMode.Decompress);
            using var ms = new MemoryStream();
            df.CopyTo(ms);
            if (ms.Length > 16)
            {
                var inner = DecodeBytes(ms.ToArray(), out var h3);
                if (inner != null) { how = "Deflate → " + h3; return inner; }
            }
        }
        catch { }
        return null;
    }

    public static string DescribeBinary(byte[] b)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# 바이너리 페이로드 (실행하지 않음)");
        sb.AppendLine($"# 크기   : {b.Length:N0} bytes");
        sb.AppendLine($"# MD5    : {Convert.ToHexString(MD5.HashData(b)).ToLowerInvariant()}");
        sb.AppendLine($"# SHA256 : {Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant()}");
        if (b.Length > 0x40 && b[0] == 'M' && b[1] == 'Z')
        {
            int pe = BitConverter.ToInt32(b, 0x3C);
            string kind = "PE";
            if (pe > 0 && pe + 0x18 < b.Length && b[pe] == 'P' && b[pe + 1] == 'E')
            {
                ushort ch = BitConverter.ToUInt16(b, pe + 22);
                ushort machine = BitConverter.ToUInt16(b, pe + 4);
                kind = ((ch & 0x2000) != 0 ? "DLL" : "EXE") + (machine == 0x8664 ? " (x64)" : machine == 0x14c ? " (x86)" : "");
                int optOff = pe + 24;
                ushort magic = BitConverter.ToUInt16(b, optOff);
                int ddOff = optOff + (magic == 0x20b ? 112 : 96);
                if (ddOff + 15 * 8 + 8 <= b.Length && BitConverter.ToInt32(b, ddOff + 14 * 8) != 0) kind += " · .NET 어셈블리";
            }
            sb.AppendLine($"# 형식   : Windows {kind}");
        }
        var strs = ExtractStrings(b, 6).Take(40).ToList();
        if (strs.Count > 0)
        {
            sb.AppendLine("# 주요 문자열:");
            foreach (var s in strs) sb.AppendLine("#   " + s);
        }
        return sb.ToString();
    }

    public static IEnumerable<string> ExtractStrings(byte[] b, int min)
    {
        var cur = new StringBuilder();
        var res = new List<string>();
        foreach (var x in b)
        {
            if (x >= 0x20 && x < 0x7f) cur.Append((char)x);
            else { if (cur.Length >= min) res.Add(cur.ToString()); cur.Clear(); }
        }
        if (cur.Length >= min) res.Add(cur.ToString());
        // UTF-16
        cur.Clear();
        for (int i = 0; i + 1 < b.Length; i += 2)
        {
            if (b[i + 1] == 0 && b[i] >= 0x20 && b[i] < 0x7f) cur.Append((char)b[i]);
            else { if (cur.Length >= min) res.Add(cur.ToString()); cur.Clear(); }
        }
        // 흥미로운 문자열 우선
        return res.Distinct().OrderByDescending(s => Regex.IsMatch(s, @"https?://|\.exe|\.dll|powershell|cmd|HKEY|\\", RegexOptions.IgnoreCase)).ThenByDescending(s => s.Length);
    }

    static string HexDump(byte[] b, int max)
    {
        var sb = new StringBuilder();
        int n = Math.Min(b.Length, max);
        for (int i = 0; i < n; i += 16)
        {
            sb.Append("# ").Append(i.ToString("X8")).Append("  ");
            for (int j = 0; j < 16; j++) sb.Append(i + j < n ? b[i + j].ToString("X2") + " " : "   ");
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < n; j++) { var c = b[i + j]; sb.Append(c >= 0x20 && c < 0x7f ? (char)c : '.'); }
            sb.AppendLine();
        }
        if (b.Length > max) sb.AppendLine($"# ... ({b.Length - max:N0} bytes 생략)");
        return sb.ToString();
    }

    public static FileInfoModel BuildFileInfo(string name, string path, byte[] bytes)
    {
        return new FileInfoModel
        {
            Name = string.IsNullOrEmpty(name) ? "(붙여넣기)" : name,
            Path = path ?? "",
            Size = bytes.LongLength,
            Md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant(),
            Sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant(),
            Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            Entropy = Entropy(bytes)
        };
    }

    public static double Entropy(byte[] b)
    {
        if (b.Length == 0) return 0;
        var f = new int[256];
        foreach (var x in b) f[x]++;
        double e = 0;
        foreach (var c in f)
        {
            if (c == 0) continue;
            double p = (double)c / b.Length;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}
