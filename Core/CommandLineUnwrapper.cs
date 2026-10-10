using System.Text;
using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

/// <summary>
/// "powershell.exe -nop -w hidden -enc ..." 형태의 프로세스 명령줄을 해석하여
/// 실제 실행되는 스크립트 본문을 꺼낸다. (실행하지 않음)
/// </summary>
public static class CommandLineUnwrapper
{
    static readonly Regex HostPrefix = new(
        @"^\s*(?:(?:cmd(?:\.exe)?|%comspec%)\s+/[ck]\s+)?""?(?:[a-z]:\\[^""]*\\)?(?:powershell|pwsh)(?:\.exe)?""?(?=\s|$)",
        RegexOptions.IgnoreCase);

    public sealed class Result
    {
        public string Script { get; set; } = "";
        public string Method { get; set; } = "";
        public List<string> Flags { get; } = new();
    }

    public static Result TryUnwrap(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var trimmed = text.Trim().TrimStart('﻿');
        var m = HostPrefix.Match(trimmed);
        if (!m.Success) return null;

        var rest = trimmed.Substring(m.Length);
        var res = new Result();
        int pos = 0;
        while (pos < rest.Length)
        {
            while (pos < rest.Length && char.IsWhiteSpace(rest[pos])) pos++;
            if (pos >= rest.Length) break;
            int tokStart = pos;
            string tok = ReadArg(rest, ref pos);
            var lower = tok.ToLowerInvariant();

            // 중복된 호스트 이름 ("powershell.exe powershell -w h ...") 무시
            if (Regex.IsMatch(lower, @"^(?:[a-z]:\\.*\\)?(?:powershell|pwsh)(?:\.exe)?$")) continue;

            if (lower.StartsWith("-") || lower.StartsWith("/"))
            {
                var name = lower.TrimStart('-', '/');
                if (name.Length == 0) continue;

                if (IsPrefixOf(name, "encodedcommand", 1) || name == "ec" || name == "enc")
                {
                    while (pos < rest.Length && char.IsWhiteSpace(rest[pos])) pos++;
                    var b64 = ReadArg(rest, ref pos);
                    var decoded = DecodeEncodedCommand(b64);
                    if (decoded != null)
                    {
                        res.Script = decoded;
                        res.Method = "EncodedCommand (Base64 → UTF-16LE)";
                        res.Flags.Add(tok);
                        return res;
                    }
                    continue;
                }
                if (IsPrefixOf(name, "command", 1))
                {
                    while (pos < rest.Length && char.IsWhiteSpace(rest[pos])) pos++;
                    var body = rest.Substring(pos).Trim();
                    res.Script = StripOuterQuotes(body);
                    res.Method = "-Command 인자 추출";
                    res.Flags.Add(tok);
                    return res;
                }
                if (IsPrefixOf(name, "file", 1))
                {
                    // -File <경로> : 스크립트 본문이 명령줄에 없음 (호출 측에서 드롭 파일 내용을 연결)
                    return null;
                }
                // 값을 가지는 옵션
                if (IsPrefixOf(name, "windowstyle", 1) || IsPrefixOf(name, "executionpolicy", 2) || name == "ep" ||
                    IsPrefixOf(name, "version", 1) || IsPrefixOf(name, "inputformat", 2) || IsPrefixOf(name, "outputformat", 1) ||
                    IsPrefixOf(name, "configurationname", 4) || IsPrefixOf(name, "workingdirectory", 2) || name == "wd" ||
                    IsPrefixOf(name, "psconsolefile", 3))
                {
                    while (pos < rest.Length && char.IsWhiteSpace(rest[pos])) pos++;
                    var v = pos < rest.Length ? ReadArg(rest, ref pos) : "";
                    res.Flags.Add(tok + " " + v);
                    continue;
                }
                res.Flags.Add(tok);
                continue;
            }

            // 옵션이 아닌 첫 토큰부터는 전부 명령(-Command 기본 동작)
            var body2 = rest.Substring(tokStart).Trim();
            res.Script = StripOuterQuotes(body2);
            res.Method = "명령줄 스크립트 인자 추출";
            return res;
        }
        return null;
    }

    static bool IsPrefixOf(string name, string full, int minLen) =>
        name.Length >= minLen && full.StartsWith(name, StringComparison.Ordinal);

    static string ReadArg(string s, ref int pos)
    {
        var sb = new StringBuilder();
        bool inQ = false;
        while (pos < s.Length)
        {
            char c = s[pos];
            if (c == '"') { inQ = !inQ; pos++; continue; }
            if (!inQ && char.IsWhiteSpace(c)) break;
            sb.Append(c);
            pos++;
        }
        return sb.ToString();
    }

    static string StripOuterQuotes(string body)
    {
        body = body.Trim();
        if (body.Length >= 2 && body[0] == '"')
        {
            int last = body.LastIndexOf('"');
            if (last > 0) body = body.Substring(1, last - 1);
            else body = body.Substring(1);
            body = body.Replace("\\\"", "\"");
        }
        else if (body.StartsWith("&") || body.StartsWith("{"))
        {
            // "& {...}" 형태는 그대로
        }
        return body.Trim();
    }

    public static string DecodeEncodedCommand(string b64)
    {
        try
        {
            b64 = Regex.Replace(b64, @"[^A-Za-z0-9+/=]", "");
            int pad = b64.Length % 4;
            if (pad == 2) b64 += "=="; else if (pad == 3) b64 += "=";
            var bytes = Convert.FromBase64String(b64);
            var s = Encoding.Unicode.GetString(bytes);
            if (Printable(s) > 0.85) return s;
            s = Encoding.UTF8.GetString(bytes);
            if (Printable(s) > 0.85) return s;
        }
        catch { }
        return null;
    }

    public static double Printable(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        int ok = 0;
        foreach (var c in s)
            if (c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7F) || (c >= 0xA0 && c != 0xFFFD)) ok++;
        return (double)ok / s.Length;
    }
}
