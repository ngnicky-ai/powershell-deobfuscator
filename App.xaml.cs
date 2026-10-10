using System.IO;
using System.Text;
using System.Windows;
using PsDeobfuscator.Core;

namespace PsDeobfuscator;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // 헤드리스 모드: PsDeobfuscator.exe --cli <입력파일> <출력 텍스트> [html출력]
        if (e.Args.Length >= 3 && e.Args[0] == "--cli")
        {
            try
            {
                var bytes = File.ReadAllBytes(e.Args[1]);
                var text = DecodeFileText(bytes);
                var r = Deobfuscator.Analyze(text, Path.GetFileName(e.Args[1]), e.Args[1], bytes);
                File.WriteAllText(e.Args[2], ReportExporter.ToText(r), Encoding.UTF8);
                if (e.Args.Length >= 4) File.WriteAllText(e.Args[3], ReportExporter.ToHtml(r), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                File.WriteAllText(e.Args[2], ex.ToString(), Encoding.UTF8);
            }
            Shutdown(0);
            return;
        }
        // 레이어 덤프: PsDeobfuscator.exe --dump <입력파일> <출력폴더>
        if (e.Args.Length >= 3 && e.Args[0] == "--dump")
        {
            var bytes = File.ReadAllBytes(e.Args[1]);
            var r = Deobfuscator.Analyze(DecodeFileText(bytes), Path.GetFileName(e.Args[1]), e.Args[1], bytes);
            Directory.CreateDirectory(e.Args[2]);
            int n = 0;
            foreach (var l in r.AllLayers)
            {
                if (l.IsBinary) continue;
                File.WriteAllText(Path.Combine(e.Args[2], $"{n:D2}_L{l.Depth}_raw.txt"), l.RawContent, Encoding.UTF8);
                File.WriteAllText(Path.Combine(e.Args[2], $"{n:D2}_L{l.Depth}_clean.txt"), l.CleanContent, Encoding.UTF8);
                n++;
            }
            Shutdown(0);
            return;
        }
        // 회귀 테스트: --test [regression.json] [보고서.txt]   (종료 코드 0=통과, 1=실패)
        if (e.Args.Length >= 1 && e.Args[0] == "--test")
        {
            var rep = RegressionRunner.Run(Arg(e, 1) ?? RegressionRunner.DefaultPath);
            Emit(rep.ToText(), Arg(e, 2));
            Shutdown(rep.Success ? 0 : 1);
            return;
        }
        // 규칙 자체 테스트: --validate-rules [rules.json] [보고서.txt]
        if (e.Args.Length >= 1 && e.Args[0] == "--validate-rules")
        {
            var rep = RuleValidator.Validate(Arg(e, 1));
            Emit(rep.ToText(), Arg(e, 2));
            Shutdown(rep.Passed ? 0 : 1);
            return;
        }
        // 기대값 기록: --snapshot <샘플파일> [regression.json]
        if (e.Args.Length >= 2 && e.Args[0] == "--snapshot")
        {
            var bytes = File.ReadAllBytes(e.Args[1]);
            var r = Deobfuscator.Analyze(DecodeFileText(bytes), Path.GetFileName(e.Args[1]), Path.GetFullPath(e.Args[1]), bytes);
            var suite = Arg(e, 2) ?? RegressionRunner.DefaultPath;
            var c = RegressionRunner.Snapshot(r, suite);
            RegressionRunner.AddOrReplace(suite, c);
            Emit($"회귀 테스트에 추가: {c.Name}\n  파일 {c.File}\n  규칙 {string.Join(",", c.Rules)}\n  IOC {c.Iocs.Count}개 → {suite}\n", null);
            Shutdown(0);
            return;
        }
        base.OnStartup(e);
        new MainWindow().Show();
    }

    static string Arg(StartupEventArgs e, int i) => e.Args.Length > i && !string.IsNullOrWhiteSpace(e.Args[i]) ? e.Args[i] : null;

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern bool AttachConsole(int pid);

    /// <summary>CLI 결과를 파일로 쓰고, 터미널에서 실행했다면 콘솔에도 출력한다 (GUI 앱이라 부모 콘솔에 붙음).</summary>
    static void Emit(string text, string outFile)
    {
        if (outFile != null) File.WriteAllText(outFile, text, new UTF8Encoding(true));
        try
        {
            if (AttachConsole(-1))
            {
                var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true };
                stdout.WriteLine();
                stdout.Write(text);
            }
        }
        catch { }
    }

    /// <summary>BOM/UTF-16 을 고려해 파일을 텍스트로 읽는다.</summary>
    public static string DecodeFileText(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        if (bytes.Length >= 4 && bytes[1] == 0 && bytes[3] == 0) return Encoding.Unicode.GetString(bytes);
        var utf8 = new UTF8Encoding(false, true);
        try { return utf8.GetString(bytes); }
        catch
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(949).GetString(bytes);
        }
    }
}
