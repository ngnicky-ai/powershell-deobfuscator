using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PsDeobfuscator.Core;

/// <summary>
/// 탐지 규칙/명령어 설명은 실행 파일과 분리된 Rules\rules.json 에 둔다.
/// (사용자가 규칙을 직접 추가·수정할 수 있고, 실행 파일에 악성 키워드가 포함되지 않아 백신 오탐도 줄어든다)
/// </summary>
public static class RuleStore
{
    public sealed class BehaviorRule
    {
        public string Id { get; set; } = "";
        public string Category { get; set; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Mitre { get; set; } = "";
        public string MitreName { get; set; } = "";
        public string Tactic { get; set; } = "";
        public string Severity { get; set; } = "Info";
        public string Pattern { get; set; } = "";
        /// <summary>반드시 탐지되어야 하는 코드 조각 (규칙 자체 테스트)</summary>
        public List<string> Examples { get; set; } = new();
        /// <summary>탐지되면 안 되는 코드 조각 (오탐 방지 테스트)</summary>
        public List<string> CounterExamples { get; set; } = new();
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string Author { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string Updated { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<string> References { get; set; }
    }

    public sealed class CommandRule
    {
        public string Pattern { get; set; } = "";
        public string Name { get; set; } = "";
        public string Kind { get; set; } = "";
        public string Description { get; set; } = "";
        public bool Suspicious { get; set; }
        public List<string> Examples { get; set; } = new();
        public List<string> CounterExamples { get; set; } = new();
    }

    public sealed class RuleFile
    {
        public int Version { get; set; }
        public List<BehaviorRule> Behaviors { get; set; } = new();
        public List<CommandRule> Commands { get; set; } = new();
    }

    static RuleFile _data;
    static string _path;

    /// <summary>규칙을 다시 읽을 때마다 증가 (분석기가 컴파일한 정규식 캐시 무효화용)</summary>
    public static int Generation { get; private set; }
    public static string LoadError { get; private set; }
    /// <summary>로드 중 제외된 규칙 (잘못된 정규식 등)</summary>
    public static List<string> LoadIssues { get; } = new();

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// 규칙 파일 위치. 우선순위: 환경 변수 PSDEOB_RULES → (개발 중) 프로젝트 원본 Rules\rules.json → 실행 폴더.
    /// 원본을 우선하면 규칙을 고친 뒤 재빌드 없이 '규칙 다시 읽기'로 바로 반영된다.
    /// </summary>
    public static string RulePath => _path ??= ResolvePath();

    static string ResolvePath()
    {
        var env = Environment.GetEnvironmentVariable("PSDEOB_RULES");
        if (!string.IsNullOrEmpty(env) && File.Exists(env)) return env;
        var src = ProjectFile(Path.Combine("Rules", "rules.json"));
        if (src != null) return src;
        // 단일 exe 배포: exe 옆에 Rules\rules.json 을 두면 내장 기본 규칙 대신 사용
        var beside = Path.Combine(AppDir, "Rules", "rules.json");
        if (File.Exists(beside)) return beside;
        return Path.Combine(AppContext.BaseDirectory, "Rules", "rules.json");
    }

    /// <summary>실행 파일이 있는 폴더 (단일 exe 는 BaseDirectory 가 임시 압축 해제 폴더라 다름)</summary>
    public static string AppDir => Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

    /// <summary>화면·보고서에 표시할 경로 (개인 폴더 경로가 드러나지 않도록 줄임)</summary>
    public static string Friendly(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        var full = Path.GetFullPath(path);
        string Rel(string root, string label)
        {
            var r = root.TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
            return full.StartsWith(r, StringComparison.OrdinalIgnoreCase) ? label + "\\" + full[r.Length..] : null;
        }
        var pd = ProjectDir;
        if (pd != null)
        {
            var parent = Path.GetDirectoryName(pd);
            if (Rel(pd, "<프로젝트>") is { } a) return a;
            if (parent != null && Rel(parent, "<작업 폴더>") is { } b) return b;
        }
        if (!AppContext.BaseDirectory.TrimEnd('\\').Equals(AppDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) &&
            Rel(AppContext.BaseDirectory, "<내장>") is { } c) return c;
        if (Rel(AppDir, "<실행 폴더>") is { } d) return d;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Rel(home, "%USERPROFILE%") ?? full;
    }

    /// <summary>실행 폴더에서 위로 올라가며 PsDeobfuscator.csproj 옆의 파일을 찾는다 (개발 환경).</summary>
    public static string ProjectFile(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 7 && dir != null; i++, dir = dir.Parent)
        {
            if (!File.Exists(Path.Combine(dir.FullName, "PsDeobfuscator.csproj"))) continue;
            var p = Path.Combine(dir.FullName, relative);
            return File.Exists(p) ? p : null;
        }
        return null;
    }

    /// <summary>프로젝트 폴더 (개발 환경이 아니면 null)</summary>
    public static string ProjectDir
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 7 && dir != null; i++, dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "PsDeobfuscator.csproj"))) return dir.FullName;
            return null;
        }
    }

    public static RuleFile Data => _data ??= Load();

    public static void Reload()
    {
        _data = null;
        _path = null;
        Generation++;
    }

    /// <summary>파일을 그대로 읽는다 (검증기용: 잘못된 규칙도 포함).</summary>
    public static RuleFile ReadRaw(string path) =>
        JsonSerializer.Deserialize<RuleFile>(File.ReadAllText(path), JsonOptions) ?? new RuleFile();

    static RuleFile Load()
    {
        LoadError = null;
        LoadIssues.Clear();
        try
        {
            var data = ReadRaw(RulePath);
            // 잘못된 정규식은 제외하되, 무엇이 빠졌는지 기록한다
            data.Behaviors = data.Behaviors.Where(b =>
            {
                if (IsValidRegex(b.Pattern)) return true;
                LoadIssues.Add($"행위 규칙 '{b.Id}' 의 정규식이 잘못되어 제외했습니다.");
                return false;
            }).ToList();
            data.Commands = data.Commands.Where(c =>
            {
                if (IsValidRegex(c.Pattern)) return true;
                LoadIssues.Add($"명령어 설명 '{c.Name}' 의 정규식이 잘못되어 제외했습니다.");
                return false;
            }).ToList();
            return data;
        }
        catch (Exception ex)
        {
            LoadError = $"규칙 파일을 읽지 못했습니다 ({RulePath}): {ex.Message}";
            return new RuleFile();
        }
    }

    static bool IsValidRegex(string p)
    {
        if (string.IsNullOrEmpty(p)) return false;
        try { _ = new System.Text.RegularExpressions.Regex(p); return true; }
        catch { return false; }
    }
}
