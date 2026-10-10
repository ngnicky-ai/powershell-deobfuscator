using System.Collections.ObjectModel;

namespace PsDeobfuscator.Core;

/// <summary>난독화 해제 과정에서 얻은 한 단계(레이어).</summary>
public sealed class Layer
{
    public int Depth { get; set; }
    public string Title { get; set; } = "";
    /// <summary>이 레이어를 얻기 위해 사용된 기법 (예: "EncodedCommand(Base64/UTF-16LE)")</summary>
    public string Method { get; set; } = "";
    /// <summary>원시 디코딩 결과</summary>
    public string RawContent { get; set; } = "";
    /// <summary>상수 접기/정리를 거친 가독성 버전</summary>
    public string CleanContent { get; set; } = "";
    public bool IsBinary { get; set; }
    public byte[] Bytes { get; set; }
    public string BinaryInfo { get; set; } = "";
    public ObservableCollection<Layer> Children { get; } = new();
    /// <summary>안전 평가 중 변수에 대입된 문자열 (런타임에만 완성되는 URL·경로 탐지용)</summary>
    public List<string> ObservedStrings { get; } = new();
    /// <summary>이 레이어를 평가하면서 엔진이 처리하지 못한 항목</summary>
    public List<EngineGap> Gaps { get; } = new();
    /// <summary>평가 한도(단계 수·시간)에 도달했는지</summary>
    public bool BudgetHit { get; set; }
    public Layer Parent { get; set; }

    public string Indent => new string(' ', Depth * 2);
    public string DisplayTitle => $"L{Depth}  {Title}";
    public int Length => IsBinary ? (Bytes?.Length ?? 0) : RawContent.Length;
    public string SizeText => IsBinary ? $"{Length:N0} bytes" : $"{Length:N0} chars";
}

/// <summary>스크립트 평가 중 '실행 대신 캡처'된 페이로드.</summary>
public sealed class CapturedPayload
{
    public string Kind { get; set; } = "";
    public string Text { get; set; }
    public byte[] Bytes { get; set; }
    public string Note { get; set; } = "";
}

public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

/// <summary>엔진 미지원 항목의 분류</summary>
public enum GapKind
{
    /// <summary>엔진에 기능을 추가하면 해독 범위가 넓어지는 항목</summary>
    NeedsEngine = 0,
    /// <summary>평가 단계·크기 한도에 도달</summary>
    Limit = 1,
    /// <summary>네트워크·시스템 상태·외부 파일에 의존 (정적 분석으로는 의도적으로 미실행)</summary>
    Environment = 2,
    /// <summary>앞선 실패로 값을 몰라 생긴 연쇄 실패</summary>
    Cascade = 3,
}

public sealed class EngineGap
{
    public GapKind Kind { get; set; }
    /// <summary>정규화된 원인 (예: "[System.Xyz]::Foo", "cmdlet Get-CimInstance")</summary>
    public string Detail { get; set; } = "";
    public int Count { get; set; }
    /// <summary>처음 발생한 문장 (코드 위치 이동용)</summary>
    public string Example { get; set; } = "";
    public SortedSet<int> Layers { get; } = new();
    public string KindText => Kind switch
    {
        GapKind.NeedsEngine => "엔진 확장 필요",
        GapKind.Limit => "한도 도달",
        GapKind.Environment => "환경 의존",
        _ => "연쇄 실패"
    };
    public string LayersText => string.Join(",", Layers.Select(l => "L" + l));
    public bool Actionable => Kind is GapKind.NeedsEngine or GapKind.Limit;
}

/// <summary>레이어 해독이 끝까지 되지 않은 것으로 보이는 정황</summary>
public sealed class DecodeWarning
{
    public int LayerDepth { get; set; }
    public string LayerTitle { get; set; } = "";
    public string Reason { get; set; } = "";
    public string Evidence { get; set; } = "";
    /// <summary>true: 엔진이 놓친 것으로 의심 / false: 외부 입력 의존이라 정적 복원 불가 (정보)</summary>
    public bool Suspicious { get; set; }
    public string LevelText => Suspicious ? "해독 실패 의심" : "정적 복원 불가";
}

public sealed class BehaviorFinding
{
    public string RuleId { get; set; } = "";
    public string Category { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Mitre { get; set; } = "";
    public string MitreName { get; set; } = "";
    public Severity Severity { get; set; }
    public string Evidence { get; set; } = "";
    public int LayerDepth { get; set; }
    public string SeverityText => Severity switch
    {
        Severity.Critical => "치명",
        Severity.High => "높음",
        Severity.Medium => "중간",
        Severity.Low => "낮음",
        _ => "정보"
    };
    public string MitreUrl => string.IsNullOrEmpty(Mitre) ? "" :
        "https://attack.mitre.org/techniques/" + Mitre.Replace('.', '/') + "/";
}

public sealed class Ioc
{
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string Defanged { get; set; } = "";
    public string Context { get; set; } = "";
    public int LayerDepth { get; set; }
    public bool Benign { get; set; }
    public string Note { get; set; } = "";
}

public sealed class CommandExplanation
{
    public string Name { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Description { get; set; } = "";
    public int Count { get; set; }
    public bool Suspicious { get; set; }
}

public sealed class MitreItem
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Tactic { get; set; } = "";
    public int Count { get; set; }
    public string Url => "https://attack.mitre.org/techniques/" + Id.Replace('.', '/') + "/";
}

public sealed class FileInfoModel
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public string Md5 { get; set; } = "";
    public string Sha1 { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public double Entropy { get; set; }
}

public sealed class AnalysisResult
{
    public FileInfoModel File { get; set; }
    public Layer Root { get; set; }
    public List<Layer> AllLayers { get; } = new();
    public List<BehaviorFinding> Findings { get; } = new();
    public List<Ioc> Iocs { get; } = new();
    public List<CommandExplanation> Commands { get; } = new();
    public List<MitreItem> Mitre { get; } = new();
    public int RiskScore { get; set; }
    public string RiskLevel { get; set; } = "";
    public string Classification { get; set; } = "";
    public List<string> SummaryLines { get; } = new();
    public List<string> ObfuscationTechniques { get; } = new();
    /// <summary>모든 레이어의 엔진 미지원 항목 (같은 원인끼리 합산)</summary>
    public List<EngineGap> Gaps { get; } = new();
    public List<DecodeWarning> Warnings { get; } = new();
    public TimeSpan Elapsed { get; set; }
    public Layer FinalLayer =>
        AllLayers.Where(l => !l.IsBinary).OrderByDescending(l => l.Depth).FirstOrDefault() ?? Root;
}
