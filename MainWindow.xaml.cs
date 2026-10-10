using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Xml;
using ICSharpCode.AvalonEdit.Highlighting;
using ICSharpCode.AvalonEdit.Highlighting.Xshd;
using ICSharpCode.AvalonEdit.Search;
using Microsoft.Win32;
using PsDeobfuscator.Core;

namespace PsDeobfuscator;

public partial class MainWindow : Window
{
    AnalysisResult _result;
    string _text, _name, _path;
    byte[] _bytes;
    Layer _layer;
    bool _suppressTreeSelect;
    bool _vtConfirmed;
    readonly SearchPanel _search;

    public static readonly DependencyProperty GaugeValueProperty = DependencyProperty.Register(
        nameof(GaugeValue), typeof(double), typeof(MainWindow), new PropertyMetadata(0.0, (d, _) => ((MainWindow)d).UpdateGauge()));

    public double GaugeValue
    {
        get => (double)GetValue(GaugeValueProperty);
        set => SetValue(GaugeValueProperty, value);
    }

    public MainWindow()
    {
        InitializeComponent();

        // Ctrl+마우스 휠 확대/축소 (창 전체에 적용, 배율은 다음 실행 때도 유지)
        UiZoom.Attach(this, RootGrid);
        ZoomText.Text = UiZoom.Percent;
        UiZoom.Changed += OnZoomChanged;
        Closed += (_, _) => UiZoom.Changed -= OnZoomChanged;

        LoadHighlighting();
        Editor.Options.EnableHyperlinks = false;      // 악성 URL 을 실수로 클릭하지 않도록
        Editor.Options.EnableEmailHyperlinks = false;
        Editor.Options.HighlightCurrentLine = true;
        Editor.Options.AllowScrollBelowDocument = true;
        Editor.TextArea.SelectionBrush = new SolidColorBrush(Color.FromArgb(0x66, 0x7C, 0x5C, 0xFF));
        Editor.TextArea.SelectionBorder = null;
        Editor.TextArea.SelectionForeground = null;
        Editor.TextArea.TextView.CurrentLineBackground = new SolidColorBrush(Color.FromArgb(0x22, 0x7C, 0x5C, 0xFF));
        Editor.TextArea.TextView.CurrentLineBorder = new Pen(Brushes.Transparent, 0);
        _search = SearchPanel.Install(Editor);
        _search.MarkerBrush = new SolidColorBrush(Color.FromArgb(0x88, 0xF7, 0xC9, 0x48));

        UpdateRuleStatus(null);
        _ = CheckRulesAsync();

        // 실행 인자로 파일이 넘어온 경우 (탐색기 '연결 프로그램' 등)
        var args = Environment.GetCommandLineArgs();
        if (args.Length > 1 && File.Exists(args[1])) Loaded += async (_, _) => await OpenFileAsync(args[1]);
    }

    void LoadHighlighting()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "Resources", "PowerShellDark.xshd");
            using var reader = XmlReader.Create(path);
            Editor.SyntaxHighlighting = HighlightingLoader.Load(reader, HighlightingManager.Instance);
        }
        catch
        {
            Editor.SyntaxHighlighting = HighlightingManager.Instance.GetDefinition("PowerShell");
        }
    }

    #region 분석

    async Task OpenFileAsync(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (fi.Length > 30 * 1024 * 1024 &&
                MessageBox.Show(this, $"파일이 큽니다 ({fi.Length / 1024 / 1024:N0} MB). 분석에 시간이 걸릴 수 있습니다. 계속할까요?", "PS Deobfuscator",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            var bytes = await File.ReadAllBytesAsync(path);
            await AnalyzeAsync(App.DecodeFileText(bytes), fi.Name, path, bytes);
        }
        catch (Exception ex)
        {
            SetStatus("파일을 열 수 없습니다: " + ex.Message, true);
            MessageBox.Show(this, "파일을 열 수 없습니다.\n" + ex.Message, "PS Deobfuscator", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    async Task AnalyzeAsync(string text, string name, string path, byte[] bytes)
    {
        _text = text; _name = name; _path = path; _bytes = bytes;
        ShowBusy(true);
        SetStatus($"분석 중… {name}");
        try
        {
            var r = await Task.Run(() => Deobfuscator.Analyze(text, name, path, bytes));
            ShowResult(r);
        }
        catch (Exception ex)
        {
            SetStatus("분석 실패: " + ex.Message, true);
            MessageBox.Show(this, "분석 중 오류가 발생했습니다.\n" + ex.Message, "PS Deobfuscator", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ShowBusy(false);
        }
    }

    void ShowBusy(bool on, string text = null)
    {
        if (on) BusyText.Text = text ?? "레이어를 해제하는 중…";
        BusyOverlay.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        var sb = (Storyboard)Resources["SpinStoryboard"];
        if (on) sb.Begin(this, true); else sb.Stop(this);
    }

    void ShowResult(AnalysisResult r)
    {
        _result = r;
        WelcomePanel.Visibility = Visibility.Collapsed;
        FileCard.Visibility = Visibility.Visible;
        LayerCard.Visibility = Visibility.Visible;
        ClassChip.Visibility = Visibility.Visible;
        ReanalyzeButton.IsEnabled = true;
        ExportButton.IsEnabled = true;

        // 파일 정보
        FileNameText.Text = r.File.Name;
        FileNameText.ToolTip = string.IsNullOrEmpty(r.File.Path) ? r.File.Name : r.File.Path;
        FileSizeText.Text = $"{r.File.Size:N0} bytes";
        ShaText.Text = r.File.Sha256;
        Md5Text.Text = r.File.Md5;
        EntropyText.Text = r.File.Entropy.ToString("F2");
        Dispatcher.BeginInvoke(() =>
        {
            var host = (FrameworkElement)EntropyBar.Parent;
            EntropyBar.Width = Math.Max(4, host.ActualWidth * Math.Min(1, r.File.Entropy / 8.0));
        }, System.Windows.Threading.DispatcherPriority.Loaded);

        // 위험도
        ClassText.Text = r.Classification;
        LevelText.Text = r.RiskLevel;
        var (c1, c2) = RiskColors(r.RiskScore);
        GaugeStop1.Color = c1;
        GaugeStop2.Color = c2;
        LevelText.Foreground = new SolidColorBrush(c1);
        StatusDot.Fill = new SolidColorBrush(c1);
        BeginAnimation(GaugeValueProperty, new DoubleAnimation(0, r.RiskScore, TimeSpan.FromMilliseconds(900))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        });

        // 레이어
        int maxDepth = r.AllLayers.Max(l => l.Depth);
        LayerCountText.Text = $"{maxDepth}단계 · {r.AllLayers.Count}개";
        LayerTree.ItemsSource = new[] { r.Root };

        // 오른쪽 탭
        SummaryList.ItemsSource = r.SummaryLines;
        SummaryEmpty.Visibility = Visibility.Collapsed;
        TechList.ItemsSource = r.ObfuscationTechniques;
        FindingList.ItemsSource = r.Findings;
        CommandList.ItemsSource = r.Commands;
        MitreList.ItemsSource = r.Mitre;
        ApplyIocFilter();
        FindingsTab.Header = $"행위 {r.Findings.Count}";
        IocTab.Header = $"IOC {r.Iocs.Count(i => !i.Benign)}";
        CommandsTab.Header = $"명령어 {r.Commands.Count}";
        MitreTab.Header = $"ATT&CK {r.Mitre.Count}";
        ShowDiagnostics(r);
        StatLayers.Text = maxDepth.ToString();
        StatFindings.Text = r.Findings.Count.ToString();
        StatIocs.Text = r.Iocs.Count(i => !i.Benign).ToString();
        StatTime.Text = r.Elapsed.TotalSeconds < 1 ? $"{r.Elapsed.TotalMilliseconds:N0}ms" : $"{r.Elapsed.TotalSeconds:N1}s";
        RightTabs.SelectedIndex = 0;

        // 가장 깊은 최종 레이어를 기본 표시
        var final = r.FinalLayer;
        ShowLayer(final);
        Dispatcher.BeginInvoke(() => SelectLayerInTree(final, false), System.Windows.Threading.DispatcherPriority.Loaded);

        FadeIn(RightTabs);
        FadeIn(Editor);
        SetStatus($"분석 완료 · {r.File.Name} · {maxDepth}단계 해제 · 행위 {r.Findings.Count}건 · IOC {r.Iocs.Count(i => !i.Benign)}건");
    }

    static (Color, Color) RiskColors(int score) => score switch
    {
        >= 75 => (Color.FromRgb(0xFF, 0x4D, 0x6D), Color.FromRgb(0xFF, 0x8C, 0x42)),
        >= 50 => (Color.FromRgb(0xFF, 0x8C, 0x42), Color.FromRgb(0xF7, 0xC9, 0x48)),
        >= 25 => (Color.FromRgb(0xF7, 0xC9, 0x48), Color.FromRgb(0x4C, 0xC9, 0xF0)),
        _ => (Color.FromRgb(0x2E, 0xC4, 0xB6), Color.FromRgb(0x00, 0xD4, 0xFF)),
    };

    void UpdateGauge()
    {
        const double d = 150, t = 12;
        double circumference = Math.PI * (d - t) / t; // 대시 단위는 선 두께 기준
        double len = Math.Max(0.001, GaugeValue / 100.0 * circumference);
        GaugeArc.StrokeDashArray = new DoubleCollection { len, 1000 };
        // 0 일 때 둥근 선 끝만 남아 점처럼 보이지 않도록 숨김
        GaugeArc.Visibility = GaugeValue < 0.5 ? Visibility.Hidden : Visibility.Visible;
        ScoreText.Text = ((int)Math.Round(GaugeValue)).ToString();
    }

    static void FadeIn(UIElement el)
    {
        el.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(350)));
    }

    void SetStatus(string text, bool error = false)
    {
        StatusText.Text = text;
        StatusText.Foreground = error ? (Brush)FindResource("CriticalBrush") : (Brush)FindResource("MutedBrush");
    }

    #endregion

    #region 레이어 표시

    void ShowLayer(Layer layer)
    {
        if (layer == null) return;
        _layer = layer;
        LayerTitleText.Text = $"L{layer.Depth} · {layer.Title}";
        LayerMethodText.Text = layer.Method + "  ·  " + layer.SizeText;
        var text = layer.IsBinary || ViewClean.IsChecked == true ? layer.CleanContent : layer.RawContent;
        text ??= "";
        if (text.Length > 8_000_000) text = text[..8_000_000] + "\n\n# ... (표시 한도 초과로 생략)";
        Editor.Text = text;
        Editor.ScrollToHome();
        SaveLayerButton.ToolTip = layer.IsBinary ? "바이너리 페이로드 저장 (.bin)" : "이 레이어를 텍스트 파일로 저장";
    }

    void OnLayerSelected(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (_suppressTreeSelect) return;
        if (e.NewValue is Layer l) ShowLayer(l);
    }

    void OnViewModeChanged(object sender, RoutedEventArgs e)
    {
        if (_layer != null) ShowLayer(_layer);
    }

    void OnWrapChanged(object sender, RoutedEventArgs e) => Editor.WordWrap = WrapToggle.IsChecked == true;

    void SelectLayerInTree(Layer target, bool bringIntoView = true)
    {
        if (target == null) return;
        var path = new Stack<Layer>();
        for (var l = target; l != null; l = l.Parent) path.Push(l);
        ItemsControl container = LayerTree;
        TreeViewItem item = null;
        while (path.Count > 0)
        {
            var l = path.Pop();
            container.UpdateLayout();
            item = container.ItemContainerGenerator.ContainerFromItem(l) as TreeViewItem;
            if (item == null) return;
            item.IsExpanded = true;
            container = item;
        }
        _suppressTreeSelect = true;
        item.IsSelected = true;
        if (bringIntoView) item.BringIntoView();
        _suppressTreeSelect = false;
    }

    /// <summary>근거 문자열이 있는 레이어로 이동해 해당 위치를 선택한다.</summary>
    void JumpTo(int depth, string snippet)
    {
        if (_result == null || string.IsNullOrWhiteSpace(snippet)) return;
        var probe = snippet.Split('\n')[0].Trim().Trim('…').Trim();
        if (probe.Length > 60) probe = probe[..60];
        var candidates = _result.AllLayers.Where(l => !l.IsBinary).OrderBy(l => Math.Abs(l.Depth - depth)).ToList();
        foreach (var l in candidates)
        {
            bool inClean = l.CleanContent?.Contains(probe, StringComparison.OrdinalIgnoreCase) == true;
            bool inRaw = !inClean && l.RawContent?.Contains(probe, StringComparison.OrdinalIgnoreCase) == true;
            if (!inClean && !inRaw) continue;
            if (inClean) ViewClean.IsChecked = true; else ViewRaw.IsChecked = true;
            ShowLayer(l);
            SelectLayerInTree(l);
            int idx = Editor.Text.IndexOf(probe, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                Editor.Select(idx, probe.Length);
                var loc = Editor.Document.GetLocation(idx);
                Editor.ScrollTo(loc.Line, loc.Column);
                Editor.TextArea.Caret.Offset = idx;
            }
            SetStatus($"L{l.Depth} '{l.Title}' 에서 위치를 찾았습니다.");
            return;
        }
        SetStatus("코드에서 해당 위치를 찾지 못했습니다.");
    }

    void OnEvidenceClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is BehaviorFinding f) JumpTo(f.LayerDepth, f.Evidence);
    }

    #endregion

    #region IOC

    void ApplyIocFilter()
    {
        if (_result == null) return;
        var q = IocFilter.Text?.Trim() ?? "";
        bool hideBenign = HideBenignToggle.IsChecked == true;
        IocList.ItemsSource = _result.Iocs
            .Where(i => !hideBenign || !i.Benign)
            .Where(i => q.Length == 0 || i.Value.Contains(q, StringComparison.OrdinalIgnoreCase) || i.Type.Contains(q, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    void OnIocFilterChanged(object sender, RoutedEventArgs e) => ApplyIocFilter();

    Ioc SelectedIoc => IocList.SelectedItem as Ioc;

    void OnIocCopy(object sender, RoutedEventArgs e)
    {
        if (SelectedIoc is { } i) CopyText(i.Value, "값을 복사했습니다.");
    }

    void OnIocCopyDefanged(object sender, RoutedEventArgs e)
    {
        if (SelectedIoc is { } i) CopyText(i.Defanged, "디팽된 값을 복사했습니다.");
    }

    void OnIocVirusTotal(object sender, RoutedEventArgs e)
    {
        if (SelectedIoc is { } i) OpenVirusTotal(i.Value);
    }

    void OnIocGoto(object sender, RoutedEventArgs e)
    {
        if (SelectedIoc is { } i) JumpTo(i.LayerDepth, i.Value);
    }

    void OnIocDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (SelectedIoc is { } i) JumpTo(i.LayerDepth, i.Value);
    }

    void OnCopyAllIocClick(object sender, RoutedEventArgs e)
    {
        if (_result == null) return;
        var sb = new StringBuilder();
        foreach (var g in _result.Iocs.Where(i => !i.Benign).GroupBy(i => i.Type))
        {
            sb.AppendLine($"[{g.Key}]");
            foreach (var i in g) sb.AppendLine(i.Defanged);
            sb.AppendLine();
        }
        CopyText(sb.ToString(), "전체 IOC 를 디팽 형태로 복사했습니다.");
    }

    void OpenVirusTotal(string value)
    {
        if (!_vtConfirmed)
        {
            var ok = MessageBox.Show(this,
                "선택한 값(해시/도메인/URL)을 VirusTotal 웹사이트에서 검색합니다.\n값이 외부 서비스로 전송됩니다. 계속할까요?",
                "VirusTotal 조회", MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (ok != MessageBoxResult.Yes) return;
            _vtConfirmed = true;
        }
        OpenUrl("https://www.virustotal.com/gui/search/" + Uri.EscapeDataString(Uri.EscapeDataString(value)));
    }

    #endregion

    #region 진단 · 규칙 관리 · 회귀 테스트

    RuleValidator.Report _ruleReport;

    void ShowDiagnostics(AnalysisResult r)
    {
        WarningList.ItemsSource = r.Warnings.OrderByDescending(w => w.Suspicious).ThenBy(w => w.LayerDepth).ToList();
        DiagOkPanel.Visibility = r.Warnings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ApplyGapFilter();
        int issues = r.Warnings.Count(w => w.Suspicious) + r.Gaps.Count(g => g.Actionable);
        DiagTab.Header = issues > 0 ? $"진단 {issues}" : "진단";
        AddRegressionButton.IsEnabled = !string.IsNullOrEmpty(r.File.Path) && File.Exists(r.File.Path);
    }

    void ApplyGapFilter()
    {
        if (_result == null) return;
        bool all = ShowAllGapsToggle.IsChecked == true;
        var list = _result.Gaps.Where(g => all || g.Actionable).ToList();
        GapList.ItemsSource = list;
        GapEmptyText.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        GapEmptyText.Text = all || _result.Gaps.Count == 0
            ? "엔진이 처리하지 못한 항목이 없습니다."
            : $"엔진 확장이 필요한 항목이 없습니다. (환경 의존 {_result.Gaps.Count}건은 '환경 의존 포함'으로 볼 수 있음)";
    }

    void OnGapFilterChanged(object sender, RoutedEventArgs e) => ApplyGapFilter();

    void OnWarningClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is DecodeWarning w) JumpTo(w.LayerDepth, w.Evidence);
    }

    void OnGapClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is EngineGap g && g.Layers.Count > 0) JumpTo(g.Layers.Min, g.Example);
    }

    async Task CheckRulesAsync()
    {
        var path = RuleStore.RulePath;
        _ruleReport = await Task.Run(() => RuleValidator.Validate(path));
        UpdateRuleStatus(_ruleReport);
    }

    void UpdateRuleStatus(RuleValidator.Report rep)
    {
        var rules = RuleStore.Data;
        RulePathText.Text = RuleStore.Friendly(RuleStore.RulePath);
        RulePathText.ToolTip = RuleStore.RulePath;
        string head = $"행위 규칙 {rules.Behaviors.Count}개 · 명령어 설명 {rules.Commands.Count}개";
        if (RuleStore.LoadError != null)
        {
            RulesText.Text = "규칙 파일 오류";
            RulesDot.Fill = (Brush)FindResource("CriticalBrush");
            RuleStatusText.Text = RuleStore.LoadError;
            SetStatus(RuleStore.LoadError, true);
            return;
        }
        if (rep == null)
        {
            RulesText.Text = head + " · 자체 테스트 중…";
            RuleStatusText.Text = head;
            return;
        }
        if (rep.Passed)
        {
            RulesText.Text = $"{head} · 자체 테스트 통과" + (rep.Warnings > 0 ? $" (경고 {rep.Warnings})" : "");
            RulesDot.Fill = (Brush)FindResource(rep.Warnings > 0 ? "MediumBrush" : "SafeBrush");
            RuleStatusText.Text = $"{head}\n자체 테스트 통과 — 예시 {rep.ExamplesChecked}건 · 반례 {rep.CounterExamplesChecked}건" + (rep.Warnings > 0 ? $" · 경고 {rep.Warnings}" : "");
            RuleStatusText.Foreground = (Brush)FindResource("TextBrush");
        }
        else
        {
            RulesText.Text = $"규칙 자체 테스트 실패 — 오류 {rep.Errors}";
            RulesDot.Fill = (Brush)FindResource("CriticalBrush");
            RuleStatusText.Text = $"{head}\n자체 테스트 실패 — 오류 {rep.Errors} · 경고 {rep.Warnings} (클릭해서 확인)";
            RuleStatusText.Foreground = (Brush)FindResource("CriticalBrush");
        }
        if (RuleStore.LoadIssues.Count > 0) RuleStatusText.Text += "\n" + string.Join("\n", RuleStore.LoadIssues);
    }

    void OnToolsClick(object sender, RoutedEventArgs e)
    {
        AddRegressionItem.IsEnabled = _result != null && !string.IsNullOrEmpty(_result.File.Path) && File.Exists(_result.File.Path);
        ToolsMenu.PlacementTarget = ToolsButton;
        ToolsMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        ToolsMenu.IsOpen = true;
    }

    async void OnValidateRules(object sender, RoutedEventArgs e)
    {
        ShowBusy(true, "규칙 자체 테스트 중…");
        try
        {
            var path = RuleStore.RulePath;
            _ruleReport = await Task.Run(() => RuleValidator.Validate(path));
            UpdateRuleStatus(_ruleReport);
        }
        finally { ShowBusy(false); }
        var r = _ruleReport;
        new ReportWindow("규칙 자체 테스트", r.Passed, r.Passed ? "통과" : "실패",
            $"오류 {r.Errors} · 경고 {r.Warnings} — 행위 규칙 {r.BehaviorCount}개 (예시 보유 {r.RulesWithExamples}개)",
            $"예시 {r.ExamplesChecked}건 · 반례 {r.CounterExamplesChecked}건 · {r.Elapsed.TotalMilliseconds:N0}ms  |  {RuleStore.Friendly(r.Path)}",
            r.ToText(), "rule_validation.txt") { Owner = this }.ShowDialog();
    }

    async void OnRunRegression(object sender, RoutedEventArgs e)
    {
        var path = RegressionRunner.DefaultPath;
        if (!File.Exists(path))
        {
            MessageBox.Show(this, $"회귀 테스트 파일이 없습니다.\n{path}\n\n샘플을 연 뒤 '현재 파일을 회귀 테스트에 추가'로 만들 수 있습니다.",
                "회귀 테스트", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ShowBusy(true, "회귀 테스트 실행 중…");
        RegressionRunner.Report rep;
        try
        {
            rep = await Task.Run(() => RegressionRunner.Run(path, name => Dispatcher.BeginInvoke(() => BusyText.Text = "회귀 테스트: " + name)));
        }
        finally { ShowBusy(false); }
        SetStatus($"회귀 테스트 {(rep.Success ? "통과" : "실패")} — 통과 {rep.Passed} · 실패 {rep.Failed} · 건너뜀 {rep.Skipped}", !rep.Success);
        new ReportWindow("회귀 테스트", rep.Success, rep.Success ? "통과" : "실패",
            $"통과 {rep.Passed} · 실패 {rep.Failed} · 건너뜀 {rep.Skipped}",
            $"{rep.Elapsed.TotalSeconds:N1}s  |  {RuleStore.Friendly(rep.Path)}", rep.ToText(), "regression_report.txt") { Owner = this }.ShowDialog();
    }

    void OnAddToRegression(object sender, RoutedEventArgs e)
    {
        if (_result == null || string.IsNullOrEmpty(_result.File.Path) || !File.Exists(_result.File.Path))
        {
            MessageBox.Show(this, "파일로 연 샘플만 회귀 테스트에 추가할 수 있습니다 (클립보드 분석은 제외).", "회귀 테스트", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var suite = RegressionRunner.DefaultPath;
        var c = RegressionRunner.Snapshot(_result, suite);
        var msg = $"현재 분석 결과를 기대값으로 기록합니다.\n\n" +
                  $"이름: {c.Name}\n파일: {c.File}\n최소 해제 단계: {c.MinDepth} · 최소 레이어: {c.MinLayers} · 최소 위험도: {c.MinRisk}\n" +
                  $"필수 규칙({c.Rules.Count}): {string.Join(", ", c.Rules)}\n필수 IOC: {c.Iocs.Count}개\n" +
                  $"엔진 확장 필요 허용: {c.MaxEngineGaps}개\n\n저장 위치: {RuleStore.Friendly(suite)}\n(같은 파일의 기존 항목은 교체됩니다)\n\n" +
                  "※ 결과가 맞는지 먼저 확인한 뒤 추가하세요. 오탐 IOC 는 regression.json 의 forbiddenIocs 에 넣으면 재발을 막을 수 있습니다.";
        if (MessageBox.Show(this, msg, "회귀 테스트에 추가", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        try
        {
            RegressionRunner.AddOrReplace(suite, c);
            SetStatus($"회귀 테스트에 추가했습니다: {c.Name} ({RegressionRunner.Load(suite).Cases.Count}개 케이스)");
        }
        catch (Exception ex) { SetStatus("저장 실패: " + ex.Message, true); }
    }

    async void OnReloadRules(object sender, RoutedEventArgs e)
    {
        RuleStore.Reload();
        UpdateRuleStatus(null);
        await CheckRulesAsync();
        SetStatus($"규칙을 다시 읽었습니다 ({RuleStore.Data.Behaviors.Count}개)." + (_text != null ? " 현재 파일을 다시 분석합니다." : ""), RuleStore.LoadError != null);
        if (_text != null) await AnalyzeAsync(_text, _name, _path, _bytes);
    }

    void OnOpenRulesFolder(object sender, RoutedEventArgs e)
    {
        try { Process.Start("explorer.exe", $"/select,\"{RuleStore.RulePath}\""); }
        catch (Exception ex) { SetStatus("폴더를 열 수 없습니다: " + ex.Message, true); }
    }

    #endregion

    #region 버튼/메뉴

    async void OnOpenClick(object sender, RoutedEventArgs e) => await ShowOpenDialog(null);

    async void OnSampleFolderClick(object sender, RoutedEventArgs e) => await ShowOpenDialog(FindSampleFolder());

    void OnDropZoneClick(object sender, MouseButtonEventArgs e) => OnOpenClick(sender, e);

    async Task ShowOpenDialog(string initialDir)
    {
        var dlg = new OpenFileDialog
        {
            Title = "분석할 PowerShell 스크립트 선택",
            Filter = "스크립트/텍스트 (*.ps1;*.psm1;*.txt;*.bat;*.cmd;*.vbs;*.log;*.xml)|*.ps1;*.psm1;*.txt;*.bat;*.cmd;*.vbs;*.log;*.xml|모든 파일 (*.*)|*.*",
        };
        if (initialDir != null) dlg.InitialDirectory = initialDir;
        if (dlg.ShowDialog(this) == true) await OpenFileAsync(dlg.FileName);
    }

    static string FindSampleFolder()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 7 && dir != null; i++, dir = dir.Parent)
        {
            var s = Path.Combine(dir.FullName, "sample");
            if (Directory.Exists(s)) return s;
        }
        return null;
    }

    async void OnPasteClick(object sender, RoutedEventArgs e)
    {
        string text = null;
        try { if (Clipboard.ContainsText()) text = Clipboard.GetText(); } catch { }
        if (string.IsNullOrWhiteSpace(text))
        {
            SetStatus("클립보드에 텍스트가 없습니다.", true);
            return;
        }
        await AnalyzeAsync(text, "(클립보드)", "", Encoding.UTF8.GetBytes(text));
    }

    async void OnReanalyzeClick(object sender, RoutedEventArgs e)
    {
        if (_text != null) await AnalyzeAsync(_text, _name, _path, _bytes);
    }

    void OnExportClick(object sender, RoutedEventArgs e)
    {
        ExportMenu.PlacementTarget = ExportButton;
        ExportMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        ExportMenu.IsOpen = true;
    }

    string BaseName => Path.GetFileNameWithoutExtension(_result?.File.Name ?? "analysis").Trim('(', ')');

    void SaveWithDialog(string defaultName, string filter, Func<string> content, Encoding enc = null)
    {
        if (_result == null) return;
        var dlg = new SaveFileDialog { FileName = defaultName, Filter = filter };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            File.WriteAllText(dlg.FileName, content(), enc ?? new UTF8Encoding(false));
            SetStatus("저장했습니다: " + dlg.FileName);
        }
        catch (Exception ex)
        {
            SetStatus("저장 실패: " + ex.Message, true);
        }
    }

    void OnExportHtml(object sender, RoutedEventArgs e) =>
        SaveWithDialog($"{BaseName}_report.html", "HTML 보고서 (*.html)|*.html", () => ReportExporter.ToHtml(_result));

    void OnExportJson(object sender, RoutedEventArgs e) =>
        SaveWithDialog($"{BaseName}_result.json", "JSON (*.json)|*.json", () => ReportExporter.ToJson(_result));

    void OnExportCsv(object sender, RoutedEventArgs e) =>
        SaveWithDialog($"{BaseName}_ioc.csv", "CSV (*.csv)|*.csv", () => ReportExporter.ToIocCsv(_result), new UTF8Encoding(true));

    void OnExportText(object sender, RoutedEventArgs e) =>
        SaveWithDialog($"{BaseName}_report.txt", "텍스트 (*.txt)|*.txt", () => ReportExporter.ToText(_result));

    void OnExportScript(object sender, RoutedEventArgs e) =>
        SaveWithDialog($"{BaseName}_deobfuscated.txt", "텍스트 (*.txt)|*.txt", () =>
            "# [PS Deobfuscator] 복호화된 최종 레이어 — 분석용 텍스트입니다. 절대 실행하지 마세요.\r\n" +
            $"# 원본: {_result.File.Name}  SHA256: {_result.File.Sha256}\r\n# 레이어: L{_result.FinalLayer.Depth} {_result.FinalLayer.Method}\r\n\r\n" +
            _result.FinalLayer.CleanContent);

    void OnSaveLayerClick(object sender, RoutedEventArgs e)
    {
        if (_layer == null) return;
        if (_layer.IsBinary && _layer.Bytes != null)
        {
            if (MessageBox.Show(this, "추출된 바이너리 페이로드는 실제 악성코드일 수 있습니다.\n실행되지 않도록 .bin 확장자로 저장합니다. 계속할까요?",
                    "페이로드 저장", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            var dlg = new SaveFileDialog { FileName = $"{BaseName}_L{_layer.Depth}_payload.bin", Filter = "바이너리 (*.bin)|*.bin" };
            if (dlg.ShowDialog(this) == true)
            {
                File.WriteAllBytes(dlg.FileName, _layer.Bytes);
                SetStatus("페이로드를 저장했습니다: " + dlg.FileName);
            }
            return;
        }
        var text = Editor.Text;
        SaveWithDialog($"{BaseName}_L{_layer.Depth}.txt", "텍스트 (*.txt)|*.txt", () => text);
    }

    void OnCopyCodeClick(object sender, RoutedEventArgs e) => CopyText(Editor.Text, "코드를 복사했습니다.");

    void OnFindClick(object sender, RoutedEventArgs e)
    {
        _search.Open();
        _search.Reactivate();
    }

    void OnCopyHashClick(object sender, RoutedEventArgs e)
    {
        if (_result == null) return;
        CopyText($"SHA256: {_result.File.Sha256}\r\nSHA1: {_result.File.Sha1}\r\nMD5: {_result.File.Md5}", "해시를 복사했습니다.");
    }

    void OnVirusTotalHashClick(object sender, RoutedEventArgs e)
    {
        if (_result != null) OpenVirusTotal(_result.File.Sha256);
    }

    void OnOpenUrlTag(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is string url && url.StartsWith("https://attack.mitre.org/")) OpenUrl(url);
    }

    void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { SetStatus("브라우저를 열 수 없습니다: " + ex.Message, true); }
    }

    void CopyText(string text, string msg)
    {
        try
        {
            Clipboard.SetDataObject(text ?? "", true);
            SetStatus(msg);
        }
        catch (Exception ex)
        {
            SetStatus("클립보드 사용 실패: " + ex.Message, true);
        }
    }

    #endregion

    #region 화면 배율

    void OnZoomChanged(double level)
    {
        ZoomText.Text = UiZoom.Percent;
        ZoomToastText.Text = UiZoom.Percent;
        // 잠깐 보였다가 사라지는 안내
        var fade = new DoubleAnimationUsingKeyFrames();
        fade.KeyFrames.Add(new LinearDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(80))));
        fade.KeyFrames.Add(new LinearDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(700))));
        fade.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(1000))));
        ZoomToast.BeginAnimation(OpacityProperty, fade);
    }

    void OnZoomIn(object sender, RoutedEventArgs e) => UiZoom.ZoomIn();
    void OnZoomOut(object sender, RoutedEventArgs e) => UiZoom.ZoomOut();
    void OnZoomReset(object sender, RoutedEventArgs e) => UiZoom.Reset();

    #endregion

    #region 창/드래그/단축키

    void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    void OnMaximize(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    void OnClose(object sender, RoutedEventArgs e) => Close();

    void OnStateChanged(object sender, EventArgs e)
    {
        // 최대화 시 화면 밖으로 잘리는 테두리 보정
        RootGrid.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
        MaxButton.Content = WindowState == WindowState.Maximized ? "" : "";
    }

    void OnDragEnter(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            DropOverlay.Visibility = Visibility.Visible;
            e.Effects = DragDropEffects.Copy;
        }
        else e.Effects = DragDropEffects.None;
        e.Handled = true;
    }

    void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    void OnDragLeave(object sender, DragEventArgs e)
    {
        // 자식 요소 사이 이동 시 깜빡임 방지: 창 밖으로 나갔을 때만 숨김
        var p = e.GetPosition(this);
        if (p.X <= 0 || p.Y <= 0 || p.X >= ActualWidth || p.Y >= ActualHeight) DropOverlay.Visibility = Visibility.Collapsed;
    }

    async void OnDrop(object sender, DragEventArgs e)
    {
        DropOverlay.Visibility = Visibility.Collapsed;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0 && File.Exists(files[0]))
            await OpenFileAsync(files[0]);
    }

    void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        var mods = Keyboard.Modifiers;
        if (e.Key == Key.O && mods == ModifierKeys.Control) { OnOpenClick(sender, e); e.Handled = true; }
        else if (e.Key == Key.V && mods == (ModifierKeys.Control | ModifierKeys.Shift)) { OnPasteClick(sender, e); e.Handled = true; }
        else if (e.Key == Key.F5) { OnReanalyzeClick(sender, e); e.Handled = true; }
        else if (e.Key == Key.F && mods == ModifierKeys.Control) { OnFindClick(sender, e); e.Handled = true; }
    }

    #endregion
}
