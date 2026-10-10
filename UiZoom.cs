using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace PsDeobfuscator;

/// <summary>
/// 화면 전체 확대/축소. Ctrl+마우스 휠, Ctrl + '+' / '-' / '0' 으로 조절하며
/// 모든 창이 같은 배율을 공유하고, 마지막 배율은 %APPDATA%\PsDeobfuscator\settings.json 에 저장된다.
/// </summary>
public static class UiZoom
{
    public const double Min = 0.7, Max = 2.5, Step = 0.1;

    static double _level = Load();

    /// <summary>배율이 바뀔 때 (새 배율)</summary>
    public static event Action<double> Changed;

    public static double Level
    {
        get => _level;
        set
        {
            var v = Math.Round(Math.Clamp(value, Min, Max), 2);
            if (Math.Abs(v - _level) < 0.001) return;
            _level = v;
            Save();
            Changed?.Invoke(v);
        }
    }

    public static string Percent => $"{Math.Round(_level * 100):0}%";

    public static void ZoomIn() => Level = _level + Step;
    public static void ZoomOut() => Level = _level - Step;
    public static void Reset() => Level = 1.0;

    /// <summary>창에 확대/축소를 연결한다. target 에 배율을 적용하고 입력을 가로챈다.</summary>
    public static void Attach(Window window, FrameworkElement target)
    {
        void Apply(double z) => target.LayoutTransform = new ScaleTransform(z, z);
        Apply(_level);
        Changed += Apply;
        window.Closed += (_, _) => Changed -= Apply;

        // 터널링 이벤트라 코드 편집기·스크롤 영역보다 먼저 받는다
        window.PreviewMouseWheel += (_, e) =>
        {
            if (Keyboard.Modifiers != ModifierKeys.Control) return;
            if (e.Delta > 0) ZoomIn(); else if (e.Delta < 0) ZoomOut();
            e.Handled = true;
        };
        window.PreviewKeyDown += (_, e) =>
        {
            if (Keyboard.Modifiers != ModifierKeys.Control) return;
            switch (e.Key)
            {
                case Key.OemPlus or Key.Add: ZoomIn(); e.Handled = true; break;
                case Key.OemMinus or Key.Subtract: ZoomOut(); e.Handled = true; break;
                case Key.D0 or Key.NumPad0: Reset(); e.Handled = true; break;
            }
        };
    }

    #region 설정 저장

    static string SettingsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PsDeobfuscator", "settings.json");

    sealed class Settings
    {
        public double Zoom { get; set; } = 1.0;
    }

    static double Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var s = JsonSerializer.Deserialize<Settings>(File.ReadAllText(SettingsPath));
                if (s != null && s.Zoom >= Min && s.Zoom <= Max) return s.Zoom;
            }
        }
        catch { }
        return 1.0;
    }

    static void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new Settings { Zoom = _level }));
        }
        catch { }
    }

    #endregion
}
