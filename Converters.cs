using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using PsDeobfuscator.Core;

namespace PsDeobfuscator;

public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value is Severity s
            ? s switch
            {
                Severity.Critical => "CriticalBrush",
                Severity.High => "HighBrush",
                Severity.Medium => "MediumBrush",
                Severity.Low => "LowBrush",
                _ => "InfoBrush"
            }
            : "InfoBrush";
        return Application.Current.Resources[key];
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class BoolToVisConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool b = value is bool v && v;
        if (parameter as string == "invert") b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>진단 항목 색: GapKind 또는 bool(해독 실패 의심 여부). parameter="bg" 면 반투명 배경.</summary>
public sealed class DiagBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var c = value switch
        {
            GapKind.NeedsEngine => Color.FromRgb(0xFF, 0x8C, 0x42),
            GapKind.Limit => Color.FromRgb(0xF7, 0xC9, 0x48),
            GapKind.Environment => Color.FromRgb(0x8D, 0x99, 0xAE),
            GapKind.Cascade => Color.FromRgb(0x6B, 0x72, 0x9C),
            true => Color.FromRgb(0xFF, 0x8C, 0x42),
            false => Color.FromRgb(0x4C, 0xC9, 0xF0),
            _ => Color.FromRgb(0x8D, 0x99, 0xAE),
        };
        if (parameter as string == "bg") c = Color.FromArgb(0x30, c.R, c.G, c.B);
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class NonEmptyToVis : IValueConverter
{
    public static readonly NonEmptyToVis Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.IsNullOrEmpty(value as string) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

public sealed class IocTypeBrushConverter : IValueConverter
{
    static readonly Dictionary<string, Color> Colors = new()
    {
        ["URL"] = Color.FromRgb(0xFF, 0x6B, 0x9A),
        ["도메인"] = Color.FromRgb(0xFF, 0x8C, 0x42),
        ["IP"] = Color.FromRgb(0xF7, 0xC9, 0x48),
        ["채굴 풀"] = Color.FromRgb(0xFF, 0x4D, 0x6D),
        ["지갑/계정"] = Color.FromRgb(0xC7, 0x7D, 0xFF),
        ["레지스트리"] = Color.FromRgb(0x4C, 0xC9, 0xF0),
        ["파일 경로"] = Color.FromRgb(0x2E, 0xC4, 0xB6),
        ["파일명"] = Color.FromRgb(0x80, 0xED, 0x99),
        ["이메일"] = Color.FromRgb(0xA0, 0xC4, 0xFF),
        ["해시(SHA256)"] = Color.FromRgb(0xB8, 0xB8, 0xD1),
    };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var c = value is string s && Colors.TryGetValue(s, out var col) ? col : Color.FromRgb(0x8D, 0x99, 0xAE);
        if (parameter as string == "bg") c = Color.FromArgb(0x33, c.R, c.G, c.B);
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
