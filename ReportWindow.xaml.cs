using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace PsDeobfuscator;

/// <summary>규칙 자체 테스트·회귀 테스트 결과를 보여 주는 창.</summary>
public partial class ReportWindow : Window
{
    readonly string _defaultName;

    public ReportWindow(string title, bool ok, string badge, string head, string sub, string body, string defaultFileName)
    {
        InitializeComponent();
        UiZoom.Attach(this, Root);
        Title = title;
        _defaultName = defaultFileName;
        BadgeText.Text = badge;
        Badge.Background = (Brush)FindResource(ok ? "SafeBrush" : "CriticalBrush");
        HeadText.Text = head;
        SubText.Text = sub;
        Body.Text = body;
        Body.Options.EnableHyperlinks = false;
    }

    void OnCopy(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetDataObject(Body.Text, true); } catch { }
    }

    void OnSave(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog { FileName = _defaultName, Filter = "텍스트 (*.txt)|*.txt" };
        if (dlg.ShowDialog(this) == true) File.WriteAllText(dlg.FileName, Body.Text, new UTF8Encoding(true));
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}
