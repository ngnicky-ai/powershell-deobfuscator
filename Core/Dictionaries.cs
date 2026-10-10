namespace PsDeobfuscator.Core;

/// <summary>이름 정규화와 명령어 설명에 쓰이는 사전.</summary>
public static class Dictionaries
{
    static readonly string[] CmdletList =
    {
        "New-Object","New-Item","Get-Item","Get-ChildItem","Invoke-Item","Invoke-Expression","Invoke-Command","Invoke-WebRequest",
        "Invoke-RestMethod","Start-Process","Stop-Process","Get-Process","Start-Sleep","Set-Content","Add-Content","Get-Content",
        "Out-File","Out-Null","Out-String","Write-Host","Write-Output","Remove-Item","Copy-Item","Move-Item","Rename-Item",
        "Test-Path","Join-Path","Split-Path","Resolve-Path","Set-ItemProperty","Get-ItemProperty","New-ItemProperty","Remove-ItemProperty",
        "Get-WmiObject","Get-CimInstance","Invoke-WmiMethod","Invoke-CimMethod","Register-ScheduledTask","New-ScheduledTaskAction",
        "New-ScheduledTaskTrigger","Unregister-ScheduledTask","Set-MpPreference","Add-MpPreference","Get-MpPreference","Set-ExecutionPolicy",
        "Expand-Archive","Compress-Archive","Start-BitsTransfer","ConvertTo-SecureString","ConvertFrom-SecureString","Add-Type",
        "Get-Variable","Set-Variable","New-Variable","Clear-History","Clear-EventLog","Get-Random","ForEach-Object","Where-Object",
        "Select-Object","Sort-Object","Measure-Object","Get-Date","Get-Service","Stop-Service","New-Service","Set-Service",
        "Get-NetIPAddress","Get-Clipboard","Set-Clipboard","Import-Module","Get-Command","Get-Host","Get-Culture","Get-ComputerInfo",
        "Unblock-File","Set-Location","Get-Location","Restart-Computer","Stop-Computer","ConvertTo-Json","ConvertFrom-Json",
        "ConvertTo-Base64","Get-FileHash","Send-MailMessage","Invoke-Item","Register-WmiEvent","Set-WmiInstance","Get-LocalUser",
        "New-LocalUser","Add-LocalGroupMember","Enable-PSRemoting","Set-Item","Write-Error","Wait-Process","Get-Acl","Set-Acl",
    };

    public static readonly Dictionary<string, string> Cmdlets =
        CmdletList.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(x => x, x => x, StringComparer.OrdinalIgnoreCase);

    public static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["iex"] = "Invoke-Expression", ["icm"] = "Invoke-Command", ["iwr"] = "Invoke-WebRequest", ["irm"] = "Invoke-RestMethod",
        ["ii"] = "Invoke-Item", ["saps"] = "Start-Process", ["start"] = "Start-Process", ["ni"] = "New-Item", ["gi"] = "Get-Item",
        ["gci"] = "Get-ChildItem", ["ls"] = "Get-ChildItem", ["dir"] = "Get-ChildItem", ["sc"] = "Set-Content", ["ac"] = "Add-Content",
        ["gc"] = "Get-Content", ["cat"] = "Get-Content", ["type"] = "Get-Content", ["rm"] = "Remove-Item", ["del"] = "Remove-Item",
        ["ri"] = "Remove-Item", ["erase"] = "Remove-Item", ["rd"] = "Remove-Item", ["cp"] = "Copy-Item", ["copy"] = "Copy-Item",
        ["cpi"] = "Copy-Item", ["mv"] = "Move-Item", ["move"] = "Move-Item", ["mi"] = "Move-Item", ["sleep"] = "Start-Sleep",
        ["gwmi"] = "Get-WmiObject", ["gcim"] = "Get-CimInstance", ["gps"] = "Get-Process", ["ps"] = "Get-Process", ["kill"] = "Stop-Process",
        ["spps"] = "Stop-Process", ["gv"] = "Get-Variable", ["sv"] = "Set-Variable", ["nv"] = "New-Variable", ["sp"] = "Set-ItemProperty",
        ["gp"] = "Get-ItemProperty", ["%"] = "ForEach-Object", ["foreach"] = "ForEach-Object", ["?"] = "Where-Object", ["where"] = "Where-Object",
        ["select"] = "Select-Object", ["sort"] = "Sort-Object", ["echo"] = "Write-Output", ["write"] = "Write-Output", ["cd"] = "Set-Location",
        ["sl"] = "Set-Location", ["pwd"] = "Get-Location", ["ipmo"] = "Import-Module", ["gcm"] = "Get-Command", ["si"] = "Set-Item",
        ["curl"] = "Invoke-WebRequest", ["wget"] = "Invoke-WebRequest", ["measure"] = "Measure-Object", ["clhy"] = "Clear-History",
    };

    static readonly string[] MemberList =
    {
        "DownloadFile","DownloadString","DownloadData","DownloadFileAsync","OpenRead","UploadString","UploadFile","UploadData",
        "Replace","Split","Substring","ToLower","ToUpper","Trim","TrimStart","TrimEnd","ToCharArray","ToString","Length","Count",
        "Invoke","InvokeScript","NewScriptBlock","InvokeCommand","GetString","GetBytes","FromBase64String","ToBase64String",
        "SecurityProtocol","Headers","Proxy","Credentials","UseDefaultCredentials","Encoding","ReadToEnd","CopyTo","ToArray",
        "Create","Load","GetType","GetMethod","GetField","GetValue","SetValue","EntryPoint","Name","Value","Path","Start",
        "Contains","StartsWith","EndsWith","IndexOf","Insert","Remove","PadLeft","Join","Reverse","Matches","Write","Close","Dispose",
        "CreateDecryptor","TransformFinalBlock","Key","IV","Mode","Padding","Run","ExpandEnvironmentStrings","CurrentDirectory",
    };

    static readonly Dictionary<string, string> Members =
        MemberList.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(x => x, x => x, StringComparer.OrdinalIgnoreCase);

    public static string CanonicalMember(string name) => Members.TryGetValue(name, out var c) ? c : null;

    static readonly string[] TypeList =
    {
        "Net.ServicePointManager","System.Net.ServicePointManager","Net.WebClient","System.Net.WebClient","Net.SecurityProtocolType",
        "System.Net.SecurityProtocolType","Convert","System.Convert","Text.Encoding","System.Text.Encoding","String","string","Char","char",
        "int","byte","byte[]","char[]","string[]","object[]","ScriptBlock","scriptblock","System.Management.Automation.ScriptBlock",
        "Reflection.Assembly","System.Reflection.Assembly","IO.File","System.IO.File","IO.MemoryStream","System.IO.MemoryStream",
        "IO.StreamReader","System.IO.StreamReader","IO.Compression.DeflateStream","System.IO.Compression.DeflateStream",
        "IO.Compression.GZipStream","System.IO.Compression.GZipStream","IO.Compression.CompressionMode","System.IO.Compression.CompressionMode",
        "Runtime.InteropServices.Marshal","System.Runtime.InteropServices.Marshal","Environment","System.Environment","Array","Math",
        "Regex","Text.RegularExpressions.Regex","System.Text.RegularExpressions.Regex","void","IO.Path","System.IO.Path","Diagnostics.Process",
        "System.Diagnostics.Process","Security.Cryptography.AesManaged","System.Security.Cryptography.AesManaged","bool","double","long",
    };

    static readonly Dictionary<string, string> Types =
        TypeList.GroupBy(x => x, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

    public static string CanonicalType(string name) => Types.TryGetValue(name.Trim(), out var c) ? c : null;

}
