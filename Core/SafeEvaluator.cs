using System.Collections;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.IO.Compression;
using System.Management.Automation.Language;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

#region 값/신호 타입

public sealed class UnsupportedException : Exception
{
    public UnsupportedException(string msg) : base(msg) { }
}
public sealed class BudgetExceededException : Exception
{
    public BudgetExceededException() : base("evaluation budget exceeded") { }
}
sealed class BreakSignal : Exception { }
sealed class ContinueSignal : Exception { }
sealed class ReturnSignal : Exception { }

public sealed class ScriptBlockValue
{
    public ScriptBlockAst Ast { get; init; }
    public string Text { get; init; } = "";
    public bool FromDynamicCode { get; init; }
    public override string ToString() => Text;
}

public sealed class TypeRef
{
    public string Name { get; init; } = "";
    public override string ToString() => Name;
}

public sealed class VarInfo
{
    public string Name { get; set; } = "";
    public object Value { get; set; }
    public override string ToString() => Name;
}

public sealed class SecureStringValue
{
    public string Plain { get; init; } = "";
    public override string ToString() => "System.Security.SecureString";
}

public sealed class NetworkCredentialValue
{
    public string UserName { get; set; } = "";
    public string Password { get; set; } = "";
}

/// <summary>네트워크/실행 계열 객체는 실제로 만들지 않고 자리표시자로만 둔다.</summary>
public sealed class StubObject
{
    public string TypeName { get; init; } = "";
    public override string ToString() => TypeName;
}

sealed class ExecContextStub { }

#endregion

/// <summary>
/// PowerShell AST를 '안전하게' 해석하는 인터프리터.
/// 문자열/수치 연산, Base64·압축·AES 같은 순수 메모리 연산만 실제로 수행하고,
/// 코드 실행(iex, ScriptBlock::Create 등)·파일 쓰기·네트워크는 수행하지 않고 내용을 캡처만 한다.
/// </summary>
public sealed class SafeEvaluator
{
    public List<CapturedPayload> Captures { get; } = new();
    readonly HashSet<string> _captureKeys = new();

    /// <summary>true면 환경변수를 $env:NAME 마커로 남긴다 (정리 출력용).</summary>
    public bool FoldMode { get; set; }
    public long MaxSteps { get; set; } = 6_000_000;
    public const char EnvStart = '\u0001', EnvEnd = '\u0002';

    long _steps;
    readonly List<Dictionary<string, object>> _scopes = new();
    readonly Dictionary<string, FunctionDefinitionAst> _functions = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, object> _virtualFs = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, object> _readOnlyVars;
    const int MaxLoop = 500_000;
    const int MaxString = 30_000_000;

    static SafeEvaluator()
    {
        try { Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); } catch { }
    }

    public SafeEvaluator()
    {
        _scopes.Add(new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase));
        _readOnlyVars = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["true"] = true,
            ["false"] = false,
            ["null"] = null,
            ["ShellId"] = "Microsoft.PowerShell",
            ["PSHome"] = @"C:\Windows\System32\WindowsPowerShell\v1.0",
            ["VerbosePreference"] = "SilentlyContinue",
            ["DebugPreference"] = "SilentlyContinue",
            ["ErrorActionPreference"] = "Continue",
            ["WarningPreference"] = "Continue",
            ["ProgressPreference"] = "Continue",
            ["ConfirmPreference"] = "High",
            ["MaximumDriveCount"] = 4096L,
            ["MaximumHistoryCount"] = 4096L,
            ["MaximumFunctionCount"] = 4096L,
            ["MaximumVariableCount"] = 4096L,
            ["MaximumAliasCount"] = 4096L,
            ["MaximumErrorCount"] = 256L,
            ["OFS"] = " ",
            ["PSCulture"] = "ko-KR",
            ["PSUICulture"] = "ko-KR",
            ["NestedPromptLevel"] = 0L,
            ["PSScriptRoot"] = "",
            ["PSCommandPath"] = "",
            ["HOME"] = "%USERPROFILE%",
            ["PID"] = 4242L,
        };
    }

    #region 진입점

    public static ScriptBlockAst Parse(string script, out Token[] tokens, out ParseError[] errors)
        => Parser.ParseInput(script, out tokens, out errors);

    public void Run(ScriptBlockAst ast)
    {
        try
        {
            RunScriptBlockBody(ast, new List<object>(), null, false);
        }
        catch (BudgetExceededException)
        {
            BudgetHit = true;
            RecordGap(Cancel ? "limit time" : "limit steps", null);
        }
        catch (ReturnSignal) { }
        catch (BreakSignal) { }
        catch (ContinueSignal) { }
    }

    /// <summary>정리기에서 사용: 부작용 없는 표현식 하나만 평가한다.</summary>
    public bool TryEvalPure(ExpressionAst expr, out object value)
    {
        value = null;
        try
        {
            value = Eval(expr);
            return true;
        }
        catch (Exception ex) when (ex is not StackOverflowException)
        {
            return false;
        }
    }

    public void SetVariable(string name, object value) => _scopes[0][name] = value;

    #endregion

    #region 캡처

    void Capture(string kind, string text, string note = "")
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        var key = kind + "\0" + text.GetHashCode();
        if (!_captureKeys.Add(key)) return;
        Captures.Add(new CapturedPayload { Kind = kind, Text = text, Note = note });
    }

    void CaptureBytes(string kind, byte[] bytes, string note = "")
    {
        if (bytes == null || bytes.Length == 0) return;
        var key = kind + "\0b" + Convert.ToBase64String(SHA1.HashData(bytes));
        if (!_captureKeys.Add(key)) return;
        Captures.Add(new CapturedPayload { Kind = kind, Bytes = bytes, Note = note });
    }

    void CaptureDecoded(string kind, string s)
    {
        if (s == null || s.Length < 12) return;
        if (CommandLineUnwrapper.Printable(s) < 0.9) return;
        Capture(kind, s);
    }

    #endregion

    #region 스코프

    public volatile bool Cancel;

    void Step()
    {
        if (++_steps > MaxSteps || Cancel) throw new BudgetExceededException();
    }

    void PushScope() => _scopes.Add(new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase));
    void PopScope() => _scopes.RemoveAt(_scopes.Count - 1);

    bool TryGetVar(string name, out object value)
    {
        for (int i = _scopes.Count - 1; i >= 0; i--)
            if (_scopes[i].TryGetValue(name, out value)) return true;
        if (_readOnlyVars.TryGetValue(name, out value)) return true;
        value = null;
        return false;
    }

    /// <summary>평가 중 변수에 대입된 문자열 (IOC 추출용: URL/경로 등이 런타임에만 완성되는 경우).</summary>
    public HashSet<string> ObservedStrings { get; } = new();

    void SetVar(string name, object value, bool global = false)
    {
        if (value is string s && s.Length > MaxString) throw new UnsupportedException("string too large");
        if (global) _scopes[0][name] = value;
        else _scopes[^1][name] = value;
    }

    object GetVariable(VariableExpressionAst v)
    {
        var path = v.VariablePath;
        var name = path.VarName();
        if (path.IsDriveQualified)
        {
            var drive = path.DriveName;
            if (drive.Equals("env", StringComparison.OrdinalIgnoreCase)) return EnvValue(name);
            if (drive.Equals("variable", StringComparison.OrdinalIgnoreCase))
            {
                if (TryGetVar(name, out var vv) && vv is not UnknownValue) return vv;
            }
            throw new UnsupportedException("drive variable " + path.UserPath);
        }
        if (name.Equals("ExecutionContext", StringComparison.OrdinalIgnoreCase)) return new ExecContextStub();
        if (name.Equals("args", StringComparison.OrdinalIgnoreCase) && !TryGetVar("args", out _)) return Array.Empty<object>();
        if (name == "_" || name.Equals("PSItem", StringComparison.OrdinalIgnoreCase))
        {
            if (TryGetVar("_", out var u)) return u;
        }
        if (TryGetVar(name, out var val))
        {
            if (val is UnknownValue) throw new UnsupportedException("unknown value $" + name);
            return val;
        }
        // 한 번도 대입되지 않은 변수는 PowerShell 처럼 $null (정리기 모드에서는 알 수 없음으로 취급)
        if (!FoldMode) return null;
        throw new UnsupportedException("unknown variable $" + name);
    }

    /// <summary>대입은 있었지만 값을 계산하지 못한 변수 (예: 네트워크 응답).</summary>
    sealed class UnknownValue
    {
        public static readonly UnknownValue Instance = new();
    }

    public object EnvValue(string name)
    {
        switch (name.ToLowerInvariant())
        {
            case "comspec": return @"C:\WINDOWS\system32\cmd.exe";
            case "windir":
            case "systemroot": return FoldMode ? EnvMarker(name) : @"C:\WINDOWS";
            case "public": return FoldMode ? EnvMarker(name) : @"C:\Users\Public";
            case "programdata":
            case "allusersprofile": return FoldMode ? EnvMarker(name) : @"C:\ProgramData";
            case "systemdrive": return "C:";
            case "processor_architecture": return "AMD64";
            case "os": return "Windows_NT";
        }
        if (FoldMode) return EnvMarker(name);
        return "%" + name.ToUpperInvariant() + "%";
    }

    static string EnvMarker(string name) => EnvStart + name + EnvEnd;

    #endregion

    #region 문장 실행

    void RunScriptBlockBody(ScriptBlockAst sb, List<object> output, object dollarUnder, bool setUnder)
    {
        if (setUnder) SetVar("_", dollarUnder);
        if (sb.BeginBlock != null) ExecStatements(sb.BeginBlock.Statements, output);
        if (sb.ProcessBlock != null) ExecStatements(sb.ProcessBlock.Statements, output);
        if (sb.EndBlock != null) ExecStatements(sb.EndBlock.Statements, output);
    }

    void ExecStatements(IEnumerable<StatementAst> statements, List<object> output)
    {
        // 함수 정의는 먼저 등록 (PowerShell은 사용 전 정의가 필요하지만, 관대하게 처리)
        foreach (var st in statements)
            if (st is FunctionDefinitionAst f) _functions[f.Name] = f;

        foreach (var st in statements)
        {
            try
            {
                ExecStatement(st, output);
            }
            catch (UnsupportedException ex) { RecordGap(ex.Message, st); }
            catch (BudgetExceededException) { throw; }
            catch (BreakSignal) { throw; }
            catch (ContinueSignal) { throw; }
            catch (ReturnSignal) { throw; }
            catch (Exception ex) when (ex is FormatException or InvalidCastException or IndexOutOfRangeException
                                       or ArgumentException or OverflowException or InvalidOperationException
                                       or CryptographicException or InvalidDataException or IOException
                                       or NullReferenceException or DivideByZeroException or TargetInvocationException
                                       or RegexMatchTimeoutException or NotSupportedException or OutOfMemoryException
                                       or KeyNotFoundException or DecoderFallbackException)
            {
                var inner = ex is TargetInvocationException { InnerException: { } ie } ? ie : ex;
                RecordGap("runtime " + inner.GetType().Name + ": " + inner.Message, st);
            }
        }
    }

    #region 미지원 항목 기록

    /// <summary>원인별로 모은 엔진 미지원 항목 (키: 분류+원인)</summary>
    public Dictionary<string, EngineGap> Gaps { get; } = new();
    public bool BudgetHit { get; private set; }

    void RecordGap(string message, Ast where)
    {
        if (FoldMode) return;
        var (kind, detail) = EngineDiagnostics.Classify(message);
        var key = (int)kind + "|" + detail;
        if (!Gaps.TryGetValue(key, out var g))
        {
            if (Gaps.Count >= 500) return;
            var ex = where?.Extent.Text ?? "";
            ex = ex.Replace("\r", " ").Replace("\n", " ");
            if (ex.Length > 200) ex = ex[..200] + "…";
            g = Gaps[key] = new EngineGap { Kind = kind, Detail = detail, Example = ex };
        }
        g.Count++;
    }

    #endregion

    void ExecStatement(StatementAst st, List<object> output)
    {
        Step();
        switch (st)
        {
            case FunctionDefinitionAst f:
                _functions[f.Name] = f;
                return;
            case AssignmentStatementAst a:
                ExecAssignment(a);
                return;
            case PipelineAst p:
                output.AddRange(RunPipeline(p, null));
                return;
            case CommandExpressionAst cex:
                {
                    var v = Eval(cex.Expression);
                    if (v != null && !IsVoidCast(cex.Expression)) output.AddRange(EnumeratePipeline(v));
                    return;
                }
            case IfStatementAst iff:
                ExecIf(iff, output);
                return;
            case ForStatementAst fo:
                ExecFor(fo, output);
                return;
            case ForEachStatementAst fe:
                ExecForEach(fe, output);
                return;
            case WhileStatementAst wh:
                ExecWhile(wh.Condition, wh.Body, output, false, true);
                return;
            case DoWhileStatementAst dw:
                ExecWhile(dw.Condition, dw.Body, output, true, true);
                return;
            case DoUntilStatementAst du:
                ExecWhile(du.Condition, du.Body, output, true, false);
                return;
            case TryStatementAst tr:
                try { ExecStatements(tr.Body.Statements, output); }
                finally { if (tr.Finally != null) ExecStatements(tr.Finally.Statements, output); }
                return;
            case ReturnStatementAst r:
                if (r.Pipeline != null) output.AddRange(EvalPipelineOutput(r.Pipeline));
                throw new ReturnSignal();
            case BreakStatementAst:
                throw new BreakSignal();
            case ContinueStatementAst:
                throw new ContinueSignal();
            case ExitStatementAst:
                return; // 분석 목적상 계속 진행
            case SwitchStatementAst sw:
                ExecSwitch(sw, output);
                return;
            case TrapStatementAst:
                return;
            case PipelineBaseAst pb:
                output.AddRange(EvalPipelineOutput(pb));
                return;
            default:
                throw new UnsupportedException(st.GetType().Name);
        }
    }

    void ExecIf(IfStatementAst iff, List<object> output)
    {
        foreach (var clause in iff.Clauses)
        {
            bool cond;
            try
            {
                cond = ToBool(CollectPipeline(clause.Item1));
            }
            catch (UnsupportedException ex)
            {
                RecordGap(ex.Message, clause.Item1);
                // 조건을 알 수 없으면 모든 분기를 추측 실행하여 페이로드를 최대한 찾는다
                foreach (var c in iff.Clauses) SafeExecBlock(c.Item2, output);
                if (iff.ElseClause != null) SafeExecBlock(iff.ElseClause, output);
                return;
            }
            if (cond)
            {
                ExecStatements(clause.Item2.Statements, output);
                return;
            }
        }
        if (iff.ElseClause != null) ExecStatements(iff.ElseClause.Statements, output);
    }

    /// <summary>
    /// switch 문. PowerShell 의미론: 입력이 배열이면 원소마다 평가, 일치하는 모든 절을 실행,
    /// 절 안의 break 는 switch 만 끝내고 continue 는 다음 원소로 넘어간다 (바깥 반복문에 영향 없음).
    /// -Wildcard / -Regex / -CaseSensitive / -Exact 지원, 스크립트 블록 조건 지원.
    /// </summary>
    void ExecSwitch(SwitchStatementAst sw, List<object> output)
    {
        var flags = sw.Flags;
        if (flags.HasFlag(SwitchFlags.File)) throw new UnsupportedException("switch -File");
        bool cs = flags.HasFlag(SwitchFlags.CaseSensitive);
        var input = CollectPipeline(sw.Condition);
        var items = input is IEnumerable && input is not string && input is not Hashtable ? Enumerate(input).ToList() : new List<object> { input };
        int n = 0;
        foreach (var item in items)
        {
            if (++n > MaxLoop) throw new UnsupportedException("loop limit");
            SetVar("_", item);
            bool matched = false;
            try
            {
                foreach (var clause in sw.Clauses)
                {
                    if (!SwitchMatches(clause.Item1, item, flags, cs)) continue;
                    matched = true;
                    ExecStatements(clause.Item2.Statements, output);
                }
                if (!matched && sw.Default != null) ExecStatements(sw.Default.Statements, output);
            }
            catch (BreakSignal) { break; }
            catch (ContinueSignal) { }
        }
    }

    bool SwitchMatches(ExpressionAst cond, object item, SwitchFlags flags, bool cs)
    {
        if (cond is ScriptBlockExpressionAst sbe)
        {
            var o = new List<object>();
            RunScriptBlockBody(sbe.ScriptBlock, o, item, true);
            return ToBool(Unwrap(o));
        }
        var pattern = EvalArgument(cond);
        var s = ToStr(item);
        if (flags.HasFlag(SwitchFlags.Regex))
            return Regex.IsMatch(s, ToStr(pattern), cs ? RegexOptions.None : RegexOptions.IgnoreCase);
        if (flags.HasFlag(SwitchFlags.Wildcard))
            return WildcardToRegex(ToStr(pattern), cs).IsMatch(s);
        return Compare(item, pattern, cs) == 0;
    }

    void SafeExecBlock(StatementBlockAst b, List<object> output)
    {
        try { ExecStatements(b.Statements, output); }
        catch (BreakSignal) { }
        catch (ContinueSignal) { }
    }

    void ExecFor(ForStatementAst fo, List<object> output)
    {
        if (fo.Initializer != null) ExecStatement(fo.Initializer, new List<object>());
        int n = 0;
        while (true)
        {
            if (fo.Condition != null && !ToBool(CollectPipeline(fo.Condition))) break;
            if (++n > MaxLoop) throw new UnsupportedException("loop limit");
            try { ExecStatements(fo.Body.Statements, output); }
            catch (BreakSignal) { break; }
            catch (ContinueSignal) { }
            if (fo.Iterator != null) ExecStatement(fo.Iterator, new List<object>());
        }
    }

    void ExecForEach(ForEachStatementAst fe, List<object> output)
    {
        var coll = CollectPipeline(fe.Condition);
        int n = 0;
        foreach (var item in Enumerate(coll))
        {
            if (++n > MaxLoop) throw new UnsupportedException("loop limit");
            SetVar(fe.Variable.VariablePath.VarName(), item);
            try { ExecStatements(fe.Body.Statements, output); }
            catch (BreakSignal) { break; }
            catch (ContinueSignal) { }
        }
    }

    void ExecWhile(PipelineBaseAst cond, StatementBlockAst body, List<object> output, bool doFirst, bool whileTrue)
    {
        int n = 0;
        bool first = doFirst;
        while (true)
        {
            if (!first)
            {
                bool c = ToBool(CollectPipeline(cond));
                if (c != whileTrue) break;
            }
            first = false;
            if (++n > MaxLoop) throw new UnsupportedException("loop limit");
            try { ExecStatements(body.Statements, output); }
            catch (BreakSignal) { break; }
            catch (ContinueSignal) { }
        }
    }

    void ExecAssignment(AssignmentStatementAst a)
    {
        object rhs;
        try
        {
            rhs = CollectStatement(a.Right);
        }
        catch (Exception ex) when (ex is not (BudgetExceededException or BreakSignal or ContinueSignal or ReturnSignal))
        {
            // 값을 모르는 변수로 표시 → 이후 이 변수를 쓰는 식은 평가하지 않는다 ($null 로 오인 방지)
            var target = a.Left is ConvertExpressionAst c ? c.Child : a.Left;
            if (target is VariableExpressionAst v && !v.VariablePath.IsDriveQualified)
                SetVar(v.VariablePath.VarName(), UnknownValue.Instance, v.VariablePath.IsScript || v.VariablePath.IsGlobal);
            throw;
        }
        Assign(a.Left, a.Operator, rhs);
    }

    void Assign(ExpressionAst left, TokenKind op, object rhs)
    {
        if (op != TokenKind.Equals)
        {
            var cur = Eval(left);
            rhs = op switch
            {
                TokenKind.PlusEquals => Add(cur, rhs),
                TokenKind.MinusEquals => Arith(cur, rhs, "-"),
                TokenKind.MultiplyEquals => Multiply(cur, rhs),
                TokenKind.DivideEquals => Arith(cur, rhs, "/"),
                TokenKind.RemainderEquals => Arith(cur, rhs, "%"),
                _ => throw new UnsupportedException("assign op " + op)
            };
        }

        switch (left)
        {
            case VariableExpressionAst v:
                {
                    var path = v.VariablePath;
                    if (path.IsDriveQualified && !path.DriveName.Equals("variable", StringComparison.OrdinalIgnoreCase))
                        throw new UnsupportedException("assign to drive");
                    if (op == TokenKind.Equals && rhs is string os && os.Length >= 6 && os.Length <= 4000 && ObservedStrings.Count < 3000)
                        ObservedStrings.Add(os);
                    SetVar(path.VarName(), rhs, path.IsScript || path.IsGlobal);
                    return;
                }
            case ConvertExpressionAst c:
                Assign(c.Child, TokenKind.Equals, ConvertTo(c.Type.TypeName, rhs));
                return;
            case AttributedExpressionAst at:
                Assign(at.Child, TokenKind.Equals, rhs);
                return;
            case IndexExpressionAst ix:
                {
                    var target = Eval(ix.Target);
                    var index = Eval(ix.Index);
                    if (target is Hashtable ht) { ht[ToStr(index)] = rhs; return; }
                    if (target is IList l)
                    {
                        int i = (int)ToLong(index);
                        if (i < 0) i += l.Count;
                        l[i] = ConvertElement(rhs, target.GetType().GetElementType());
                        return;
                    }
                    throw new UnsupportedException("index assign");
                }
            case MemberExpressionAst m when !m.Static:
                {
                    var target = Eval(m.Expression);
                    var name = MemberName(m.Member);
                    if (target is Hashtable ht) { ht[name] = rhs; return; }
                    if (target is SymmetricAlgorithm || target is MemoryStream || target is NetworkCredentialValue)
                    {
                        var prop = target.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                        if (prop != null && prop.CanWrite && TryConvertArg(rhs, prop.PropertyType, out var conv, out _))
                        {
                            prop.SetValue(target, conv);
                            return;
                        }
                    }
                    // 네트워크 객체 등 자리표시자의 속성 설정은 의미가 없으므로 조용히 무시
                    if (target is StubObject) return;
                    throw new UnsupportedException("member " + name + " on " + target?.GetType().Name);
                }
            case MemberExpressionAst sm when sm.Static:
                {
                    // [Net.ServicePointManager]::SecurityProtocol = ... 같은 시스템 전역 설정
                    var tn = sm.Expression is TypeExpressionAst te ? te.TypeName.FullName : sm.Expression.Extent.Text;
                    throw new UnsupportedException($"static member [{tn}]::{MemberName(sm.Member)}");
                }
            case ArrayLiteralAst arr:
                {
                    var vals = Enumerate(rhs).ToList();
                    for (int i = 0; i < arr.Elements.Count; i++)
                    {
                        object v = i < vals.Count ? vals[i] : null;
                        if (i == arr.Elements.Count - 1 && vals.Count > arr.Elements.Count)
                            v = vals.Skip(i).ToArray();
                        Assign(arr.Elements[i], TokenKind.Equals, v);
                    }
                    return;
                }
            default:
                throw new UnsupportedException("assign target " + left.GetType().Name);
        }
    }

    /// <summary>할당 우변: 단일 표현식이면 값 그대로(배열 타입 유지), 아니면 출력을 모은다.</summary>
    object CollectStatement(StatementAst st)
    {
        if (st is CommandExpressionAst cex) return Eval(cex.Expression);
        if (st is PipelineAst p && p.PipelineElements.Count == 1 && p.PipelineElements[0] is CommandExpressionAst ce)
            return Eval(ce.Expression);
        if (st is AssignmentStatementAst a)
        {
            ExecAssignment(a);
            return Eval(a.Left);
        }
        if (st is PipelineBaseAst pb) return CollectPipeline(pb);
        var outp = new List<object>();
        ExecStatement(st, outp);
        return Unwrap(outp);
    }

    object CollectPipeline(PipelineBaseAst pb)
    {
        if (pb is PipelineAst p && p.PipelineElements.Count == 1 && p.PipelineElements[0] is CommandExpressionAst ce)
            return Eval(ce.Expression);
        return Unwrap(EvalPipelineOutput(pb));
    }

    List<object> EvalPipelineOutput(PipelineBaseAst pb)
    {
        if (pb is PipelineAst p) return RunPipeline(p, null);
        if (pb is AssignmentStatementAst a) { ExecAssignment(a); return new List<object>(); }
        var o = new List<object>();
        ExecStatement(pb, o);
        return o;
    }

    static object Unwrap(List<object> list) => list.Count switch
    {
        0 => null,
        1 => list[0],
        _ => list.ToArray()
    };

    #endregion

    #region 파이프라인/명령

    List<object> RunPipeline(PipelineAst p, List<object> initialInput)
    {
        List<object> current = initialInput;
        for (int i = 0; i < p.PipelineElements.Count; i++)
        {
            var el = p.PipelineElements[i];
            if (el is CommandExpressionAst ce)
            {
                if (i != 0) throw new UnsupportedException("expression mid-pipeline");
                var v = Eval(ce.Expression);
                current = new List<object>();
                if (v != null && !IsVoidCast(ce.Expression)) current.AddRange(EnumeratePipeline(v));
            }
            else if (el is CommandAst cmd)
            {
                current = RunCommand(cmd, i == 0 ? null : current ?? new List<object>());
            }
            else throw new UnsupportedException("pipeline element");
        }
        return current ?? new List<object>();
    }

    static bool IsVoidCast(ExpressionAst e) =>
        e is ConvertExpressionAst c && c.Type.TypeName.Name.Equals("void", StringComparison.OrdinalIgnoreCase);

    IEnumerable<object> EnumeratePipeline(object v)
    {
        if (v == null) { yield return null; yield break; }
        if (v is string || v is Hashtable) { yield return v; yield break; }
        if (v is IEnumerable e)
        {
            foreach (var x in e) yield return Normalize(x);
            yield break;
        }
        yield return v;
    }

    sealed class BoundArgs
    {
        public Dictionary<string, object> Named { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Switches { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<object> Positional { get; } = new();
        public object Get(string name) => Named.TryGetValue(name, out var v) ? v : null;
        public bool Has(string name) => Named.ContainsKey(name) || Switches.Contains(name);
    }

    /// <summary>명령 인자를 바인딩한다. valueParams의 이름(접두어 허용)은 값을 가지며 나머지 -옵션은 스위치로 본다.</summary>
    BoundArgs Bind(CommandAst cmd, int startIndex, string[] valueParams, string[] switchParams = null)
    {
        var b = new BoundArgs();
        var els = cmd.CommandElements;
        for (int i = startIndex; i < els.Count; i++)
        {
            var el = els[i];
            if (el is CommandParameterAst cp)
            {
                var canon = Canon(cp.ParameterName, valueParams, switchParams);
                if (cp.Argument != null)
                {
                    b.Named[canon ?? cp.ParameterName] = Eval(cp.Argument);
                }
                else if (canon != null && valueParams.Contains(canon, StringComparer.OrdinalIgnoreCase) && i + 1 < els.Count && els[i + 1] is not CommandParameterAst)
                {
                    b.Named[canon] = EvalArgument(els[++i]);
                }
                else b.Switches.Add(canon ?? cp.ParameterName);
            }
            else if (el is ExpressionAst ea)
            {
                if (ea is VariableExpressionAst ve && ve.Splatted) continue;
                b.Positional.Add(EvalArgument(ea));
            }
        }
        return b;
    }

    static string Canon(string given, string[] valueParams, string[] switchParams)
    {
        var all = valueParams.Concat(switchParams ?? Array.Empty<string>()).ToList();
        var exact = all.FirstOrDefault(n => n.Equals(given, StringComparison.OrdinalIgnoreCase));
        if (exact != null) return exact;
        var pre = all.Where(n => n.StartsWith(given, StringComparison.OrdinalIgnoreCase)).ToList();
        return pre.Count >= 1 ? pre[0] : null;
    }

    object EvalArgument(CommandElementAst el)
    {
        if (el is StringConstantExpressionAst s) return ConstValue(s);
        if (el is ExpressionAst e) return Eval(e);
        throw new UnsupportedException("argument");
    }

    string ResolveCommandName(CommandAst cmd)
    {
        var first = cmd.CommandElements[0];
        if (first is StringConstantExpressionAst sc) return ConstValue(sc);
        var v = Eval((ExpressionAst)first);
        if (v is ScriptBlockValue) return null;
        return ToStr(v);
    }

    List<object> RunCommand(CommandAst cmd, List<object> input)
    {
        Step();
        var first = cmd.CommandElements[0];
        object firstVal = null;
        string name;
        if (first is StringConstantExpressionAst sc) name = ConstValue(sc);
        else
        {
            firstVal = Eval((ExpressionAst)first);
            if (firstVal is ScriptBlockValue sbv)
            {
                if (sbv.FromDynamicCode || sbv.Ast == null) return new List<object>(); // 이미 캡처됨
                var o = new List<object>();
                PushScope();
                try
                {
                    var b = Bind(cmd, 1, Array.Empty<string>());
                    SetVar("args", b.Positional.ToArray());
                    if (input != null)
                        foreach (var item in input) RunScriptBlockBody(sbv.Ast, o, item, true);
                    else RunScriptBlockBody(sbv.Ast, o, null, false);
                }
                catch (ReturnSignal) { }
                finally { PopScope(); }
                return o;
            }
            name = ToStr(firstVal);
        }
        name = name.Trim();
        var lname = name.ToLowerInvariant();
        var bare = Path.GetFileName(lname);
        if (bare.EndsWith(".exe")) bare = bare[..^4];

        if (_functions.TryGetValue(name, out var fn)) return CallFunction(fn, cmd, input);

        switch (bare)
        {
            case "iex":
            case "invoke-expression":
                {
                    var b = Bind(cmd, 1, new[] { "Command" });
                    var c = b.Get("Command") ?? b.Positional.FirstOrDefault();
                    if (c != null) Capture("Invoke-Expression", ToStr(c));
                    else if (input != null) Capture("Invoke-Expression (파이프라인)", string.Join("\n", input.Select(ToStr)));
                    return new List<object>();
                }
            case "invoke-command":
            case "icm":
                {
                    var b = Bind(cmd, 1, new[] { "ScriptBlock", "ArgumentList", "ComputerName" });
                    var sb = b.Get("ScriptBlock") ?? b.Positional.FirstOrDefault();
                    if (sb is ScriptBlockValue s && !s.FromDynamicCode) Capture("Invoke-Command", s.Text);
                    return new List<object>();
                }
            case "write-output":
            case "echo":
            case "write":
                {
                    var b = Bind(cmd, 1, new[] { "InputObject" });
                    var o = new List<object>();
                    if (b.Get("InputObject") is { } io) o.AddRange(EnumeratePipeline(io));
                    foreach (var p in b.Positional) o.AddRange(EnumeratePipeline(p));
                    if (input != null) o.AddRange(input);
                    return o;
                }
            case "write-host":
            case "write-verbose":
            case "write-debug":
            case "write-warning":
            case "write-information":
            case "out-null":
            case "out-host":
            case "out-default":
            case "start-sleep":
            case "sleep":
            case "set-strictmode":
            case "clear-host":
            case "cls":
                return new List<object>();
            case "out-string":
                return new List<object> { string.Join(Environment.NewLine, (input ?? new()).Select(ToStr)) + Environment.NewLine };
            case "foreach-object":
            case "%":
            case "foreach":
                return ForEachObject(cmd, input);
            case "where-object":
            case "?":
            case "where":
                return WhereObject(cmd, input);
            case "select-object":
            case "select":
                {
                    var b = Bind(cmd, 1, new[] { "First", "Last", "Skip", "Index", "ExpandProperty", "Property" }, new[] { "Unique" });
                    IEnumerable<object> seq = input ?? new List<object>();
                    if (b.Get("ExpandProperty") is { } ep) seq = seq.Select(x => GetMember(x, ToStr(ep)));
                    if (b.Get("Skip") is { } sk) seq = seq.Skip((int)ToLong(sk));
                    if (b.Get("First") is { } fi) seq = seq.Take((int)ToLong(fi));
                    if (b.Get("Last") is { } la) { var l = seq.ToList(); seq = l.Skip(Math.Max(0, l.Count - (int)ToLong(la))); }
                    if (b.Get("Index") is { } ix) { var l = seq.ToList(); seq = Enumerate(ix).Select(i => l[(int)ToLong(i)]); }
                    if (b.Has("Unique")) seq = seq.Distinct();
                    return seq.ToList();
                }
            case "sort-object":
            case "sort":
                {
                    var b = Bind(cmd, 1, new[] { "Property" }, new[] { "Descending", "Unique" });
                    if (b.Get("Property") != null || b.Positional.Count > 0) throw new UnsupportedException("sort by property");
                    var l = (input ?? new()).OrderBy(x => x is string ? 1 : 0).ThenBy(x => x is string ? 0 : ToDouble(x)).ThenBy(ToStr, StringComparer.OrdinalIgnoreCase).ToList();
                    if (b.Has("Descending")) l.Reverse();
                    if (b.Has("Unique")) l = l.Distinct().ToList();
                    return l;
                }
            case "join-string":
                {
                    var b = Bind(cmd, 1, new[] { "Separator", "Property" });
                    return new List<object> { string.Join(ToStr(b.Get("Separator") ?? b.Positional.FirstOrDefault() ?? ""), (input ?? new()).Select(ToStr)) };
                }
            case "out-file":
            case "set-content":
            case "add-content":
            case "sc":
            case "ac":
                {
                    var b = Bind(cmd, 1, new[] { "FilePath", "Path", "LiteralPath", "Value", "InputObject", "Encoding", "Width" },
                        new[] { "Force", "Append", "NoNewline", "NoClobber", "PassThru" });
                    var path = b.Get("FilePath") ?? b.Get("Path") ?? b.Get("LiteralPath") ?? b.Positional.ElementAtOrDefault(0);
                    object content = b.Get("Value") ?? b.Get("InputObject");
                    if (content == null && b.Positional.Count > 1) content = b.Positional[1];
                    if (content == null && input != null) content = input.Count == 1 ? input[0] : input.ToArray();
                    var p = ToStr(path);
                    if (content is byte[] bytes)
                    {
                        _virtualFs[p] = bytes;
                        CaptureBytes($"파일 쓰기 ({bare}) → {p}", bytes, p);
                    }
                    else
                    {
                        var text = content is IEnumerable && content is not string
                            ? string.Join(Environment.NewLine, Enumerate(content).Select(ToStr))
                            : ToStr(content);
                        if ((bare is "add-content" or "ac" || b.Has("Append")) && _virtualFs.TryGetValue(p, out var prev))
                            text = ToStr(prev) + Environment.NewLine + text;
                        _virtualFs[p] = text;
                        Capture($"파일 쓰기 ({name}) → {p}", text, p);
                    }
                    return new List<object>();
                }
            case "get-content":
            case "gc":
            case "cat":
            case "type":
                {
                    var b = Bind(cmd, 1, new[] { "Path", "LiteralPath", "Encoding", "TotalCount", "Tail", "ReadCount" }, new[] { "Raw" });
                    var p = ToStr(b.Get("Path") ?? b.Get("LiteralPath") ?? b.Positional.FirstOrDefault());
                    if (!_virtualFs.TryGetValue(p, out var c)) throw new UnsupportedException("get-content real file");
                    if (b.Has("Raw") || c is byte[]) return new List<object> { c };
                    return ToStr(c).Split('\n').Select(x => (object)x.TrimEnd('\r')).ToList();
                }
            case "new-object":
                {
                    var b = Bind(cmd, 1, new[] { "TypeName", "ArgumentList", "ComObject", "Property" }, new[] { "Strict" });
                    if (b.Get("ComObject") is { } com) return new List<object> { new StubObject { TypeName = "COM:" + ToStr(com) } };
                    var tn = ToStr(b.Get("TypeName") ?? b.Positional.ElementAtOrDefault(0));
                    var al = b.Get("ArgumentList") ?? b.Positional.ElementAtOrDefault(b.Get("TypeName") == null ? 1 : 0);
                    var args = al == null ? Array.Empty<object>() : al is object[] arr ? arr : new[] { al };
                    return new List<object> { CreateObject(tn, args) };
                }
            case "convertto-securestring":
                {
                    var b = Bind(cmd, 1, new[] { "String", "Key", "SecureKey" }, new[] { "AsPlainText", "Force" });
                    var s = ToStr(b.Get("String") ?? b.Positional.FirstOrDefault() ?? input?.FirstOrDefault());
                    if (b.Has("AsPlainText")) return new List<object> { new SecureStringValue { Plain = s } };
                    var key = b.Get("Key") ?? b.Positional.ElementAtOrDefault(1);
                    if (key == null) throw new UnsupportedException("DPAPI securestring");
                    var plain = DecryptSecureString(s, ToBytes(key));
                    CaptureDecoded("SecureString 복호화", plain);
                    return new List<object> { new SecureStringValue { Plain = plain } };
                }
            case "get-variable":
            case "gv":
                {
                    var b = Bind(cmd, 1, new[] { "Name", "Scope" }, new[] { "ValueOnly" });
                    var pat = ToStr(b.Get("Name") ?? b.Positional.FirstOrDefault());
                    var res = FindVariables(pat);
                    if (b.Has("ValueOnly")) return res.Select(v => v.Value).ToList();
                    return res.Cast<object>().ToList();
                }
            case "get-item":
            case "gi":
            case "get-childitem":
            case "gci":
            case "dir":
            case "ls":
            case "childitem":
            case "item":
                {
                    var b = Bind(cmd, 1, new[] { "Path", "LiteralPath" });
                    var p = ToStr(b.Get("Path") ?? b.Get("LiteralPath") ?? b.Positional.FirstOrDefault());
                    if (p.StartsWith("variable:", StringComparison.OrdinalIgnoreCase))
                        return FindVariables(p.Substring(9).TrimStart('\\', '/')).Cast<object>().ToList();
                    if (p.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
                        return new List<object> { new VarInfo { Name = p.Substring(4), Value = EnvValue(p.Substring(4)) } };
                    throw new UnsupportedException("get-item " + p);
                }
            case "set-variable":
            case "sv":
            case "set":
            case "new-variable":
            case "nv":
                {
                    var b = Bind(cmd, 1, new[] { "Name", "Value", "Scope", "Option" }, new[] { "Force", "PassThru" });
                    var n = ToStr(b.Get("Name") ?? b.Positional.ElementAtOrDefault(0));
                    var v = b.Get("Value") ?? b.Positional.ElementAtOrDefault(1) ?? (input != null ? Unwrap(input) : null);
                    SetVar(n, v, true);
                    return new List<object>();
                }
            case "set-item":
            case "si":
            case "new-item":
            case "ni":
                {
                    var b = Bind(cmd, 1, new[] { "Path", "Value", "ItemType", "Name" }, new[] { "Force" });
                    var p = ToStr(b.Get("Path") ?? b.Positional.ElementAtOrDefault(0));
                    if (p.StartsWith("variable:", StringComparison.OrdinalIgnoreCase))
                    {
                        SetVar(p.Substring(9).TrimStart('\\', '/'), b.Get("Value") ?? b.Positional.ElementAtOrDefault(1), true);
                        return new List<object>();
                    }
                    return new List<object>(); // 디렉터리 생성 등은 무시
                }
            case "start-process":
            case "saps":
            case "start":
                {
                    var b = Bind(cmd, 1, new[] { "FilePath", "ArgumentList", "WindowStyle", "WorkingDirectory", "Verb" }, new[] { "Wait", "NoNewWindow", "PassThru" });
                    var fp = ToStr(b.Get("FilePath") ?? b.Positional.ElementAtOrDefault(0));
                    var al = b.Get("ArgumentList") ?? b.Positional.ElementAtOrDefault(1);
                    var argStr = al is object[] arr ? string.Join(" ", arr.Select(ToStr)) : ToStr(al);
                    TryCaptureCommandLine(fp + " " + argStr, "Start-Process");
                    return new List<object>();
                }
            case "powershell":
            case "pwsh":
            case "cmd":
                {
                    var text = cmd.Extent.Text;
                    var parts = new List<string> { bare };
                    for (int i = 1; i < cmd.CommandElements.Count; i++)
                    {
                        var e = cmd.CommandElements[i];
                        if (e is CommandParameterAst cp)
                        {
                            parts.Add("-" + cp.ParameterName);
                            if (cp.Argument != null) parts.Add(Quote(ToStr(Eval(cp.Argument))));
                        }
                        else
                        {
                            object v;
                            try { v = EvalArgument(e); } catch (UnsupportedException) { v = e.Extent.Text; }
                            parts.Add(Quote(v is ScriptBlockValue sv ? sv.Text : ToStr(v)));
                        }
                    }
                    var line = string.Join(" ", parts);
                    if (!TryCaptureCommandLine(line, "자식 프로세스 " + bare))
                    {
                        // powershell -File <경로>: 가상 파일시스템에서 내용 확인
                        var b = Bind(cmd, 1, new[] { "File", "WindowStyle", "ExecutionPolicy" }, new[] { "NoProfile", "NonInteractive", "NoLogo" });
                        var f = b.Get("File");
                        if (f != null && _virtualFs.TryGetValue(ToStr(f), out var content) && content is string cs)
                            Capture($"powershell -File 실행 ({ToStr(f)})", cs);
                    }
                    return new List<object>();
                }
        }
        throw new UnsupportedException("command " + name);
    }

    static string Quote(string s) => s.Contains(' ') || s.Length == 0 ? "\"" + s.Replace("\"", "\\\"") + "\"" : s;

    bool TryCaptureCommandLine(string line, string kind)
    {
        var r = CommandLineUnwrapper.TryUnwrap(line);
        if (r == null || string.IsNullOrWhiteSpace(r.Script)) return false;
        Capture($"{kind}: {r.Method}", r.Script);
        return true;
    }

    List<VarInfo> FindVariables(string pattern)
    {
        var rx = WildcardToRegex(pattern);
        var names = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in _readOnlyVars) names[kv.Key] = kv.Value;
        foreach (var sc in _scopes) foreach (var kv in sc) names[kv.Key] = kv.Value;
        return names.Where(kv => rx.IsMatch(kv.Key)).Select(kv => new VarInfo { Name = KnownCase(kv.Key), Value = kv.Value }).ToList();
    }

    static string KnownCase(string n) => n;

    List<object> ForEachObject(CommandAst cmd, List<object> input)
    {
        var b = Bind(cmd, 1, new[] { "Process", "Begin", "End", "MemberName", "InputObject" });
        var proc = b.Get("Process") ?? b.Positional.FirstOrDefault();
        var o = new List<object>();
        input ??= b.Get("InputObject") is { } io ? EnumeratePipeline(io).ToList() : new List<object>();
        if (proc is ScriptBlockValue sb && sb.Ast != null)
        {
            if (b.Get("Begin") is ScriptBlockValue bb && bb.Ast != null) RunScriptBlockBody(bb.Ast, o, null, false);
            int n = 0;
            foreach (var item in input)
            {
                if (++n > MaxLoop) throw new UnsupportedException("loop limit");
                try { RunScriptBlockBody(sb.Ast, o, item, true); }
                catch (ContinueSignal) { }
                catch (ReturnSignal) { }
            }
            if (b.Get("End") is ScriptBlockValue eb && eb.Ast != null) RunScriptBlockBody(eb.Ast, o, null, false);
            return o;
        }
        if (proc is string member)
        {
            foreach (var item in input) o.Add(GetMember(item, member));
            return o;
        }
        throw new UnsupportedException("foreach-object");
    }

    List<object> WhereObject(CommandAst cmd, List<object> input)
    {
        var b = Bind(cmd, 1, new[] { "FilterScript", "Property", "Value" });
        var filt = b.Get("FilterScript") ?? b.Positional.FirstOrDefault();
        if (filt is not ScriptBlockValue sb || sb.Ast == null) throw new UnsupportedException("where-object");
        var o = new List<object>();
        foreach (var item in input ?? new List<object>())
        {
            var r = new List<object>();
            RunScriptBlockBody(sb.Ast, r, item, true);
            if (ToBool(Unwrap(r))) o.Add(item);
        }
        return o;
    }

    List<object> CallFunction(FunctionDefinitionAst fn, CommandAst cmd, List<object> input)
    {
        var parms = (IReadOnlyList<ParameterAst>)fn.Parameters ?? (IReadOnlyList<ParameterAst>)fn.Body.ParamBlock?.Parameters ?? Array.Empty<ParameterAst>();
        var pnames = parms.Select(p => p.Name.VariablePath.VarName()).ToArray();
        var b = Bind(cmd, 1, pnames);
        return InvokeFunction(fn, parms, b.Named, b.Positional, input);
    }

    List<object> InvokeFunction(FunctionDefinitionAst fn, IReadOnlyList<ParameterAst> parms, Dictionary<string, object> named, List<object> positional, List<object> input)
    {
        if (_scopes.Count > 60) throw new UnsupportedException("recursion");
        var output = new List<object>();
        PushScope();
        try
        {
            var pos = new Queue<object>(positional);
            foreach (var p in parms)
            {
                var pn = p.Name.VariablePath.VarName();
                object v;
                if (named.TryGetValue(pn, out var nv)) v = nv;
                else if (pos.Count > 0) v = pos.Dequeue();
                else v = p.DefaultValue != null ? Eval(p.DefaultValue) : null;
                var tc = p.Attributes.OfType<TypeConstraintAst>().FirstOrDefault();
                if (tc != null && v != null)
                {
                    try { v = ConvertTo(tc.TypeName, v); } catch (UnsupportedException) { }
                }
                SetVar(pn, v);
            }
            SetVar("args", pos.ToArray());
            if (input != null && fn.Body.ProcessBlock != null)
            {
                if (fn.Body.BeginBlock != null) ExecStatements(fn.Body.BeginBlock.Statements, output);
                foreach (var item in input)
                {
                    SetVar("_", item);
                    ExecStatements(fn.Body.ProcessBlock.Statements, output);
                }
                if (fn.Body.EndBlock != null) ExecStatements(fn.Body.EndBlock.Statements, output);
            }
            else
            {
                if (input != null) SetVar("input", input.ToArray());
                RunScriptBlockBody(fn.Body, output, null, false);
            }
        }
        catch (ReturnSignal) { }
        finally { PopScope(); }
        return output;
    }

    #endregion

    #region 표현식

    public object Eval(ExpressionAst e)
    {
        Step();
        switch (e)
        {
            case StringConstantExpressionAst s:
                return ConstValue(s);
            case ExpandableStringExpressionAst x:
                return Expand(x);
            case ConstantExpressionAst c:
                return Normalize(c.Value);
            case VariableExpressionAst v:
                return GetVariable(v);
            case ParenExpressionAst p:
                return CollectPipeline(p.Pipeline);
            case SubExpressionAst sub:
                {
                    var o = new List<object>();
                    ExecStatements(sub.SubExpression.Statements, o);
                    return Unwrap(o);
                }
            case ArrayExpressionAst arr:
                {
                    var o = new List<object>();
                    ExecStatements(arr.SubExpression.Statements, o);
                    // @(단일 배열 표현식)은 그 배열 그대로
                    if (arr.SubExpression.Statements.Count == 1 && arr.SubExpression.Statements[0] is PipelineAst pp &&
                        pp.PipelineElements.Count == 1 && pp.PipelineElements[0] is CommandExpressionAst ce)
                    {
                        var v = Eval(ce.Expression);
                        if (v is IEnumerable && v is not string && v is not Hashtable) return Enumerate(v).ToArray();
                    }
                    return o.ToArray();
                }
            case ArrayLiteralAst al:
                return al.Elements.Select(Eval).ToArray();
            case HashtableAst h:
                {
                    var ht = new Hashtable(StringComparer.OrdinalIgnoreCase);
                    foreach (var kv in h.KeyValuePairs) ht[ToStr(Eval(kv.Item1))] = CollectStatement(kv.Item2);
                    return ht;
                }
            case ScriptBlockExpressionAst sbe:
                return new ScriptBlockValue { Ast = sbe.ScriptBlock, Text = InnerScriptText(sbe) };
            case ConvertExpressionAst conv:
                {
                    var v = Eval(conv.Child);
                    return ConvertTo(conv.Type.TypeName, v);
                }
            case AttributedExpressionAst attr:
                return Eval(attr.Child);
            case TypeExpressionAst t:
                return new TypeRef { Name = t.TypeName.FullName };
            case UnaryExpressionAst u:
                return EvalUnary(u);
            case BinaryExpressionAst b:
                return EvalBinary(b);
            case InvokeMemberExpressionAst im:
                return EvalInvokeMember(im);
            case MemberExpressionAst m:
                return EvalMember(m);
            case IndexExpressionAst ix:
                return EvalIndex(ix);
            case UsingExpressionAst us:
                return Eval(us.SubExpression);
            default:
                throw new UnsupportedException("expr " + e.GetType().Name);
        }
    }

    static string InnerScriptText(ScriptBlockExpressionAst sbe)
    {
        var t = sbe.Extent.Text;
        if (t.StartsWith("{") && t.EndsWith("}")) t = t.Substring(1, t.Length - 2);
        return t;
    }

    string Expand(ExpandableStringExpressionAst x)
    {
        var raw = x.Extent.Text;
        int start = x.Extent.StartOffset;
        int bodyStart, bodyEnd;
        switch (x.StringConstantType)
        {
            case StringConstantType.DoubleQuoted:
                bodyStart = 1; bodyEnd = raw.Length - 1; break;
            case StringConstantType.DoubleQuotedHereString:
                {
                    bodyStart = raw.IndexOf('\n') + 1;
                    bodyEnd = raw.LastIndexOf('\n');
                    if (bodyEnd > 0 && raw[bodyEnd - 1] == '\r') bodyEnd--;
                    if (bodyEnd < bodyStart) bodyEnd = bodyStart;
                    break;
                }
            default:
                bodyStart = 0; bodyEnd = raw.Length; break;
        }
        var nested = x.NestedExpressions.OrderBy(n => n.Extent.StartOffset).ToList();
        var sb = new StringBuilder();
        int ni = 0;
        for (int i = bodyStart; i < bodyEnd;)
        {
            if (ni < nested.Count && nested[ni].Extent.StartOffset - start == i)
            {
                var v = Eval(nested[ni]);
                sb.Append(ToStr(v));
                i = nested[ni].Extent.EndOffset - start;
                ni++;
                continue;
            }
            char c = raw[i];
            if (c == '`' && i + 1 < bodyEnd)
            {
                char n = raw[i + 1];
                i += 2;
                switch (n)
                {
                    case '0': sb.Append('\0'); break;
                    case 'a': sb.Append('\a'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'v': sb.Append('\v'); break;
                    default: sb.Append(n); break;
                }
                continue;
            }
            if (x.StringConstantType == StringConstantType.DoubleQuoted && IsDoubleQuote(c) && i + 1 < bodyEnd && IsDoubleQuote(raw[i + 1]))
            {
                sb.Append(c);
                i += 2;
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    /// <summary>
    /// 문자열 상수 값. PS 7 파서는 `e·`u{} 를 이스케이프로 처리하지만 악성코드가 노리는
    /// Windows PowerShell 5.1 에서는 일반 문자이므로 5.1 규칙으로 다시 계산한다.
    /// </summary>
    public static string ConstValue(StringConstantExpressionAst s)
    {
        var raw = s.Extent.Text;
        if (raw.IndexOf('`') < 0) return s.Value;
        string body;
        switch (s.StringConstantType)
        {
            case StringConstantType.DoubleQuoted:
                body = raw.Length >= 2 ? raw.Substring(1, raw.Length - 2) : raw; break;
            case StringConstantType.DoubleQuotedHereString:
                {
                    int a = raw.IndexOf('\n') + 1, b = raw.LastIndexOf('\n');
                    if (b > 0 && raw[b - 1] == '\r') b--;
                    body = b >= a ? raw.Substring(a, b - a) : "";
                    break;
                }
            case StringConstantType.BareWord:
                body = raw; break;
            default:
                return s.Value;
        }
        var sb = new StringBuilder();
        for (int i = 0; i < body.Length; i++)
        {
            char c = body[i];
            if (c == '`' && i + 1 < body.Length)
            {
                char n = body[++i];
                sb.Append(n switch
                {
                    '0' => '\0', 'a' => '\a', 'b' => '\b', 'f' => '\f', 'n' => '\n', 'r' => '\r', 't' => '\t', 'v' => '\v',
                    _ => n
                });
                continue;
            }
            if (s.StringConstantType == StringConstantType.DoubleQuoted && IsDoubleQuote(c) && i + 1 < body.Length && IsDoubleQuote(body[i + 1]))
            {
                sb.Append(c); i++; continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    static bool IsDoubleQuote(char c) => c is '"' or '\u201C' or '\u201D' or '\u201E';

    object EvalUnary(UnaryExpressionAst u)
    {
        switch (u.TokenKind)
        {
            case TokenKind.Not:
            case TokenKind.Exclaim:
                return !ToBool(Eval(u.Child));
            case TokenKind.Minus:
                {
                    var v = Eval(u.Child);
                    return IsFloat(v) ? -ToDouble(v) : (object)(-ToLong(v));
                }
            case TokenKind.Plus:
                return ToNumber(Eval(u.Child));
            case TokenKind.Bnot:
                return ~ToLong(Eval(u.Child));
            case TokenKind.Join:
                return string.Join("", Enumerate(Eval(u.Child)).Select(ToStr));
            case TokenKind.Comma:
                return new[] { Eval(u.Child) };
            case TokenKind.PlusPlus:
            case TokenKind.MinusMinus:
            case TokenKind.PostfixPlusPlus:
            case TokenKind.PostfixMinusMinus:
                {
                    var cur = Eval(u.Child);
                    bool inc = u.TokenKind is TokenKind.PlusPlus or TokenKind.PostfixPlusPlus;
                    object nv = IsFloat(cur) ? ToDouble(cur) + (inc ? 1 : -1) : (object)(ToLong(cur) + (inc ? 1 : -1));
                    Assign(u.Child, TokenKind.Equals, nv);
                    return u.TokenKind is TokenKind.PostfixPlusPlus or TokenKind.PostfixMinusMinus ? cur : nv;
                }
        }
        var name = u.TokenKind.ToString();
        if (name is "Isplit" or "Csplit" or "Split")
        {
            var s = ToStr(Eval(u.Child));
            return Regex.Split(s.Trim(), @"\s+").Where(x => x.Length > 0).Cast<object>().ToArray();
        }
        throw new UnsupportedException("unary " + u.TokenKind);
    }

    object EvalBinary(BinaryExpressionAst b)
    {
        var op = b.Operator;
        if (op == TokenKind.And) return ToBool(Eval(b.Left)) && ToBool(Eval(b.Right));
        if (op == TokenKind.Or) return ToBool(Eval(b.Left)) || ToBool(Eval(b.Right));

        // 'a'+'b'+'c'+... 처럼 왼쪽으로 깊게 중첩된 체인은 재귀 대신 반복으로 평가 (스택 오버플로 방지)
        if (b.Left is BinaryExpressionAst lb && lb.Operator == op && IsChainOp(op))
        {
            var chain = new Stack<ExpressionAst>();
            ExpressionAst cur = b;
            while (cur is BinaryExpressionAst cb && cb.Operator == op)
            {
                chain.Push(cb.Right);
                cur = cb.Left;
            }
            var acc = Eval(cur);
            while (chain.Count > 0)
            {
                Step();
                acc = ApplyChain(op, acc, Eval(chain.Pop()));
            }
            return acc;
        }

        var l = Eval(b.Left);
        var r = Eval(b.Right);
        switch (op)
        {
            case TokenKind.Plus: return Add(l, r);
            case TokenKind.Minus: return Arith(l, r, "-");
            case TokenKind.Multiply: return Multiply(l, r);
            case TokenKind.Divide: return Arith(l, r, "/");
            case TokenKind.Rem: return Arith(l, r, "%");
            case TokenKind.Xor: return ToBool(l) ^ ToBool(r);
            case TokenKind.Band: return ToLong(l) & ToLong(r);
            case TokenKind.Bor: return ToLong(l) | ToLong(r);
            case TokenKind.Bxor: return ToLong(l) ^ ToLong(r);
            case TokenKind.Shl: return ToLong(l) << (int)ToLong(r);
            case TokenKind.Shr: return ToLong(l) >> (int)ToLong(r);
            case TokenKind.DotDot: return Range(l, r);
            case TokenKind.Format: return Format(l, r);
            case TokenKind.Join:
                return string.Join(ToStr(r), Enumerate(l).Select(ToStr));
        }
        var name = op.ToString();
        bool cs = name.StartsWith("C") && name.Length > 1 && char.IsLower(name[1]);
        var core = (name.StartsWith("I") || cs) && name.Length > 2 && char.IsLower(name[1]) ? name.Substring(1) : name;
        switch (core.ToLowerInvariant())
        {
            case "replace": return ReplaceOp(l, r, cs);
            case "split": return SplitOp(l, r, cs);
            case "eq": return CompareOp(l, r, cs, c => c == 0);
            case "ne": return CompareOp(l, r, cs, c => c != 0);
            case "lt": return CompareOp(l, r, cs, c => c < 0);
            case "le": return CompareOp(l, r, cs, c => c <= 0);
            case "gt": return CompareOp(l, r, cs, c => c > 0);
            case "ge": return CompareOp(l, r, cs, c => c >= 0);
            case "like": return MatchOp(l, s => WildcardToRegex(ToStr(r), cs).IsMatch(s));
            case "notlike": return MatchOp(l, s => !WildcardToRegex(ToStr(r), cs).IsMatch(s));
            case "match":
                {
                    var rx = new Regex(ToStr(r), cs ? RegexOptions.None : RegexOptions.IgnoreCase);
                    if (l is IEnumerable && l is not string) return MatchOp(l, s => rx.IsMatch(s));
                    var m = rx.Match(ToStr(l));
                    if (m.Success)
                    {
                        var ht = new Hashtable(StringComparer.OrdinalIgnoreCase);
                        foreach (var gn in rx.GetGroupNames())
                            if (m.Groups[gn].Success) ht[gn] = m.Groups[gn].Value;
                        SetVar("matches", ht);
                    }
                    return m.Success;
                }
            case "notmatch":
                {
                    var rx = new Regex(ToStr(r), cs ? RegexOptions.None : RegexOptions.IgnoreCase);
                    return MatchOp(l, s => !rx.IsMatch(s));
                }
            case "contains": return Enumerate(l).Any(x => Compare(x, r, cs) == 0);
            case "notcontains": return !Enumerate(l).Any(x => Compare(x, r, cs) == 0);
            case "in": return Enumerate(r).Any(x => Compare(x, l, cs) == 0);
            case "notin": return !Enumerate(r).Any(x => Compare(x, l, cs) == 0);
        }
        throw new UnsupportedException("binary " + op);
    }

    static bool IsChainOp(TokenKind op) => op is TokenKind.Plus or TokenKind.Minus or TokenKind.Multiply or TokenKind.Bxor or TokenKind.Band or TokenKind.Bor;

    object ApplyChain(TokenKind op, object l, object r) => op switch
    {
        TokenKind.Plus => Add(l, r),
        TokenKind.Minus => Arith(l, r, "-"),
        TokenKind.Multiply => Multiply(l, r),
        TokenKind.Bxor => ToLong(l) ^ ToLong(r),
        TokenKind.Band => ToLong(l) & ToLong(r),
        TokenKind.Bor => ToLong(l) | ToLong(r),
        _ => throw new UnsupportedException("chain")
    };

    object MatchOp(object l, Func<string, bool> pred)
    {
        if (l is IEnumerable && l is not string) return Enumerate(l).Where(x => pred(ToStr(x))).ToArray();
        return pred(ToStr(l));
    }

    object CompareOp(object l, object r, bool cs, Func<int, bool> pred)
    {
        if (l is IEnumerable && l is not string && l is not Hashtable)
            return Enumerate(l).Where(x => pred(Compare(x, r, cs))).ToArray();
        return pred(Compare(l, r, cs));
    }

    int Compare(object l, object r, bool cs)
    {
        if (l == null && r == null) return 0;
        if (l == null) return -1;
        if (r == null) return 1;
        if (IsNumeric(l) || l is bool)
        {
            if (l is bool lb) return lb.CompareTo(ToBool(r));
            if (TryToDouble(r, out var rd)) return ToDouble(l).CompareTo(rd);
            return string.Compare(ToStr(l), ToStr(r), cs ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
        }
        return string.Compare(ToStr(l), ToStr(r), cs ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
    }

    object ReplaceOp(object l, object r, bool cs)
    {
        var parts = r is object[] arr ? arr : new[] { r };
        var pat = ToStr(parts.ElementAtOrDefault(0));
        var rep = ToStr(parts.ElementAtOrDefault(1));
        var rx = new Regex(pat, cs ? RegexOptions.None : RegexOptions.IgnoreCase);
        if (l is IEnumerable && l is not string)
            return Enumerate(l).Select(x => (object)rx.Replace(ToStr(x), rep)).ToArray();
        return rx.Replace(ToStr(l), rep);
    }

    object SplitOp(object l, object r, bool cs)
    {
        var parts = r is object[] arr ? arr : new[] { r };
        if (parts.ElementAtOrDefault(0) is ScriptBlockValue) throw new UnsupportedException("split scriptblock");
        var pat = ToStr(parts.ElementAtOrDefault(0));
        int max = parts.Length > 1 ? (int)ToLong(parts[1]) : 0;
        var rx = new Regex(pat, cs ? RegexOptions.None : RegexOptions.IgnoreCase);
        var res = new List<object>();
        foreach (var x in Enumerate(l))
        {
            var s = ToStr(x);
            var sp = max > 0 ? rx.Split(s, max) : rx.Split(s);
            res.AddRange(sp);
        }
        return res.ToArray();
    }

    object Format(object l, object r)
    {
        var fmt = ToStr(l);
        var args = (r is object[] arr ? arr : r is IEnumerable e && r is not string ? e.Cast<object>().ToArray() : new[] { r })
            .Select(FormatArg).ToArray();
        return string.Format(CultureInfo.InvariantCulture, fmt, args);
    }

    object FormatArg(object v) => v switch
    {
        null => "",
        IEnumerable e when v is not string => ToStr(v),
        bool b => b ? "True" : "False",
        _ => v
    };

    object Range(object l, object r)
    {
        if (l is string ls && r is string rs && ls.Length == 1 && rs.Length == 1 && !char.IsDigit(ls[0]))
        {
            int a = ls[0], z = rs[0];
            return (a <= z ? Enumerable.Range(a, z - a + 1) : Enumerable.Range(z, a - z + 1).Reverse()).Select(c => (object)(char)c).ToArray();
        }
        long from = ToLong(l), to = ToLong(r);
        long count = Math.Abs(to - from) + 1;
        if (count > 2_000_000) throw new UnsupportedException("range too large");
        var res = new object[count];
        long step = from <= to ? 1 : -1;
        for (long i = 0; i < count; i++) res[i] = from + i * step;
        return res;
    }

    object Add(object l, object r)
    {
        switch (l)
        {
            case null:
                return r;
            case string s:
                {
                    var rs = ToStr(r);
                    if (s.Length + rs.Length > MaxString) throw new UnsupportedException("string too large");
                    return s + rs;
                }
            case char c:
                if (r is string || r is char) return c + ToStr(r);
                return (long)c + ToLong(r);
            case Hashtable h1 when r is Hashtable h2:
                {
                    var n = new Hashtable(h1, StringComparer.OrdinalIgnoreCase);
                    foreach (DictionaryEntry kv in h2) n[kv.Key] = kv.Value;
                    return n;
                }
            case IEnumerable e:
                {
                    var list = e.Cast<object>().Select(Normalize).ToList();
                    if (r is IEnumerable re && r is not string && r is not Hashtable) list.AddRange(re.Cast<object>().Select(Normalize));
                    else list.Add(r);
                    if (list.Count > 50_000_000) throw new UnsupportedException("array too large");
                    return list.ToArray();
                }
        }
        return Arith(l, r, "+");
    }

    object Multiply(object l, object r)
    {
        if (l is string s)
        {
            var n = ToLong(r);
            if (n < 0 || s.Length * n > MaxString) throw new UnsupportedException("string repeat");
            return string.Concat(Enumerable.Repeat(s, (int)n));
        }
        if (l is IEnumerable e && l is not string)
        {
            var n = (int)ToLong(r);
            var items = e.Cast<object>().ToList();
            return Enumerable.Range(0, Math.Max(0, n)).SelectMany(_ => items).ToArray();
        }
        return Arith(l, r, "*");
    }

    object Arith(object l, object r, string op)
    {
        var a = ToNumber(l);
        var b = ToNumber(r);
        if (a is double || b is double)
        {
            double x = ToDouble(a), y = ToDouble(b);
            return op switch { "+" => x + y, "-" => x - y, "*" => x * y, "/" => x / y, "%" => x % y, _ => throw new UnsupportedException(op) };
        }
        long xi = (long)a, yi = (long)b;
        try
        {
            checked
            {
                switch (op)
                {
                    case "+": return xi + yi;
                    case "-": return xi - yi;
                    case "*": return xi * yi;
                    case "%": return xi % yi;
                    case "/":
                        if (yi == 0) throw new DivideByZeroException();
                        return xi % yi == 0 ? xi / yi : (double)xi / yi;
                }
            }
        }
        catch (OverflowException)
        {
            double x = xi, y = yi;
            return op switch { "+" => x + y, "-" => x - y, "*" => x * y, _ => throw new UnsupportedException(op) };
        }
        throw new UnsupportedException(op);
    }

    object EvalIndex(IndexExpressionAst ix)
    {
        var target = Eval(ix.Target);
        var index = Eval(ix.Index);
        if (target is Hashtable ht)
        {
            if (index is object[] keys) return keys.Select(k => ht[ToStr(k)]).ToArray();
            return ht[ToStr(index)];
        }
        if (index is IEnumerable && index is not string)
            return Enumerate(index).Select(i => IndexOne(target, i)).ToArray();
        return IndexOne(target, index);
    }

    object IndexOne(object target, object index)
    {
        if (target is Hashtable ht) return ht[ToStr(index)];
        if (target is string s)
        {
            long i = ToLong(index);
            if (i < 0) i += s.Length;
            return i >= 0 && i < s.Length ? s[(int)i] : null;
        }
        if (target is IList l)
        {
            long i = ToLong(index);
            if (i < 0) i += l.Count;
            return i >= 0 && i < l.Count ? Normalize(l[(int)i]) : null;
        }
        if (target is MatchCollection mc) return mc[(int)ToLong(index)];
        if (target is GroupCollection gc) return index is string gs ? gc[gs] : gc[(int)ToLong(index)];
        if (target == null) throw new UnsupportedException("index null");
        // 스칼라에 [0]은 자기 자신
        if (ToLong(index) == 0) return target;
        return null;
    }

    string MemberName(CommandElementAst member)
    {
        if (member is StringConstantExpressionAst s) return ConstValue(s);
        if (member is ExpressionAst e) return ToStr(Eval(e));
        throw new UnsupportedException("member name");
    }

    object EvalMember(MemberExpressionAst m)
    {
        var name = MemberName(m.Member);
        if (m.Static)
        {
            var t = Eval(m.Expression);
            if (t is not TypeRef tr) throw new UnsupportedException("static on non-type");
            return GetStaticMember(tr.Name, name);
        }
        var target = Eval(m.Expression);
        return GetMember(target, name);
    }

    public object GetMember(object target, string name)
    {
        var lname = name.ToLowerInvariant();
        switch (target)
        {
            case null:
                return null;
            case string s:
                if (lname == "length") return (long)s.Length;
                if (lname == "count") return 1L;
                break;
            case Hashtable ht:
                if (ht.ContainsKey(name)) return ht[name];
                if (lname == "count") return (long)ht.Count;
                if (lname == "keys") return ht.Keys.Cast<object>().ToArray();
                if (lname == "values") return ht.Values.Cast<object>().ToArray();
                return null;
            case VarInfo vi:
                if (lname == "name") return vi.Name;
                if (lname == "value") return vi.Value;
                return null;
            case SecureStringValue ss:
                if (lname == "length") return (long)ss.Plain.Length;
                break;
            case NetworkCredentialValue nc:
                if (lname == "password") return nc.Password;
                if (lname == "username") return nc.UserName;
                break;
            case ExecContextStub:
                if (lname is "invokecommand" or "sessionstate") return target;
                break;
            case ScriptBlockValue sb:
                if (lname == "ast") throw new UnsupportedException("ast");
                break;
            case Array arr when lname is "length" or "count" or "longlength":
                return (long)arr.Length;
            case IEnumerable e when target is not string && !IsSafeReflectType(target.GetType()):
                // 멤버 열거
                return e.Cast<object>().Select(x => GetMember(Normalize(x), name)).ToArray();
        }
        if (IsSafeReflectType(target.GetType()))
        {
            var prop = target.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            if (prop != null && prop.GetIndexParameters().Length == 0 && IsSafeReturn(prop.PropertyType))
                return Normalize(prop.GetValue(target));
        }
        if (lname == "length" || lname == "count") return 1L;
        throw new UnsupportedException("member " + name + " on " + target.GetType().Name);
    }

    object EvalInvokeMember(InvokeMemberExpressionAst im)
    {
        var name = MemberName(im.Member);
        var args = (im.Arguments ?? (IReadOnlyList<ExpressionAst>)Array.Empty<ExpressionAst>()).Select(Eval).ToArray();
        if (im.Static)
        {
            var t = Eval(im.Expression);
            if (t is not TypeRef tr) throw new UnsupportedException("static call on non-type");
            return InvokeStatic(tr.Name, name, args);
        }
        var target = Eval(im.Expression);
        return InvokeInstance(target, name, args);
    }

    #endregion

    #region .NET 화이트리스트

    static string NormType(string n)
    {
        n = n.Trim();
        // "[byte[]]" → "byte[]" (배열 표기 "[]" 는 유지)
        if (n.StartsWith("[") && n.EndsWith("]")) n = n[1..^1];
        n = n.ToLowerInvariant();
        if (n.StartsWith("system.")) n = n.Substring(7);
        return n;
    }

    static readonly Dictionary<string, Type> StaticTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["convert"] = typeof(Convert),
        ["math"] = typeof(Math),
        ["bitconverter"] = typeof(BitConverter),
        ["string"] = typeof(string),
        ["char"] = typeof(char),
        ["text.encoding"] = typeof(Encoding),
        ["text.regularexpressions.regex"] = typeof(Regex),
        ["regex"] = typeof(Regex),
        ["array"] = typeof(Array),
        ["int"] = typeof(int),
        ["int32"] = typeof(int),
        ["int64"] = typeof(long),
        ["long"] = typeof(long),
        ["byte"] = typeof(byte),
        ["double"] = typeof(double),
        ["uri"] = typeof(Uri),
        ["io.path"] = typeof(Path),
        ["text.regularexpressions.regexoptions"] = typeof(RegexOptions),
        ["io.compression.compressionmode"] = typeof(CompressionMode),
        ["security.cryptography.ciphermode"] = typeof(CipherMode),
        ["security.cryptography.paddingmode"] = typeof(PaddingMode),
        ["stringsplitoptions"] = typeof(StringSplitOptions),
        ["globalization.cultureinfo"] = typeof(CultureInfo),
    };

    static readonly HashSet<string> BlockedStaticMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "GetTempPath", "GetTempFileName", "ChangeType", "GetType", "CreateInstance", "SetValue", "GetFullPath", "Exists"
    };

    object GetStaticMember(string typeName, string member)
    {
        var tn = NormType(typeName);
        var lm = member.ToLowerInvariant();
        if (tn == "text.encoding")
        {
            return lm switch
            {
                "utf8" => new UTF8Encoding(false),
                "unicode" => Encoding.Unicode,
                "ascii" => Encoding.ASCII,
                "default" => new UTF8Encoding(false),
                "utf32" => Encoding.UTF32,
                "bigendianunicode" => Encoding.BigEndianUnicode,
                "utf7" => Encoding.Latin1,
                "latin1" => Encoding.Latin1,
                _ => throw new UnsupportedException("encoding " + member)
            };
        }
        if (tn == "string" && lm == "empty") return "";
        if (tn == "io.path" && lm == "directoryseparatorchar") return '\\';
        if (tn == "environment" && lm == "newline") return "\r\n";
        if (StaticTypes.TryGetValue(tn, out var t))
        {
            if (t.IsEnum) return Enum.Parse(t, member, true);
            var p = t.GetProperty(member, BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase);
            if (p != null && IsSafeReturn(p.PropertyType)) return Normalize(p.GetValue(null));
            var f = t.GetField(member, BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase);
            if (f != null && IsSafeReturn(f.FieldType)) return Normalize(f.GetValue(null));
        }
        throw new UnsupportedException($"static member [{typeName}]::{member}");
    }

    object InvokeStatic(string typeName, string method, object[] args)
    {
        var tn = NormType(typeName);
        var lm = method.ToLowerInvariant();

        if (lm == "new") return CreateObject(typeName, args);

        switch (tn)
        {
            case "management.automation.scriptblock":
            case "scriptblock":
                if (lm == "create")
                {
                    var text = ToStr(args.FirstOrDefault());
                    Capture("[ScriptBlock]::Create", text);
                    return new ScriptBlockValue { Text = text, FromDynamicCode = true };
                }
                break;
            case "reflection.assembly":
                if (lm is "load" or "unsafeloadfrom" or "loadfrom" or "loadfile")
                {
                    if (args.FirstOrDefault() is byte[] asm) CaptureBytes("[Reflection.Assembly]::Load (메모리 내 .NET 어셈블리)", asm);
                    return new StubObject { TypeName = "System.Reflection.Assembly" };
                }
                break;
            case "runtime.interopservices.marshal":
                if (lm is "securestringtobstr" or "securestringtoglobalallocunicode" or "securestringtocotaskmemunicode" or "securestringtoglobalallocansi")
                    return args.FirstOrDefault();
                if (lm.StartsWith("ptrtostring"))
                {
                    if (args.FirstOrDefault() is SecureStringValue ss) return ss.Plain;
                    throw new UnsupportedException("ptrtostring");
                }
                if (lm.StartsWith("zerofree")) return null;
                break;
            case "io.file":
                {
                    var p = ToStr(args.ElementAtOrDefault(0));
                    switch (lm)
                    {
                        case "writealltext":
                        case "appendalltext":
                            _virtualFs[p] = ToStr(args.ElementAtOrDefault(1));
                            Capture($"[IO.File]::{method} → {p}", ToStr(args.ElementAtOrDefault(1)), p);
                            return null;
                        case "writeallbytes":
                            if (args.ElementAtOrDefault(1) is byte[] wb) { _virtualFs[p] = wb; CaptureBytes($"[IO.File]::WriteAllBytes → {p}", wb, p); }
                            return null;
                        case "writealllines":
                            {
                                var wl = string.Join(Environment.NewLine, Enumerate(args.ElementAtOrDefault(1)).Select(ToStr));
                                _virtualFs[p] = wl;
                                Capture($"[IO.File]::WriteAllLines → {p}", wl, p);
                                return null;
                            }
                        case "readalltext":
                        case "readallbytes":
                        case "readalllines":
                            if (_virtualFs.TryGetValue(p, out var c))
                            {
                                if (lm == "readallbytes") return c is byte[] ? c : Encoding.UTF8.GetBytes(ToStr(c));
                                if (lm == "readalllines") return ToStr(c).Split('\n').Select(x => (object)x.TrimEnd('\r')).ToArray();
                                return c is byte[] cb ? Encoding.UTF8.GetString(cb) : c;
                            }
                            break;
                    }
                    throw new UnsupportedException("io.file " + method);
                }
            case "environment":
                if (lm == "getenvironmentvariable") return EnvValue(ToStr(args.FirstOrDefault()));
                if (lm == "expandenvironmentvariables") return ToStr(args.FirstOrDefault());
                if (lm == "getfolderpath") return "%" + ToStr(args.FirstOrDefault()).ToUpperInvariant() + "%";
                break;
            case "io.path":
                if (lm == "gettemppath") return FoldMode ? EnvMarker("TEMP") + "\\" : "%TEMP%\\";
                break;
            case "text.encoding":
                if (lm == "getencoding")
                {
                    var a = args.FirstOrDefault();
                    return IsNumeric(a) ? Encoding.GetEncoding((int)ToLong(a)) : Encoding.GetEncoding(ToStr(a));
                }
                break;
            case "convert":
                if (lm == "frombase64string")
                {
                    var s = ToStr(args.FirstOrDefault());
                    var bytes = Convert.FromBase64String(s);
                    if (bytes.Length > 64 && bytes[0] == 'M' && bytes[1] == 'Z') CaptureBytes("Base64 디코딩 → PE 실행 파일", bytes);
                    return bytes;
                }
                break;
            case "security.cryptography.aes":
            case "security.cryptography.symmetricalgorithm":
                if (lm == "create") return Aes.Create();
                break;
            case "io.compression.zipfile":
                throw new UnsupportedException("zipfile");
        }

        if (StaticTypes.TryGetValue(tn, out var t))
        {
            if (BlockedStaticMethods.Contains(method)) throw new UnsupportedException("blocked " + method);
            var result = InvokeReflect(t, null, method, args, true);
            if (t == typeof(Array) && lm == "reverse") return null;
            return result;
        }
        throw new UnsupportedException($"static call [{typeName}]::{method}");
    }

    object InvokeInstance(object target, string method, object[] args)
    {
        var lm = method.ToLowerInvariant();
        switch (target)
        {
            case null:
                throw new UnsupportedException("method on null");
            case ExecContextStub:
                if (lm is "invokescript" or "newscriptblock")
                {
                    var t = ToStr(args.FirstOrDefault());
                    Capture("$ExecutionContext.InvokeCommand." + method, t);
                    return new ScriptBlockValue { Text = t, FromDynamicCode = true };
                }
                if (lm == "expandstring") return ToStr(args.FirstOrDefault());
                break;
            case ScriptBlockValue sb:
                if (lm is "invoke" or "invokereturnasis")
                {
                    if (sb.FromDynamicCode || sb.Ast == null) return null;
                    var o = new List<object>();
                    PushScope();
                    try { SetVar("args", args); RunScriptBlockBody(sb.Ast, o, null, false); }
                    catch (ReturnSignal) { }
                    finally { PopScope(); }
                    return Unwrap(o);
                }
                if (lm == "tostring") return sb.Text;
                break;
            case string s:
                switch (lm)
                {
                    case "replace":
                        if (args.Length == 2 && (args[0] is string || args[0] is char))
                        {
                            var from = ToStr(args[0]);
                            if (from.Length == 0) return s;
                            var res = s.Replace(from, args[1] == null ? "" : ToStr(args[1]), StringComparison.Ordinal);
                            if (res.Length > MaxString) throw new UnsupportedException("string too large");
                            return res;
                        }
                        break;
                    case "split":
                        // Windows PowerShell 5.1 의미론: 문자열 인자는 char[] 로 변환되어 각 문자 기준 분할
                        if (args.Length >= 1 && args[0] is string sep && args.Length == 1)
                            return s.Split(sep.ToCharArray()).Cast<object>().ToArray();
                        break;
                    case "tostring":
                        return s;
                    case "getbytes":
                        throw new UnsupportedException("getbytes on string");
                }
                break;
            case SecureStringValue ss:
                break;
            case NetworkCredentialValue nc:
                if (lm == "getnetworkcredential") return nc;
                break;
            case VarInfo vi:
                if (lm == "tostring") return vi.Name;
                break;
            case StubObject stub:
                throw new UnsupportedException("stub method " + stub.TypeName + "." + method);
            case Array arr when lm == "tostring":
                return arr.GetType().FullName;
            case Array arr when lm == "clone":
                return arr.Clone();
        }

        if (lm == "gettype") throw new UnsupportedException("gettype");
        if (target is Encoding enc && lm == "getstring")
        {
            var r = InvokeReflect(enc.GetType(), enc, method, args, false);
            if (r is string rs) CaptureDecoded("Encoding.GetString 디코딩 결과", rs);
            return r;
        }
        if (IsSafeReflectType(target.GetType()))
        {
            var r = InvokeReflect(target.GetType(), target, method, args, false);
            if (target is StreamReader && lm == "readtoend" && r is string rs) CaptureDecoded("압축 해제(StreamReader) 결과", rs);
            if (target is ICryptoTransform && r is byte[] dec)
            {
                if (dec.Length > 64 && dec[0] == 'M' && dec[1] == 'Z') CaptureBytes("복호화 → PE 실행 파일", dec);
            }
            return r;
        }
        throw new UnsupportedException("method " + method + " on " + target.GetType().Name);
    }

    static bool IsSafeReflectType(Type t) =>
        t == typeof(string) || t.IsPrimitive || t == typeof(decimal) ||
        typeof(Encoding).IsAssignableFrom(t) ||
        t == typeof(MemoryStream) || t == typeof(DeflateStream) || t == typeof(GZipStream) ||
        t == typeof(StreamReader) || t == typeof(StringBuilder) || t == typeof(List<object>) ||
        t == typeof(Regex) || t == typeof(Match) || t == typeof(Group) || t == typeof(Capture) ||
        t == typeof(MatchCollection) || t == typeof(GroupCollection) ||
        typeof(SymmetricAlgorithm).IsAssignableFrom(t) || typeof(ICryptoTransform).IsAssignableFrom(t) ||
        t == typeof(Uri) || t.IsEnum;

    static bool IsSafeReturn(Type t) =>
        !typeof(Type).IsAssignableFrom(t) && !typeof(MemberInfo).IsAssignableFrom(t) &&
        !typeof(Delegate).IsAssignableFrom(t) && !typeof(Assembly).IsAssignableFrom(t) &&
        t != typeof(IntPtr) && !t.IsPointer;

    object InvokeReflect(Type type, object target, string name, object[] args, bool isStatic)
    {
        var flags = BindingFlags.Public | (isStatic ? BindingFlags.Static : BindingFlags.Instance);
        var candidates = type.GetMethods(flags)
            .Where(m => m.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && !m.IsGenericMethodDefinition && IsSafeReturn(m.ReturnType))
            .ToList();
        if (candidates.Count == 0)
        {
            // 속성처럼 호출되는 경우 (예: .ToCharArray 이외)
            throw new UnsupportedException("no method " + name);
        }

        object[] bestArgs = null;
        MethodInfo best = null;
        int bestScore = -1;
        foreach (var m in candidates)
        {
            var ps = m.GetParameters();
            if (ps.Any(p => p.ParameterType.IsByRef || p.ParameterType.IsPointer)) continue;
            if (ps.Any(p => p.ParameterType.IsGenericType && p.ParameterType.GetGenericTypeDefinition() == typeof(ReadOnlySpan<>))) continue;
            if (ps.Any(p => p.ParameterType.IsGenericType && p.ParameterType.GetGenericTypeDefinition() == typeof(Span<>))) continue;
            object[] conv;
            int score;
            if (TryBindArgs(ps, args, out conv, out score) && score > bestScore)
            {
                best = m; bestArgs = conv; bestScore = score;
            }
        }
        if (best == null) throw new UnsupportedException("no overload " + name);
        var result = best.Invoke(target, bestArgs);
        if (result is string rs && rs.Length > MaxString) throw new UnsupportedException("string too large");
        return Normalize(result);
    }

    bool TryBindArgs(ParameterInfo[] ps, object[] args, out object[] conv, out int score)
    {
        conv = null; score = 0;
        bool hasParams = ps.Length > 0 && ps[^1].GetCustomAttribute<ParamArrayAttribute>() != null;
        int fixedCount = hasParams ? ps.Length - 1 : ps.Length;

        if (!hasParams && args.Length != ps.Length) return false;
        if (hasParams && args.Length < fixedCount) return false;

        var result = new object[ps.Length];
        for (int i = 0; i < fixedCount; i++)
        {
            if (!TryConvertArg(args[i], ps[i].ParameterType, out result[i], out int s)) return false;
            score += s;
        }
        if (hasParams)
        {
            var et = ps[^1].ParameterType.GetElementType();
            var rest = args.Skip(fixedCount).ToArray();
            // 배열 하나가 그대로 넘어온 경우
            if (rest.Length == 1 && TryConvertArg(rest[0], ps[^1].ParameterType, out var whole, out int ws) && rest[0] is IEnumerable && rest[0] is not string)
            {
                result[^1] = whole; score += ws;
            }
            else
            {
                var arr = Array.CreateInstance(et, rest.Length);
                for (int i = 0; i < rest.Length; i++)
                {
                    if (!TryConvertArg(rest[i], et, out var ev, out int s)) return false;
                    arr.SetValue(ev, i);
                    score += s;
                }
                result[^1] = arr;
                score -= 1;
            }
        }
        conv = result;
        return true;
    }

    bool TryConvertArg(object v, Type t, out object result, out int score)
    {
        result = null; score = 0;
        try
        {
            if (v == null)
            {
                score = 1;
                if (!t.IsValueType) { result = null; return true; }
                if (t == typeof(char)) return false;
                result = Activator.CreateInstance(t);
                return true;
            }
            var vt = v.GetType();
            if (t == vt) { result = v; score = 4; return true; }
            if (t == typeof(object)) { result = v is long l && l >= int.MinValue && l <= int.MaxValue ? (int)l : v; score = 2; return true; }
            if (t.IsInstanceOfType(v)) { result = v; score = 3; return true; }
            if (t == typeof(string))
            {
                if (v is char) { result = v.ToString(); score = 3; return true; }
                if (v is IEnumerable && v is not string) return false;
                result = ToStr(v); score = 1; return true;
            }
            if (t == typeof(char))
            {
                if (v is string s && s.Length == 1) { result = s[0]; score = 3; return true; }
                if (IsNumeric(v)) { result = (char)ToLong(v); score = 1; return true; }
                return false;
            }
            if (t.IsEnum)
            {
                if (v is string es) { result = Enum.Parse(t, es, true); score = 2; return true; }
                if (IsNumeric(v)) { result = Enum.ToObject(t, ToLong(v)); score = 2; return true; }
                return false;
            }
            if (t == typeof(int) || t == typeof(long) || t == typeof(short) || t == typeof(byte) || t == typeof(uint) ||
                t == typeof(ushort) || t == typeof(ulong) || t == typeof(sbyte))
            {
                if (v is string && !TryToDouble(v, out _)) return false;
                if (!(IsNumeric(v) || v is string || v is bool)) return false;
                result = Convert.ChangeType(ToLong(v), t, CultureInfo.InvariantCulture);
                score = IsNumeric(v) ? (t == typeof(int) ? 3 : 2) : 1;
                return true;
            }
            if (t == typeof(double) || t == typeof(float) || t == typeof(decimal))
            {
                if (!(IsNumeric(v) || v is string)) return false;
                result = Convert.ChangeType(ToDouble(v), t, CultureInfo.InvariantCulture);
                score = 1;
                return true;
            }
            if (t == typeof(bool)) { result = ToBool(v); score = 1; return true; }
            if (t.IsArray)
            {
                var et = t.GetElementType();
                IEnumerable<object> items;
                if (v is string s2)
                {
                    if (et != typeof(char)) return false;
                    items = s2.Cast<object>();
                }
                else if (v is IEnumerable e) items = e.Cast<object>();
                else items = new[] { v };
                var list = items.ToList();
                var arr = Array.CreateInstance(et, list.Count);
                for (int i = 0; i < list.Count; i++)
                {
                    if (!TryConvertArg(Normalize(list[i]), et, out var ev, out _)) return false;
                    arr.SetValue(ev, i);
                }
                result = arr; score = 1;
                return true;
            }
        }
        catch { return false; }
        return false;
    }

    object CreateObject(string typeName, object[] args)
    {
        var tn = NormType(typeName);
        if (tn.StartsWith("collections.generic.list[") || tn == "collections.arraylist")
        {
            var list = new List<object>();
            if (args.Length == 1 && args[0] is IEnumerable src && args[0] is not string) list.AddRange(Enumerate(src));
            return list;
        }
        switch (tn)
        {
            case "io.memorystream":
                if (args.Length == 0) return new MemoryStream();
                if (args[0] is byte[] b) return new MemoryStream(b);
                if (TryConvertArg(args.Length == 1 && args[0] is object[] oa ? oa : args[0], typeof(byte[]), out var bb, out _))
                    return new MemoryStream((byte[])bb);
                break;
            case "io.compression.deflatestream":
            case "io.compression.gzipstream":
                {
                    if (args.ElementAtOrDefault(0) is not Stream st) break;
                    var mode = args.Length > 1 && TryConvertArg(args[1], typeof(CompressionMode), out var md, out _) ? (CompressionMode)md : CompressionMode.Decompress;
                    if (mode != CompressionMode.Decompress) break;
                    Stream ds = tn.EndsWith("gzipstream") ? new GZipStream(st, mode) : new DeflateStream(st, mode);
                    return ds;
                }
            case "io.streamreader":
                {
                    if (args.ElementAtOrDefault(0) is not Stream st) break;
                    var enc = args.ElementAtOrDefault(1) as Encoding ?? Encoding.UTF8;
                    return new StreamReader(st, enc);
                }
            case "text.stringbuilder":
                return args.Length > 0 && args[0] is string s0 ? new StringBuilder(s0) : new StringBuilder();
            case "string":
                if (args.Length == 1 && TryConvertArg(args[0], typeof(char[]), out var ca, out _)) return new string((char[])ca);
                if (args.Length == 2 && args[0] is char c && IsNumeric(args[1])) return new string(c, (int)ToLong(args[1]));
                break;
            case "security.cryptography.aesmanaged":
            case "security.cryptography.aescryptoserviceprovider":
            case "security.cryptography.rijndaelmanaged":
            case "security.cryptography.aes":
                return Aes.Create();
            case "net.networkcredential":
                {
                    var nc = new NetworkCredentialValue { UserName = ToStr(args.ElementAtOrDefault(0)) };
                    var p = args.ElementAtOrDefault(1);
                    nc.Password = p is SecureStringValue ss ? ss.Plain : ToStr(p);
                    return nc;
                }
            case "net.webclient":
            case "net.http.httpclient":
            case "net.sockets.tcpclient":
            case "xml.xmldocument":
            case "management.automation.pscredential":
                return new StubObject { TypeName = typeName };
            case "regex":
            case "text.regularexpressions.regex":
                return args.Length > 1 && TryConvertArg(args[1], typeof(RegexOptions), out var ro, out _)
                    ? new Regex(ToStr(args[0]), (RegexOptions)ro) : new Regex(ToStr(args.FirstOrDefault()));
        }
        throw new UnsupportedException("new-object " + typeName);
    }

    object ConvertTo(ITypeName typeName, object v)
    {
        var tn = NormType(typeName.FullName);
        switch (tn)
        {
            case "void": return null;
            case "string": return ToStr(v);
            case "char":
                if (v is char) return v;
                if (v is string s) { if (s.Length == 1) return s[0]; throw new UnsupportedException("char cast"); }
                return (char)ToLong(v);
            case "int": case "int32": case "int16": case "short": case "uint32": case "uint16":
            case "long": case "int64": case "uint64": case "uint": case "ulong":
                return v is double d ? (long)Math.Round(d, MidpointRounding.ToEven) : ToLong(v);
            case "byte":
                {
                    var n = v is double d2 ? (long)Math.Round(d2, MidpointRounding.ToEven) : ToLong(v);
                    if (n < 0 || n > 255) throw new UnsupportedException("byte range");
                    return (byte)n;
                }
            case "double": case "float": case "single": case "decimal":
                return ToDouble(v);
            case "bool": case "boolean":
                return ToBool(v);
            case "array": case "object[]":
                return Enumerate(v).ToArray();
            case "object": case "psobject": case "management.automation.psobject":
                return v;
            case "byte[]":
                {
                    if (v is byte[]) return v;
                    var items = Enumerate(v).ToList();
                    var res = new byte[items.Count];
                    for (int i = 0; i < items.Count; i++)
                    {
                        var n = ToLong(items[i]);
                        if (n < 0 || n > 255) throw new UnsupportedException("byte range");
                        res[i] = (byte)n;
                    }
                    return res;
                }
            case "char[]":
                if (v is string cs) return cs.ToCharArray();
                return Enumerate(v).Select(x => x is char ch ? ch : x is string xs && xs.Length == 1 ? xs[0] : (char)ToLong(x)).ToArray();
            case "int[]": case "int32[]": case "long[]": case "int64[]":
                return Enumerate(v).Select(x => (object)ToLong(x)).ToArray();
            case "string[]":
                return Enumerate(v).Select(x => (object)ToStr(x)).ToArray();
            case "scriptblock":
            case "management.automation.scriptblock":
                {
                    var text = ToStr(v);
                    Capture("[ScriptBlock] 형변환", text);
                    return new ScriptBlockValue { Text = text, FromDynamicCode = true };
                }
            case "regex":
            case "text.regularexpressions.regex":
                return new Regex(ToStr(v));
            case "io.memorystream":
                return CreateObject("IO.MemoryStream", new[] { v });
            case "type":
                return new TypeRef { Name = ToStr(v) };
            case "text.encoding":
                if (v is Encoding) return v;
                break;
        }
        if (StaticTypes.TryGetValue(tn, out var t) && t.IsEnum)
            return v is string es ? Enum.Parse(t, es, true) : Enum.ToObject(t, ToLong(v));
        if (typeName is ArrayTypeName) return Enumerate(v).ToArray();
        throw new UnsupportedException("cast " + typeName.FullName);
    }

    static object ConvertElement(object v, Type elementType)
    {
        if (elementType == null || elementType == typeof(object)) return v;
        if (elementType == typeof(byte)) return (byte)ToLongStatic(v);
        if (elementType == typeof(char)) return v is char c ? c : (char)ToLongStatic(v);
        return v;
    }

    #endregion

    #region SecureString

    /// <summary>ConvertFrom-SecureString -Key 로 만들어진 문자열 복호화 (Invoke-Obfuscation 의 SecureString 기법).</summary>
    static string DecryptSecureString(string s, byte[] key)
    {
        const string header = "76492d1116743f0423413b16050a5345";
        if (!s.StartsWith(header, StringComparison.OrdinalIgnoreCase)) throw new UnsupportedException("securestring format");
        var inner = Encoding.Unicode.GetString(Convert.FromBase64String(s.Substring(header.Length)));
        var parts = inner.Split('|');
        if (parts.Length < 3) throw new UnsupportedException("securestring parts");
        var iv = Convert.FromBase64String(parts[1]);
        var cipher = Convert.FromHexString(parts[2]);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        var plain = aes.CreateDecryptor().TransformFinalBlock(cipher, 0, cipher.Length);
        return Encoding.Unicode.GetString(plain);
    }

    byte[] ToBytes(object v)
    {
        if (v is byte[] b) return b;
        return Enumerate(v).Select(x => (byte)ToLong(x)).ToArray();
    }

    #endregion

    #region 변환 유틸

    public static object Normalize(object v) => v switch
    {
        int i => (long)i,
        short s => (long)s,
        uint u => (long)u,
        ushort us => (long)us,
        sbyte sb => (long)sb,
        float f => (double)f,
        decimal d => (double)d,
        _ => v
    };

    public static IEnumerable<object> Enumerate(object v)
    {
        if (v == null) yield break;
        if (v is string || v is Hashtable) { yield return v; yield break; }
        if (v is IEnumerable e)
        {
            foreach (var x in e) yield return Normalize(x);
            yield break;
        }
        yield return v;
    }

    static bool IsNumeric(object v) => v is long or int or double or byte or short or float or decimal or uint or ulong or sbyte or ushort;
    static bool IsFloat(object v) => v is double or float or decimal;

    public static string ToStr(object v)
    {
        switch (v)
        {
            case null: return "";
            case string s: return s;
            case char c: return c.ToString();
            case bool b: return b ? "True" : "False";
            case double d: return d.ToString(CultureInfo.InvariantCulture);
            case float f: return f.ToString(CultureInfo.InvariantCulture);
            case IFormattable fm when v.GetType().IsPrimitive: return fm.ToString(null, CultureInfo.InvariantCulture);
            case ScriptBlockValue sb: return sb.Text;
            case Hashtable: return "System.Collections.Hashtable";
            case Encoding enc: return enc.GetType().FullName;
            case IEnumerable e: return string.Join(" ", e.Cast<object>().Select(ToStr));
            default: return v.ToString();
        }
    }

    object ToNumber(object v)
    {
        switch (v)
        {
            case null: return 0L;
            case long l: return l;
            case double d: return d;
            case bool b: return b ? 1L : 0L;
            case char c: return (long)c;
            case string s:
                {
                    s = s.Trim();
                    if (s.Length == 0) return 0L;
                    if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                        long.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hx)) return hx;
                    if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var li)) return li;
                    if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var dd)) return dd;
                    throw new UnsupportedException("not a number: " + (s.Length > 20 ? s[..20] : s));
                }
        }
        if (IsNumeric(v)) return Normalize(Convert.ChangeType(v, IsFloat(v) ? typeof(double) : typeof(long), CultureInfo.InvariantCulture));
        if (v is object[] arr && arr.Length == 1) return ToNumber(arr[0]);
        throw new UnsupportedException("not a number");
    }

    long ToLong(object v)
    {
        var n = ToNumber(v);
        return n is double d ? (long)Math.Round(d, MidpointRounding.ToEven) : (long)n;
    }

    static long ToLongStatic(object v) => v switch
    {
        long l => l,
        int i => i,
        byte b => b,
        char c => c,
        double d => (long)Math.Round(d),
        string s => long.Parse(s, CultureInfo.InvariantCulture),
        _ => throw new UnsupportedException("long")
    };

    double ToDouble(object v)
    {
        var n = ToNumber(v);
        return n is double d ? d : (long)n;
    }

    bool TryToDouble(object v, out double d)
    {
        try { d = ToDouble(v); return true; }
        catch { d = 0; return false; }
    }

    public static bool ToBool(object v)
    {
        switch (v)
        {
            case null: return false;
            case bool b: return b;
            case string s: return s.Length > 0;
            case char c: return true;
            case long l: return l != 0;
            case double d: return d != 0;
            case int i: return i != 0;
            case byte by: return by != 0;
            case ICollection col:
                if (col.Count == 0) return false;
                if (col.Count == 1) return ToBool(col.Cast<object>().First());
                return true;
            default: return true;
        }
    }

    static Regex WildcardToRegex(string pattern, bool cs = false)
    {
        var sb = new StringBuilder("^");
        foreach (var c in pattern)
        {
            switch (c)
            {
                case '*': sb.Append(".*"); break;
                case '?': sb.Append('.'); break;
                case '[': sb.Append('['); break;
                case ']': sb.Append(']'); break;
                default: sb.Append(Regex.Escape(c.ToString())); break;
            }
        }
        sb.Append('$');
        return new Regex(sb.ToString(), cs ? RegexOptions.Singleline : RegexOptions.IgnoreCase | RegexOptions.Singleline);
    }

    #endregion
}

static class VariablePathExtensions
{
    /// <summary>"env:temp", "script:x" 같은 접두어를 제거한 변수 이름.</summary>
    public static string VarName(this VariablePath p)
    {
        var up = p.UserPath;
        int i = up.IndexOf(':');
        return i >= 0 ? up[(i + 1)..] : up;
    }
}
