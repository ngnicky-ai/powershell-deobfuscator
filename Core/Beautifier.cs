using System.Management.Automation.Language;
using System.Text;
using System.Text.RegularExpressions;

namespace PsDeobfuscator.Core;

/// <summary>
/// 난독화된 스크립트를 사람이 읽기 좋게 정리한다.
///  1) 상수 접기 : ('ne'+'w-'+'object') → 'New-Object', "re`Pl`AcE" → Replace
///  2) 명령/형식/멤버 이름 대소문자 정규화 및 별칭 확장
///  3) 사용되지 않는 더미 변수 제거
///  4) 들여쓰기/줄바꿈 포맷
/// </summary>
public static class Beautifier
{
    public static bool RemoveJunk { get; set; } = true;
    public static bool ExpandAliases { get; set; } = true;

    public static string Clean(string script)
    {
        if (string.IsNullOrWhiteSpace(script)) return script ?? "";
        try
        {
            var text = script.Replace("\r\n", "\n");
            for (int pass = 0; pass < 2; pass++)
            {
                var folded = FoldPass(text, pass == 0 && RemoveJunk);
                if (folded == text) break;
                // 접기 결과가 문법적으로 깨지면 이전 결과 유지
                Parser.ParseInput(folded, out _, out var e2);
                Parser.ParseInput(text, out _, out var e1);
                if (e2.Length > e1.Length) continue;
                text = folded;
            }
            return Format(text);
        }
        catch
        {
            try { return Format(script); } catch { return script; }
        }
    }

    sealed record Repl(int Start, int End, string Text);

    static string FoldPass(string text, bool removeJunk)
    {
        var ast = Parser.ParseInput(text, out _, out _);
        var repls = new List<Repl>();

        // ---------- 상수 변수 수집 (단일 할당 + 상수 값) ----------
        var assignCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        void Count(string n) => assignCounts[n] = assignCounts.TryGetValue(n, out var c) ? c + 1 : 1;

        foreach (var a in ast.FindAll(x => x is AssignmentStatementAst, true).Cast<AssignmentStatementAst>())
            foreach (var v in LeftVariables(a.Left)) Count(v);
        foreach (var u in ast.FindAll(x => x is UnaryExpressionAst ua && ua.TokenKind is TokenKind.PlusPlus or TokenKind.MinusMinus
                     or TokenKind.PostfixPlusPlus or TokenKind.PostfixMinusMinus, true).Cast<UnaryExpressionAst>())
            if (u.Child is VariableExpressionAst uv) { Count(uv.VariablePath.VarName()); Count(uv.VariablePath.VarName()); }
        foreach (var fe in ast.FindAll(x => x is ForEachStatementAst, true).Cast<ForEachStatementAst>())
        { Count(fe.Variable.VariablePath.VarName()); Count(fe.Variable.VariablePath.VarName()); }
        foreach (var p in ast.FindAll(x => x is ParameterAst, true).Cast<ParameterAst>())
        { Count(p.Name.VariablePath.VarName()); Count(p.Name.VariablePath.VarName()); }

        var ev = new SafeEvaluator { FoldMode = true, MaxSteps = 400_000 };
        var constVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in ast.FindAll(x => x is AssignmentStatementAst, true).Cast<AssignmentStatementAst>())
        {
            if (a.Operator != TokenKind.Equals || a.Left is not VariableExpressionAst lv) continue;
            if (lv.VariablePath.IsDriveQualified) continue;
            var name = lv.VariablePath.VarName();
            if (!assignCounts.TryGetValue(name, out var cnt) || cnt != 1) continue;
            var rhs = RightExpression(a.Right);
            if (rhs == null) continue;
            if (ev.TryEvalPure(rhs, out var val) && IsFoldableValue(val, allowArrays: true))
            {
                ev.SetVariable(name, val);
                constVars.Add(name);
            }
        }

        // ---------- 사용되지 않는 더미 변수 대입 제거 ----------
        var removed = new List<(int s, int e)>();
        if (removeJunk)
        {
            var refCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var v in ast.FindAll(x => x is VariableExpressionAst, true).Cast<VariableExpressionAst>())
            {
                var n = v.VariablePath.VarName();
                refCounts[n] = refCounts.TryGetValue(n, out var c) ? c + 1 : 1;
            }
            foreach (var a in ast.FindAll(x => x is AssignmentStatementAst, true).Cast<AssignmentStatementAst>())
            {
                if (a.Operator != TokenKind.Equals || a.Left is not VariableExpressionAst lv) continue;
                var name = lv.VariablePath.VarName();
                if (!constVars.Contains(name)) continue;
                if (refCounts.TryGetValue(name, out var rc) && rc > 1) continue;
                // 문자열로 이름이 참조될 가능성 (Get-Variable 등) 배제
                if (Regex.Matches(text, Regex.Escape(name), RegexOptions.IgnoreCase).Count > 1) continue;
                if (a.Parent is not NamedBlockAst && a.Parent is not StatementBlockAst) continue;
                removed.Add((a.Extent.StartOffset, a.Extent.EndOffset));
                repls.Add(new Repl(a.Extent.StartOffset, a.Extent.EndOffset, ""));
            }
        }

        bool Inside(int s, int e) => repls.Any(r => s >= r.Start && e <= r.End);
        bool Overlaps(int s, int e) => repls.Any(r => s < r.End && e > r.Start);

        // ---------- &('new-'+'object') / .('i'+'ex') 형태의 명령 이름 ----------
        foreach (var cmd in ast.FindAll(x => x is CommandAst, true).Cast<CommandAst>())
        {
            var first = cmd.CommandElements[0];
            if (first is StringConstantExpressionAst sc0)
            {
                // 일반 명령 이름: 백틱 제거·대소문자 정규화·별칭 확장
                if (sc0.StringConstantType != StringConstantType.BareWord) continue;
                var canon = CanonicalCommand(SafeEvaluator.ConstValue(sc0));
                if (canon != null && canon != sc0.Extent.Text && !Overlaps(sc0.Extent.StartOffset, sc0.Extent.EndOffset))
                    repls.Add(new Repl(sc0.Extent.StartOffset, sc0.Extent.EndOffset, canon));
                // New-Object NET.webcLIEnt → New-Object Net.WebClient
                if ((canon ?? sc0.Value).Equals("New-Object", StringComparison.OrdinalIgnoreCase) && cmd.CommandElements.Count > 1 &&
                    cmd.CommandElements[1] is StringConstantExpressionAst tn && tn.StringConstantType == StringConstantType.BareWord)
                {
                    var ct = Dictionaries.CanonicalType(SafeEvaluator.ConstValue(tn));
                    if (ct != null && ct != tn.Extent.Text) repls.Add(new Repl(tn.Extent.StartOffset, tn.Extent.EndOffset, ct));
                }
                continue;
            }
            if (cmd.InvocationOperator is not (TokenKind.Ampersand or TokenKind.Dot)) continue;
            if (Inside(cmd.Extent.StartOffset, cmd.Extent.EndOffset)) continue;
            if (first is not ExpressionAst fe2 || first is VariableExpressionAst) continue;
            if (!ev.TryEvalPure(fe2, out var nv) || nv is not string ns) continue;
            ns = ns.Trim();
            if (!Regex.IsMatch(ns, @"^[A-Za-z][\w\-\.]*$")) continue;
            var cn = CanonicalCommand(ns) ?? ns;
            int after = first.Extent.EndOffset;
            if (after < text.Length && !char.IsWhiteSpace(text[after]) && text[after] != ';' && text[after] != '|') cn += " ";
            repls.Add(new Repl(cmd.Extent.StartOffset, first.Extent.EndOffset, cn));
        }

        // ---------- 표현식 상수 접기 (가장 바깥쪽 우선) ----------
        var exprs = ast.FindAll(x => x is ExpressionAst, true).Cast<ExpressionAst>()
            .OrderBy(x => x.Extent.StartOffset).ThenByDescending(x => x.Extent.EndOffset).ToList();
        foreach (var e in exprs)
        {
            int s = e.Extent.StartOffset, en = e.Extent.EndOffset;
            if (Inside(s, en) || Overlaps(s, en)) continue;
            if (!IsFoldCandidate(e)) continue;
            if (IsAssignmentTarget(e)) continue;
            if (!ev.TryEvalPure(e, out var val)) continue;
            if (!IsFoldableValue(val, allowArrays: true)) continue;
            var lit = ToLiteral(val, e);
            if (lit == null || lit == e.Extent.Text) continue;
            // Invoke-Item($x) → Invoke-Item 'x' : 앞 토큰과 붙지 않도록 공백 보정
            if (s > 0 && (char.IsLetterOrDigit(text[s - 1]) || text[s - 1] is '_' or '-')) lit = " " + lit;
            repls.Add(new Repl(s, en, lit));
        }

        // ---------- 멤버/형식 이름 정규화 ----------
        foreach (var m in ast.FindAll(x => x is MemberExpressionAst, true).Cast<MemberExpressionAst>())
        {
            if (m.Member is not StringConstantExpressionAst ms) continue;
            int s = ms.Extent.StartOffset, en = ms.Extent.EndOffset;
            if (Overlaps(s, en)) continue;
            var name = SafeEvaluator.ConstValue(ms);
            if (!Regex.IsMatch(name, @"^[A-Za-z_]\w*$")) continue;
            var canon = Dictionaries.CanonicalMember(name) ?? name;
            if (canon != ms.Extent.Text) repls.Add(new Repl(s, en, canon));
        }
        foreach (var t in ast.FindAll(x => x is TypeExpressionAst || x is TypeConstraintAst, true))
        {
            int s = t.Extent.StartOffset, en = t.Extent.EndOffset;
            if (Overlaps(s, en)) continue;
            var raw = t.Extent.Text;
            if (!raw.StartsWith("[") || !raw.EndsWith("]")) continue;
            var inner = raw.Substring(1, raw.Length - 2).Replace("`", "");
            var canon = Dictionaries.CanonicalType(inner);
            if (canon != null && "[" + canon + "]" != raw) repls.Add(new Repl(s, en, "[" + canon + "]"));
        }

        if (repls.Count == 0) return text;
        var sb = new StringBuilder(text);
        foreach (var r in repls.OrderByDescending(r => r.Start))
        {
            sb.Remove(r.Start, r.End - r.Start);
            sb.Insert(r.Start, r.Text);
        }
        return sb.ToString();
    }

    static ExpressionAst RightExpression(StatementAst st) => st switch
    {
        CommandExpressionAst ce => ce.Expression,
        PipelineAst { PipelineElements.Count: 1 } p when p.PipelineElements[0] is CommandExpressionAst pce => pce.Expression,
        _ => null
    };

    static IEnumerable<string> LeftVariables(ExpressionAst left)
    {
        switch (left)
        {
            case VariableExpressionAst v: yield return v.VariablePath.VarName(); break;
            case ConvertExpressionAst c: foreach (var x in LeftVariables(c.Child)) yield return x; break;
            case AttributedExpressionAst a: foreach (var x in LeftVariables(a.Child)) yield return x; break;
            case ArrayLiteralAst arr: foreach (var el in arr.Elements) foreach (var x in LeftVariables(el)) yield return x; break;
            case IndexExpressionAst ix when ix.Target is VariableExpressionAst iv:
                yield return iv.VariablePath.VarName(); yield return iv.VariablePath.VarName(); break;
            case MemberExpressionAst mx when mx.Expression is VariableExpressionAst mv:
                yield return mv.VariablePath.VarName(); yield return mv.VariablePath.VarName(); break;
        }
    }

    static bool IsAssignmentTarget(Ast e)
    {
        for (var p = e; p != null; p = p.Parent)
        {
            if (p.Parent is AssignmentStatementAst a && a.Left == p) return true;
            if (p.Parent is UnaryExpressionAst u && u.TokenKind is TokenKind.PlusPlus or TokenKind.MinusMinus or TokenKind.PostfixPlusPlus or TokenKind.PostfixMinusMinus) return true;
            if (p is StatementAst) break;
        }
        return false;
    }

    static bool IsFoldCandidate(ExpressionAst e)
    {
        switch (e)
        {
            case BinaryExpressionAst:
            case ParenExpressionAst:
            case InvokeMemberExpressionAst:
            case IndexExpressionAst:
            case SubExpressionAst:
                return true;
            case UnaryExpressionAst u:
                return u.TokenKind is TokenKind.Join or TokenKind.Minus or TokenKind.Bnot || u.TokenKind.ToString().EndsWith("split", StringComparison.OrdinalIgnoreCase);
            case ConvertExpressionAst c:
                return !c.Type.TypeName.Name.Equals("void", StringComparison.OrdinalIgnoreCase) && c.Child is not VariableExpressionAst;
            case ExpandableStringExpressionAst x:
                return x.NestedExpressions.Count > 0 && x.NestedExpressions.All(n => n is not VariableExpressionAst ve || !ve.VariablePath.IsDriveQualified || !ve.VariablePath.DriveName.Equals("env", StringComparison.OrdinalIgnoreCase));
            case StringConstantExpressionAst s:
                return s.StringConstantType == StringConstantType.DoubleQuoted && s.Extent.Text.Contains('`');
            default:
                return false;
        }
    }

    static bool IsFoldableValue(object v, bool allowArrays)
    {
        switch (v)
        {
            case string s: return s.Length <= 400_000;
            case char: return true;
            case long: return true;
            case double d: return !double.IsNaN(d) && !double.IsInfinity(d);
            case bool: return true;
            case object[] arr when allowArrays:
                return arr.Length > 0 && arr.Length <= 64 && arr.All(x => x is string xs && xs.Length < 2000 || x is long);
        }
        return false;
    }

    static string ToLiteral(object v, ExpressionAst ctx)
    {
        switch (v)
        {
            case string s: return StringLiteral(s);
            case char c: return StringLiteral(c.ToString());
            case long l: return l.ToString(System.Globalization.CultureInfo.InvariantCulture);
            case double d: return d.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
            case bool b: return b ? "$true" : "$false";
            case object[] arr:
                {
                    var items = arr.Select(x => x is string xs ? StringLiteral(xs) : Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture));
                    if (arr.Length <= 3 && arr.Sum(x => SafeEvaluator.ToStr(x).Length) < 60) return "@(" + string.Join(", ", items) + ")";
                    return "@(\n" + string.Join(",\n", items) + "\n)";
                }
        }
        return null;
    }

    public static string StringLiteral(string s)
    {
        bool hasEnv = s.IndexOf(SafeEvaluator.EnvStart) >= 0;
        bool hasCtl = s.Any(c => c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != SafeEvaluator.EnvStart && c != SafeEvaluator.EnvEnd)
                      || (s.Length < 200 && (s.Contains('\n') || s.Contains('\t')));
        if (!hasEnv && !hasCtl)
        {
            var esc = new StringBuilder("'");
            foreach (var c in s)
            {
                if (c is '\'' or '‘' or '’' or '‚' or '‛') esc.Append(c);
                esc.Append(c);
            }
            return esc.Append('\'').ToString();
        }

        var sb = new StringBuilder("\"");
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == SafeEvaluator.EnvStart)
            {
                int end = s.IndexOf(SafeEvaluator.EnvEnd, i);
                var name = s.Substring(i + 1, end - i - 1);
                bool needBrace = end + 1 < s.Length && (char.IsLetterOrDigit(s[end + 1]) || s[end + 1] is '_' or ':');
                sb.Append(needBrace ? "${env:" + name + "}" : "$env:" + name.ToUpperInvariant());
                i = end;
                continue;
            }
            switch (c)
            {
                case '`': sb.Append("``"); break;
                case '"': sb.Append("`\""); break;
                case '“': case '”': case '„': sb.Append('`').Append(c); break;
                case '$': sb.Append("`$"); break;
                case '\n': sb.Append("`n"); break;
                case '\r': sb.Append("`r"); break;
                case '\t': sb.Append("`t"); break;
                case '\0': sb.Append("`0"); break;
                default:
                    if (c < 0x20) sb.Append("`u{" + ((int)c).ToString("x") + "}");
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    static string CanonicalCommand(string name)
    {
        var clean = name.Replace("`", "");
        if (ExpandAliases && Dictionaries.Aliases.TryGetValue(clean, out var full)) return full;
        if (Dictionaries.Cmdlets.TryGetValue(clean, out var canon)) return canon;
        return clean != name ? clean : null;
    }

    #region 포매터

    public static string Format(string text)
    {
        var ast = Parser.ParseInput(text, out var tokens, out _);
        var toks = tokens.Where(t => t.Kind != TokenKind.EndOfInput).ToArray();

        // 중괄호 짝 찾기
        var match = new int[toks.Length];
        var st = new Stack<int>();
        for (int i = 0; i < toks.Length; i++)
        {
            match[i] = -1;
            var k = toks[i].Kind;
            if (k is TokenKind.LCurly or TokenKind.AtCurly) st.Push(i);
            else if (k == TokenKind.RCurly && st.Count > 0) { var o = st.Pop(); match[o] = i; match[i] = o; }
        }

        var sb = new StringBuilder();
        int indent = 0;
        bool lineStart = true;
        int blankRun = 0;
        var stack = new Stack<char>();
        int prevEnd = 0;
        // 포매터가 구조상 넣은 줄바꿈 직후의 원본 줄바꿈은 흡수한다 (빈 줄 중복 방지)
        bool softBreak = false;

        void NewLine()
        {
            // 줄 끝 공백 제거
            while (sb.Length > 0 && sb[^1] == ' ') sb.Length--;
            if (lineStart)
            {
                if (blankRun >= 1 || sb.Length == 0) return;
                blankRun++;
            }
            sb.Append("\r\n");
            lineStart = true;
        }

        void SoftNewLine()
        {
            if (!lineStart) NewLine();
            softBreak = true;
        }

        void Emit(string s, bool spaceBefore)
        {
            softBreak = false;
            if (lineStart)
            {
                sb.Append(new string(' ', Math.Max(0, indent) * 4));
                lineStart = false;
                blankRun = 0;
            }
            else if (spaceBefore && sb.Length > 0 && sb[^1] != ' ') sb.Append(' ');
            sb.Append(s);
        }

        for (int i = 0; i < toks.Length; i++)
        {
            var t = toks[i];
            var gap = t.Extent.StartOffset >= prevEnd ? text.Substring(prevEnd, t.Extent.StartOffset - prevEnd) : "";
            bool space = gap.Length > 0;
            prevEnd = t.Extent.EndOffset;

            switch (t.Kind)
            {
                case TokenKind.NewLine:
                    if (stack.Count > 0 && stack.Peek() == '(') { if (!lineStart) sb.Append(' '); continue; }
                    if (softBreak) { softBreak = false; continue; }
                    NewLine();
                    continue;
                case TokenKind.LineContinuation:
                    Emit("`", true);
                    sb.Append("\r\n");
                    lineStart = true;
                    continue;
                case TokenKind.Semi:
                    if (stack.Count == 0 || stack.Peek() == '{') SoftNewLine();
                    else Emit(";", false);
                    continue;
                case TokenKind.Comment:
                    Emit(t.Text, true);
                    if (t.Text.StartsWith("#")) SoftNewLine();
                    continue;
                case TokenKind.LCurly:
                case TokenKind.AtCurly:
                    {
                        int j = match[i];
                        if (j > i)
                        {
                            int len = toks[j].Extent.EndOffset - t.Extent.StartOffset;
                            bool simple = len <= 90;
                            for (int q = i + 1; q < j && simple; q++)
                                if (toks[q].Kind is TokenKind.Semi or TokenKind.NewLine or TokenKind.LCurly or TokenKind.Comment) simple = false;
                            if (simple)
                            {
                                // 짧은 블록은 한 줄로
                                Emit(t.Text, true);
                                int pe = t.Extent.EndOffset;
                                for (int q = i + 1; q <= j; q++)
                                {
                                    var g = text.Substring(pe, Math.Max(0, toks[q].Extent.StartOffset - pe));
                                    sb.Append(g.Length > 0 || q == j || q == i + 1 ? " " : "");
                                    sb.Append(toks[q].Text);
                                    pe = toks[q].Extent.EndOffset;
                                }
                                prevEnd = toks[j].Extent.EndOffset;
                                i = j;
                                AfterCloseBrace(ref i);
                                continue;
                            }
                        }
                        Emit(t.Text, true);
                        stack.Push('{');
                        indent++;
                        SoftNewLine();
                        continue;
                    }
                case TokenKind.RCurly:
                    if (stack.Count > 0 && stack.Peek() == '{') stack.Pop();
                    indent--;
                    if (!lineStart) NewLine();
                    Emit("}", false);
                    AfterCloseBrace(ref i);
                    continue;
                case TokenKind.LParen:
                case TokenKind.AtParen:
                case TokenKind.DollarParen:
                    Emit(t.Text, space);
                    stack.Push('(');
                    continue;
                case TokenKind.RParen:
                    if (stack.Count > 0 && stack.Peek() == '(') stack.Pop();
                    Emit(")", false);
                    continue;
                default:
                    Emit(t.Text, space);
                    continue;
            }
        }
        return sb.ToString().Trim('\r', '\n') + "\r\n";

        void AfterCloseBrace(ref int idx)
        {
            int n = idx + 1;
            while (n < toks.Length && toks[n].Kind == TokenKind.NewLine) n++;
            if (n >= toks.Length) { SoftNewLine(); return; }
            var nk = toks[n].Kind;
            if (nk is TokenKind.Else or TokenKind.ElseIf or TokenKind.Catch or TokenKind.Finally or TokenKind.Until or TokenKind.While)
            {
                // "} else {" 같은 이어지는 구문은 같은 줄
                if (nk == TokenKind.While && !IsDoWhile(toks, idx)) { SoftNewLine(); return; }
                idx = n - 1;
                prevEnd = toks[n].Extent.StartOffset;
                sb.Append(' ');
                lineStart = false;
                return;
            }
            if (nk is TokenKind.RParen or TokenKind.Comma or TokenKind.Dot or TokenKind.Pipe or TokenKind.RBracket or TokenKind.RCurly)
            {
                if (nk == TokenKind.RCurly) { SoftNewLine(); return; }
                idx = n - 1;
                prevEnd = toks[n].Extent.StartOffset;
                return;
            }
            if (stack.Count > 0 && stack.Peek() == '(') return;
            SoftNewLine();
        }
    }

    static bool IsDoWhile(Token[] toks, int closeIdx)
    {
        // 매우 단순한 휴리스틱: 블록 앞에 do 가 있는지
        int depth = 0;
        for (int i = closeIdx; i >= 0; i--)
        {
            if (toks[i].Kind == TokenKind.RCurly) depth++;
            else if (toks[i].Kind == TokenKind.LCurly)
            {
                depth--;
                if (depth == 0)
                {
                    int p = i - 1;
                    while (p >= 0 && toks[p].Kind == TokenKind.NewLine) p--;
                    return p >= 0 && toks[p].Kind == TokenKind.Do;
                }
            }
        }
        return false;
    }

    #endregion
}
