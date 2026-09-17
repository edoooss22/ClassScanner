using System.IO.Compression;
using System.Text;

namespace ClassScan;

internal sealed class JarIndex
{
    private readonly Dictionary<string, List<string>> _classes = new(StringComparer.Ordinal);
    private Dictionary<string, List<string>>? _packages;

    public List<string> Jars { get; } = new();
    public List<string> Errors { get; } = new();
    public int ClassCount => _classes.Count;
    public IEnumerable<string> AllClasses => _classes.Keys;

    public bool Contains(string internalName) => _classes.ContainsKey(internalName);

    public IReadOnlyList<string>? JarsOf(string internalName) =>
        _classes.TryGetValue(internalName, out var v) ? v : null;

    public (string Package, IReadOnlyList<string> Jars)? OwningPackage(string internalName)
    {
        if (internalName.Length == 0) return null;
        var pkgs = Packages();
        int cut = internalName.LastIndexOf('/');
        while (cut > 0)
        {
            string pkg = internalName.Substring(0, cut);
            if (pkg.Contains('/') && pkgs.TryGetValue(pkg, out var jars)) return (pkg, jars);
            cut = pkg.LastIndexOf('/');
        }
        return null;
    }

    private Dictionary<string, List<string>> Packages()
    {
        if (_packages is not null) return _packages;
        var res = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var kv in _classes)
        {
            int slash = kv.Key.LastIndexOf('/');
            if (slash <= 0) continue;
            string pkg = kv.Key.Substring(0, slash);
            if (!res.TryGetValue(pkg, out var l)) res[pkg] = l = new List<string>();
            foreach (string j in kv.Value)
                if (!l.Contains(j)) l.Add(j);
        }
        _packages = res;
        return res;
    }

    public static JarIndex Build(Target t)
    {
        var idx = new JarIndex();

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in t.Regions)
        {
            string? p = r.MappedFile;
            if (p is null || !seen.Add(p)) continue;
            if (p.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) idx.AddJar(p);
        }

        string cmd = t.CommandLine ?? "";
        var tokens = Tokenize(cmd).ToList();
        foreach (var token in tokens)
        {
            if (token.StartsWith('@'))
            {
                try
                {
                    string argFile = token[1..].Trim('"');
                    if (File.Exists(argFile))
                        foreach (var t2 in Tokenize(File.ReadAllText(argFile)))
                            idx.AddClassPath(t2);
                }
                catch { }
            }
            idx.AddClassPath(token);
        }

        var roots = new List<string>();
        string cwd = t.CurrentDirectory ?? "";
        if (cwd.Length > 3) roots.Add(cwd);
        for (int i = 0; i + 1 < tokens.Count; i++)
            if (tokens[i] is "--gameDir" or "--workDir" && tokens[i + 1].Length > 3)
                roots.Add(tokens[i + 1].Trim('"'));

        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            idx.AddDirectory(Path.Combine(root, "mods"), recursive: true);
            idx.AddDirectory(Path.Combine(root, "versions"), recursive: true);
            idx.AddDirectory(Path.Combine(root, "libraries"), recursive: true);
            idx.AddDirectory(Path.Combine(root, ".fabric"), recursive: true);
            idx.AddDirectory(root);
        }
        return idx;
    }

    private void AddClassPath(string token)
    {
        string s = token.Trim().Trim('"');
        if (s.Length == 0 || !s.Contains(".jar", StringComparison.OrdinalIgnoreCase)) return;
        foreach (var part in s.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            string p = part;
            int eq = p.IndexOf('=');
            if (eq >= 0 && p.StartsWith('-')) p = p[(eq + 1)..];
            p = p.Trim('"');
            if (p.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) AddJar(p);
        }
    }

    private static IEnumerable<string> Tokenize(string s)
    {
        bool q = false;
        var cur = new StringBuilder();
        foreach (char ch in s)
        {
            if (ch == '"') { q = !q; continue; }
            if (!q && ch is ' ' or '\r' or '\n' or '\t')
            {
                if (cur.Length > 0) { yield return cur.ToString(); cur.Clear(); }
                continue;
            }
            cur.Append(ch);
        }
        if (cur.Length > 0) yield return cur.ToString();
    }

    public void AddJar(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return; }
        if (Jars.Contains(full, StringComparer.OrdinalIgnoreCase)) return;
        if (!File.Exists(full)) return;

        Jars.Add(full);
        try
        {
            using var zip = ZipFile.OpenRead(full);
            foreach (var e in zip.Entries)
            {
                string n = e.FullName;
                if (n.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                    AddClass(n[..^6].Replace('\\', '/'), full);
                else if (n.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) &&
                         e.Length is > 0 and < 64 * 1024 * 1024)
                    AddNestedJar(full, e);
            }
        }
        catch (Exception ex)
        {
            Errors.Add($"{Path.GetFileName(full)}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void AddClass(string cn, string source)
    {
        if (cn.StartsWith("META-INF/versions/", StringComparison.OrdinalIgnoreCase))
        {
            int slash = cn.IndexOf('/', 18);
            if (slash < 0) return;
            cn = cn[(slash + 1)..];
        }
        else if (cn.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase)) return;
        if (cn.Length == 0 || cn == "module-info") return;
        if (!_classes.TryGetValue(cn, out var list))
            _classes[cn] = list = new List<string>(1);
        if (list.Count < 8) list.Add(source);
    }

    private void AddNestedJar(string outerPath, ZipArchiveEntry entry)
    {
        try
        {
            using var s = entry.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            ms.Position = 0;
            using var inner = new ZipArchive(ms, ZipArchiveMode.Read);
            string tag = $"{outerPath}!{entry.FullName}";
            foreach (var e in inner.Entries)
                if (e.FullName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                    AddClass(e.FullName[..^6].Replace('\\', '/'), tag);
        }
        catch { }
    }

    public void AddDirectory(string dir, bool recursive = false, int limit = 4000)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            var opt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            int n = 0;
            foreach (var f in Directory.EnumerateFiles(dir, "*.jar", opt))
            {
                AddJar(f);
                if (++n >= limit) break;
            }
        }
        catch (Exception ex) { Errors.Add($"{dir}: {ex.Message}"); }
    }

    public static bool IsRuntimeClass(string name) =>
        name.StartsWith("java/", StringComparison.Ordinal) ||
        name.StartsWith("javax/", StringComparison.Ordinal) ||
        name.StartsWith("jdk/", StringComparison.Ordinal) ||
        name.StartsWith("sun/", StringComparison.Ordinal) ||
        name.StartsWith("com/sun/", StringComparison.Ordinal) ||
        name.StartsWith("org/w3c/", StringComparison.Ordinal) ||
        name.StartsWith("org/xml/", StringComparison.Ordinal) ||
        name.StartsWith("org/ietf/", StringComparison.Ordinal) ||
        name.StartsWith("org/jcp/", StringComparison.Ordinal) ||
        name.StartsWith("netscape/", StringComparison.Ordinal);

    public static string? GeneratedKind(string name)
    {
        if (name.Contains("$$Lambda", StringComparison.Ordinal)) return "лямбда JVM";
        if (name.Contains("/0x", StringComparison.Ordinal) ||
            name.Contains("+0x", StringComparison.Ordinal)) return "скрытый класс";
        if (name.StartsWith("com/sun/proxy/", StringComparison.Ordinal) ||
            name.Contains("$Proxy", StringComparison.Ordinal)) return "динамический прокси";
        if (name.Contains("GeneratedMethodAccessor", StringComparison.Ordinal) ||
            name.Contains("GeneratedConstructorAccessor", StringComparison.Ordinal) ||
            name.Contains("GeneratedSerializationConstructor", StringComparison.Ordinal))
            return "акцессор рефлексии";
        if (name.Contains("$$EnhancerBy", StringComparison.Ordinal) ||
            name.Contains("$$FastClassBy", StringComparison.Ordinal)) return "CGLIB";
        if (name.StartsWith("org/spongepowered/asm/synthetic/", StringComparison.Ordinal))
            return "синтетика Mixin";
        if (name.Contains("$Anonymous$", StringComparison.Ordinal)) return "анонимный класс Mixin";
        if (name.Contains("mixinextras/sugar/impl/ref/generated/", StringComparison.Ordinal))
            return "генерация MixinExtras";
        if (name.Contains("$$InjectedInvoker", StringComparison.Ordinal) ||
            name.EndsWith("InjectedInvoker", StringComparison.Ordinal))
            return "инвокер ByteBuddy/Mixin";
        if (name.StartsWith("net/bytebuddy/renamed/", StringComparison.Ordinal) ||
            name.Contains("$ByteBuddy$", StringComparison.Ordinal)) return "генерация ByteBuddy";
        if (name.StartsWith('[')) return "массив";
        return null;
    }
}
