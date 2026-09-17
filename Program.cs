using System.Diagnostics;
using System.Text;

namespace ClassScan;

internal static class Program
{
    public const string Version = "1.0";

    private static bool _wait = true;
    private static bool _all;
    private static string? _outDir;
    private static bool _heuristic;

    private static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        Console.Title = "ClassScan";

        int pid = 0;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--pid" when i + 1 < args.Length: int.TryParse(args[++i], out pid); break;
                case "--nowait": _wait = false; break;
                case "--all": _all = true; break;
                case "--out" when i + 1 < args.Length: _outDir = args[++i]; break;
                case "--heuristic": _heuristic = true; break;
                case "-h" or "--help" or "/?":
                    Console.WriteLine($"""
                    ClassScan {Version} — проверка классов Java в процессе Minecraft:
                    происхождение (архив на диске), пакет, загрузчики, почерк имён.

                      --pid N    проверить конкретный процесс (по умолчанию javaw с наибольшим рабочим множеством)
                      --all      печатать полные списки и таблицу загрузчиков
                      --out DIR  каталог для HTML-отчёта (по умолчанию reports рядом с exe)
                      --nowait   не ждать клавишу в конце
                      --heuristic  не использовать раскладку структур ВМ, искать объекты Klass по памяти
                                   (запасной путь; включается сам, если раскладка не найдена)

                    После проверки пишется HTML-отчёт с фильтрами, поиском и полными данными.

                    Коды возврата: 1 DETECTED, 0 UNDETECTED, 2 процесс не найден, 3 ошибка чтения,
                    5 jvm.dll не загружен или граф классов не построен.
                    """);
                    return 0;
                default:
                    if (int.TryParse(args[i], out int bare) && pid == 0) pid = bare;
                    break;
            }
        }

        Native.EnablePrivilege("SeDebugPrivilege");

        Process? process = null;
        try { process = pid > 0 ? Process.GetProcessById(pid) : Target.FindJavaw(); }
        catch { }
        if (process is null)
        {
            Line(pid > 0 ? $"{pid} - процесс не найден" : "javaw.exe не найден", ConsoleColor.Red);
            Wait();
            return 2;
        }

        Target target;
        try { target = Target.Open(process); }
        catch (Exception ex)
        {
            Line($"{process.Id} - ошибка открытия процесса: {ex.Message}", ConsoleColor.Red);
            Wait();
            return 3;
        }

        string head = $"{target.Pid} - {(target.Window.Length > 0 ? target.Window : "(без окна)")}";
        Line($"[+] Процесс: {target.Name} (pid {target.Pid}), рабочее множество {target.WorkingSet / (1024 * 1024)} МБ",
            ConsoleColor.Gray);
        Line($"    {target.Path}", ConsoleColor.DarkGray);

        if (target.Wow64)
        {
            target.Dispose();
            Line($"{head} - CLASSSCAN UNKNOWN (процесс 32-разрядный)", ConsoleColor.Yellow);
            Wait();
            return 3;
        }

        var sw = Stopwatch.StartNew();
        Analysis analysis;
        ClassGraph graph;
        JarIndex jars;
        var input = new ReportInput { Target = target };
        try
        {
            var images = target.FindImages("jvm.dll");
            if (images.Count == 0)
            {
                target.Dispose();
                Line($"{head} - CLASSSCAN UNKNOWN (jvm.dll не загружен)", ConsoleColor.Yellow);
                Wait();
                return 5;
            }
            var (jvmBase, jvmPath) = images[0];
            input.JvmBase = jvmBase;
            input.JvmPath = jvmPath;
            var jvm = PeImage.FromMemory(target, jvmBase);
            if (jvm is null)
            {
                target.Dispose();
                Line($"{head} - CLASSSCAN UNKNOWN (заголовок jvm.dll не читается)", ConsoleColor.Yellow);
                Wait();
                return 5;
            }
            Line($"[+] jvm.dll: 0x{jvmBase:X}  {jvmPath}  экспортов {jvm.Exports.Count}", ConsoleColor.Gray);

            var vm = _heuristic ? new VmStructs() : VmStructs.Load(target, jvm);
            input.Vm = vm;
            Line($"[+] Раскладка структур ВМ: {(vm.Valid ? $"{vm.Count} полей ({vm.Source})" : "не найдена")}",
                vm.Valid ? ConsoleColor.Gray : ConsoleColor.Yellow);

            Line("[+] Обход графа загрузчиков классов...", ConsoleColor.Gray);
            graph = ClassGraph.Build(target, jvm, vm);
            if (!graph.Walked)
            {
                target.Dispose();
                Line($"{head} - CLASSSCAN UNKNOWN (граф классов не построен: {graph.Problem})", ConsoleColor.Yellow);
                Wait();
                return 5;
            }
            Line($"    источник: {graph.Source}; загрузчиков {graph.Loaders.Count}, классов {graph.Klasses.Count}" +
                 (graph.BytesScanned > 0 ? $", просмотрено {graph.BytesScanned / (1024 * 1024)} МБ" : ""),
                ConsoleColor.Gray);

            Line("[+] Индекс архивов игры...", ConsoleColor.Gray);
            jars = JarIndex.Build(target);
            Line($"    архивов {jars.Jars.Count}, классов в архивах {jars.ClassCount}" +
                 (jars.Errors.Count > 0 ? $", не прочитано {jars.Errors.Count}" : ""),
                jars.ClassCount > 100 ? ConsoleColor.Gray : ConsoleColor.Yellow);

            analysis = Analysis.Run(graph, jars, target.CommandLine ?? "");
            input.Graph = graph;
            input.Jars = jars;
            input.Analysis = analysis;
            input.Elapsed = sw.Elapsed;
        }
        catch (Exception ex)
        {
            target.Dispose();
            Line($"{head} - CLASSSCAN UNKNOWN (ошибка чтения: {ex.Message})", ConsoleColor.Yellow);
            Wait();
            return 3;
        }
        sw.Stop();

        string? reportPath = null;
        try
        {
            string outDir = _outDir ?? Path.Combine(AppContext.BaseDirectory, "reports");
            Directory.CreateDirectory(outDir);
            reportPath = Path.Combine(outDir, $"classscan-{target.Pid}-{DateTime.Now:yyyyMMdd-HHmmss}.html");
            File.WriteAllText(reportPath, HtmlReport.Render(input), new UTF8Encoding(false));
        }
        catch (Exception ex)
        {
            Line($"Отчёт HTML не записан: {ex.GetType().Name}: {ex.Message}", ConsoleColor.Yellow);
            reportPath = null;
        }
        target.Dispose();

        Line($"    игра на промежуточных именах Fabric: {(analysis.GameIsRemapped ? "да" : "нет")} " +
             $"(class_NNN в процессе: {analysis.IntermediaryCount}, имён в стиле обфускатора игры в архивах: {analysis.VanillaInJars})",
            ConsoleColor.DarkGray);

        if (_all) PrintLoaders(graph, analysis, jars);
        PrintFindings(analysis);

        Console.WriteLine();
        Line($"Проверено за {sw.Elapsed.TotalSeconds:F1} с", ConsoleColor.DarkGray);
        if (reportPath is not null) Line($"Отчёт HTML: {reportPath}   ← открыть в браузере", ConsoleColor.Gray);
        if (analysis.Detected) Line($"{head} - CLASSSCAN DETECTED", ConsoleColor.Red);
        else Line($"{head} - CLASSSCAN UNDETECTED", ConsoleColor.Green);

        Wait();
        return analysis.Detected ? 1 : 0;
    }

    private static void PrintLoaders(ClassGraph graph, Analysis a, JarIndex jars)
    {
        Console.WriteLine();
        Line("ЗАГРУЗЧИКИ И ЧИСЛО КЛАССОВ В КАЖДОМ", ConsoleColor.White);
        var byCld = a.Rows.GroupBy(r => r.K.Loader!.Address).ToDictionary(x => x.Key, x => x.ToList());
        int hidden = 0;
        foreach (var l in graph.Loaders.OrderByDescending(x => x.Klasses.Count))
        {
            if (l.HiddenClassHolder) { hidden++; continue; }
            byCld.TryGetValue(l.Address, out var rows);
            int noOrigin = rows?.Count(r => r.Origin is Origin.None or Origin.VanillaForeign) ?? 0;
            Line($"  0x{l.Address:X}  {l.LoaderClass,-64} классов {l.Klasses.Count,-7} без происхождения {noOrigin}" +
                 (l.Bootstrap ? "  [начальный]" : l.Privileged ? "  [привилегированный]" : "") +
                 (l.LoaderIsHiddenClass ? "  [СКРЫТЫЙ КЛАСС]" : ""),
                noOrigin > 0 ? ConsoleColor.Yellow : ConsoleColor.Gray);
        }
        if (hidden > 0) Line($"  записей скрытых классов (по одной на класс): {hidden}", ConsoleColor.DarkGray);

        Console.WriteLine();
        Line("ПРОИНДЕКСИРОВАННЫЕ АРХИВЫ", ConsoleColor.White);
        foreach (var j in jars.Jars.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            Line("  " + j, ConsoleColor.DarkGray);
        foreach (var e in jars.Errors.Take(50)) Line("  не прочитан: " + e, ConsoleColor.Yellow);

        Console.WriteLine();
        Line("КЛАССЫ ПО ПРОИСХОЖДЕНИЮ", ConsoleColor.White);
        foreach (var g in a.Rows.GroupBy(r => r.Origin).OrderByDescending(g => g.Count()))
            Line($"  {g.Count(),8}  {g.Key switch
            {
                Origin.Runtime => "стандартная библиотека Java",
                Origin.Generated => "порождены рантаймом (лямбды, прокси, скрытые классы)",
                Origin.Array => "массивы",
                Origin.Jar => "есть в архиве на диске",
                Origin.OwnedPackage => "нет в архиве, но пакет принадлежит архиву",
                Origin.VanillaForeign => "имя в стиле обфускатора игры при игре на промежуточных именах",
                Origin.Torn => "имя из освобождённой памяти (не разбирается)",
                _ => "БЕЗ ПРОИСХОЖДЕНИЯ",
            }}", ConsoleColor.Gray);
    }

    private static void PrintFindings(Analysis a)
    {
        Console.WriteLine();
        if (a.Findings.Count == 0)
        {
            Line("Находок нет.", ConsoleColor.Green);
            return;
        }

        const int limit = 40;
        foreach (var f in a.Findings)
        {
            var color = f.Severity switch
            {
                Severity.Critical => ConsoleColor.Red,
                Severity.High => ConsoleColor.Red,
                Severity.Medium => ConsoleColor.Yellow,
                Severity.Low => ConsoleColor.Yellow,
                _ => ConsoleColor.Cyan,
            };
            Console.WriteLine();
            Line($"[{Label(f.Severity)}] {f.Title}", color);
            foreach (string w in Wrap(f.Why, 110)) Line("    " + w, ConsoleColor.DarkGray);
            var lines = _all ? f.Lines : f.Lines.Take(limit).ToList();
            foreach (string l in lines) Line("      " + l, f.Severity >= Severity.Medium ? ConsoleColor.Gray : ConsoleColor.DarkGray);
            if (f.Lines.Count > lines.Count)
                Line($"      … ещё {f.Lines.Count - lines.Count} (полный список: --all)", ConsoleColor.DarkGray);
        }
    }

    private static string Label(Severity s) => s switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => "INFO",
    };

    private static IEnumerable<string> Wrap(string text, int width)
    {
        var sb = new StringBuilder();
        foreach (string word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (sb.Length + word.Length + 1 > width) { yield return sb.ToString(); sb.Clear(); }
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(word);
        }
        if (sb.Length > 0) yield return sb.ToString();
    }

    private static void Line(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    private static void Wait()
    {
        if (!_wait) return;
        Console.WriteLine();
        Console.WriteLine("Нажмите любую клавишу, чтобы закрыть окно.");
        try { Console.ReadKey(true); } catch { }
    }
}
