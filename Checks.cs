namespace ClassScan;

internal enum Severity { Info, Low, Medium, High, Critical }

internal sealed class Finding
{
    public Severity Severity;
    public string Category = "КЛАССЫ";
    public string Title = "";
    public string Why = "";
    public List<string> Lines = new();

    public Finding Add(string line) { Lines.Add(line); return this; }
}

internal enum Origin { Runtime, Generated, Array, Jar, OwnedPackage, VanillaForeign, None, Torn }

internal sealed class ClassRow
{
    public KlassRec K = null!;
    public string Name = "";
    public string Plain = "";
    public Origin Origin;
    public string OwningPackage = "";
    public bool InJar;
    public bool NonAscii;
    public bool IllegalChar;
    public bool Confusable;
    public bool RandomLike;
    public bool Intermediary;
    public bool VanillaStyle;
    public bool NoPackage;

    public string Loader => K.Loader?.LoaderClass ?? "?";
}

internal sealed class Analysis
{
    public List<ClassRow> Rows = new();
    public List<Finding> Findings = new();
    public bool GameIsRemapped;
    public int IntermediaryCount;
    public int VanillaInJars;
    public bool JarsUsable;

    public Severity Max => Findings.Count == 0 ? Severity.Info : Findings.Max(f => f.Severity);
    public bool Detected => Max >= Severity.High;

    public static Analysis Run(ClassGraph g, JarIndex jars, string commandLine)
    {
        var a = new Analysis { JarsUsable = jars.ClassCount > 100 };
        a.Classify(g, jars);
        a.CheckOrphans(jars);
        a.CheckNoPackage();
        a.CheckDuplicateLoaders(g);
        a.CheckDuplicateClasses(g);
        a.CheckPrivilegedLoaders(g, commandLine);
        a.CheckHiddenLoaders(g);
        a.CheckIsolatedLoaders(g);
        a.CheckNames();
        a.Findings = a.Findings.OrderByDescending(f => f.Severity).ToList();
        return a;
    }

    // ------------------------------------------------------------ разметка

    private void Classify(ClassGraph g, JarIndex jars)
    {
        VanillaInJars = JarsUsable ? jars.AllClasses.Count(JavaNames.IsVanillaObf) : 0;

        foreach (var k in g.Klasses)
        {
            if (k.Name.Length == 0) continue;
            var r = new ClassRow { K = k, Name = k.Name };
            r.NonAscii = JavaNames.HasNonAscii(k.Name);
            r.Plain = JavaNames.StripHiddenMarker(r.NonAscii ? JavaNames.StripEscapes(k.Name) : k.Name);
            r.IllegalChar = JavaNames.HasIllegalChar(r.Plain);
            r.InJar = jars.Contains(k.Name);

            string simple = JavaNames.SimpleName(r.Plain);
            r.Intermediary = JavaNames.IsIntermediary(simple);
            if (r.Intermediary) IntermediaryCount++;
            r.VanillaStyle = !r.NonAscii && !r.IllegalChar && JavaNames.IsVanillaObf(r.Plain);
            r.NoPackage = !k.Name.StartsWith('[') && !k.Name.Contains('/');
            if (!r.Intermediary && !r.VanillaStyle && !r.NonAscii)
            {
                r.Confusable = JavaNames.IsConfusable(simple);
                r.RandomLike = JavaNames.IsRandomLike(simple);
            }
            Rows.Add(r);
        }

        GameIsRemapped = IntermediaryCount >= 500 || (JarsUsable && VanillaInJars < 16);

        foreach (var r in Rows)
        {
            if (JavaNames.LooksLikeFreedMemory(r.Name)) { r.Origin = Origin.Torn; continue; }
            if (r.Name.StartsWith('[')) { r.Origin = Origin.Array; continue; }
            if (JarIndex.IsRuntimeClass(r.Plain)) { r.Origin = Origin.Runtime; continue; }
            if (!r.NonAscii && JarIndex.GeneratedKind(r.Plain) is not null) { r.Origin = Origin.Generated; continue; }
            if (GameIsRemapped && r.VanillaStyle) { r.Origin = Origin.VanillaForeign; continue; }
            if (r.InJar) { r.Origin = Origin.Jar; continue; }
            var own = jars.OwningPackage(r.Name);
            if (own is not null)
            {
                r.Origin = Origin.OwnedPackage;
                r.OwningPackage = own.Value.Package;
                continue;
            }
            r.Origin = Origin.None;
        }
    }

    private static bool Live(ClassRow r) => r.Origin is not (Origin.Torn or Origin.Array);

    private static bool HasOrigin(ClassRow r) =>
        r.Origin is Origin.Runtime or Origin.Generated or Origin.Jar or Origin.OwnedPackage;

    private static string Describe(ClassRow r) =>
        $"{r.Name}   [{r.Loader}]" + (r.Origin == Origin.VanillaForeign
            ? (r.InJar ? "   (имя в стиле обфускатора игры, есть в архиве — но игра работает на промежуточных именах)"
                       : "   (имя в стиле обфускатора игры, в архивах нет)")
            : "");

    // ------------------------------------------------------------ проверки

    private void CheckOrphans(JarIndex jars)
    {
        if (jars.ClassCount == 0)
        {
            Findings.Add(new Finding
            {
                Severity = Severity.Low,
                Title = $"Архивы игры не проиндексированы (классов в индексе: {jars.ClassCount}) — " +
                        "проверка происхождения классов не выполнена",
                Why = "Не удалось найти jar-файлы игры: ни по проекциям в памяти, ни по командной строке, " +
                      "ни по каталогам mods/versions/libraries относительно рабочего каталога процесса.",
            });
            return;
        }

        var owned = Rows.Where(r => r.Origin == Origin.OwnedPackage).ToList();
        if (owned.Count > 0)
        {
            var f = new Finding
            {
                Severity = Severity.Info,
                Title = $"{owned.Count} классов отсутствуют в архивах, но лежат в пакетах, принадлежащих архивам " +
                        "(код, порождённый модами во время работы)",
                Why = "Пакет-предок класса есть в архиве на диске: так выглядят классы, которые моды собирают на ходу " +
                      "(Sodium, ViaVersion, Mixin). У постороннего кода не нашлось бы даже пакета-предка.",
            };
            foreach (var r in owned.OrderBy(x => x.Name, StringComparer.Ordinal))
                f.Add($"{r.Name}   пакет «{r.OwningPackage}»   [{r.Loader}]");
            Findings.Add(f);
        }

        var orphans = Rows.Where(r => r.Origin is Origin.None or Origin.VanillaForeign && !r.NoPackage).ToList();
        if (orphans.Count == 0) return;

        int vanilla = orphans.Count(r => r.Origin == Origin.VanillaForeign);
        var f2 = new Finding
        {
            Severity = vanilla > 0 && GameIsRemapped ? Severity.Critical
                : orphans.Count >= 8 ? Severity.High : Severity.Medium,
            Title = $"{orphans.Count} загруженных классов нет ни в одном архиве, доступном игре" +
                    (vanilla > 0 ? $" (из них {vanilla} названы в стиле обфускатора игры)" : ""),
            Why = "Класс числится живым в графе загрузчиков ВМ, но его нет ни в одном из архивов, из которых игра " +
                  "может грузить код (командная строка, mods, versions, libraries, открытые процессом jar). " +
                  "Лямбды, прокси, скрытые классы и классы стандартной библиотеки исключены. Такой класс " +
                  "определили программно: Unsafe.defineClass, Lookup.defineClass, агент, JNI DefineClass." +
                  (vanilla > 0 && GameIsRemapped
                      ? " Игра работает на промежуточных именах Fabric (class_NNN), поэтому короткие имена из " +
                        "строчных букв среди загруженных классов принадлежать игре не могут."
                      : ""),
        };
        foreach (var g in orphans.GroupBy(r => JavaNames.Package(r.Name)).OrderByDescending(g => g.Count()))
            f2.Add($"пакет «{g.Key}»: {g.Count()} классов");
        f2.Add("");
        foreach (var r in orphans.OrderBy(x => x.Name, StringComparer.Ordinal))
            f2.Add(Describe(r));
        Findings.Add(f2);
    }

    private void CheckNoPackage()
    {
        var all = Rows.Where(r => r.NoPackage && Live(r) && r.Origin != Origin.Generated).ToList();
        if (all.Count == 0) return;

        var inJar = all.Where(r => r.InJar && r.Origin != Origin.VanillaForeign).ToList();
        var foreign = all.Where(r => !r.InJar || r.Origin == Origin.VanillaForeign).ToList();

        if (inJar.Count > 0)
            Findings.Add(new Finding
            {
                Severity = Severity.Info,
                Title = $"{inJar.Count} классов без пакета загружены из архивов игры",
                Why = "Классы в пакете по умолчанию есть в архиве на диске: так устроена необфусцированная " +
                      "сборка без Fabric (классы «a», «bb», «czc» лежат прямо в jar игры).",
                Lines = inJar.OrderBy(x => x.Name, StringComparer.Ordinal).Select(Describe).ToList(),
            });

        if (foreign.Count == 0) return;
        Findings.Add(new Finding
        {
            Severity = GameIsRemapped || !JarsUsable ? Severity.Critical : Severity.High,
            Title = $"{foreign.Count} загруженных классов без пакета, которых нет в архивах игры",
            Why = "Имя класса без пакета — почерк либо обфускатора игры (тогда класс обязан лежать в jar игры), " +
                  "либо инжекта: код чита кладётся в пакет по умолчанию, чтобы не выдавать себя именем. " +
                  "Ни один мод так классы не называет." +
                  (GameIsRemapped ? " Игра работает на промежуточных именах Fabric — классов без пакета у неё нет вовсе." : ""),
            Lines = foreign.OrderBy(x => x.Name, StringComparer.Ordinal).Select(Describe).ToList(),
        });
    }

    private void CheckDuplicateLoaders(ClassGraph g)
    {
        var boot = g.Loaders.Where(l => l.Bootstrap).ToList();
        if (boot.Count > 1)
        {
            var f = new Finding
            {
                Severity = Severity.High,
                Category = "ЗАГРУЗЧИКИ",
                Title = $"В графе {boot.Count} объектов загрузчика с пустой ссылкой на объект-загрузчик, а должен быть один",
                Why = "Загрузчик начальной загрузки в ВМ единственный. Записи скрытых классов тоже без объекта-загрузчика, " +
                      "но у них поднят признак держателя зеркала и они здесь не учитываются. Вторая запись без признака — " +
                      "структура, созданная в обход штатного пути.",
            };
            foreach (var l in boot)
                f.Add($"ClassLoaderData 0x{l.Address:X}: классов {l.Klasses.Count}: " +
                      string.Join(", ", l.Klasses.Take(6).Select(k => k.Name)));
            Findings.Add(f);
        }

        var groups = g.Loaders
            .Where(l => !l.HiddenClassHolder && l.LoaderOop is not (0 or ulong.MaxValue) && !l.LoaderIsHiddenClass)
            .GroupBy(l => l.LoaderClass, StringComparer.Ordinal)
            .Where(x => x.Count() > 1)
            .ToList();
        if (groups.Count == 0) return;

        var byCld = Rows.GroupBy(r => r.K.Loader!.Address).ToDictionary(x => x.Key, x => x.ToList());
        bool armed = false;
        var f2 = new Finding
        {
            Category = "ЗАГРУЗЧИКИ",
            Title = $"Дубликаты загрузчиков: {groups.Count} классов загрузчика имеют несколько экземпляров",
            Why = "Каждый экземпляр загрузчика — своя запись ClassLoaderData со своим набором классов. У чистого клиента " +
                  "загрузчики игры существуют по одному (Knot, AppClassLoader); второй экземпляр того же класса " +
                  "загрузчика создаёт код, который хочет грузить классы отдельно от игры. Штатно так выглядят " +
                  "загрузчики плагинов, скриптов и вспомогательные загрузчики Fabric — смотрите, что в них лежит.",
        };
        foreach (var grp in groups)
        {
            f2.Add($"{grp.Key}: экземпляров {grp.Count()}");
            foreach (var l in grp.OrderByDescending(l => l.Klasses.Count))
            {
                byCld.TryGetValue(l.Address, out var rows);
                int noOrigin = rows?.Count(r => r.Origin is Origin.None or Origin.VanillaForeign) ?? 0;
                armed |= noOrigin > 0;
                f2.Add($"    0x{l.Address:X}  классов {l.Klasses.Count}, без происхождения {noOrigin}: " +
                       string.Join(", ", l.Klasses.Take(4).Select(k => k.Name)));
            }
        }
        f2.Severity = armed ? Severity.High : Severity.Info;
        Findings.Add(f2);
    }

    private void CheckDuplicateClasses(ClassGraph g)
    {
        var dup = Rows
            .Where(r => Live(r) && r.Origin != Origin.Generated && r.K.Loader is { HiddenClassHolder: false })
            .GroupBy(r => r.Name, StringComparer.Ordinal)
            .Where(x => x.Select(r => r.K.Loader!.Address).Distinct().Count() > 1)
            .ToList();
        if (dup.Count == 0) return;

        var game = dup.Where(x => x.Key.StartsWith("net/minecraft/", StringComparison.Ordinal) ||
                                  x.Key.StartsWith("com/mojang/", StringComparison.Ordinal) ||
                                  x.Key.StartsWith("net/fabricmc/", StringComparison.Ordinal))
            .ToList();
        var f = new Finding
        {
            Severity = game.Count > 0 ? Severity.Medium : Severity.Info,
            Title = $"{dup.Count} классов загружены одновременно несколькими загрузчиками" +
                    (game.Count > 0 ? $" (из них классов игры: {game.Count})" : ""),
            Why = "Одно имя в двух загрузчиках — две независимые копии класса. Для библиотек это бывает штатно " +
                  "(AppClassLoader и Knot грузят свои копии ASM), но копия класса игры под чужим загрузчиком — " +
                  "то, что делает Java-чит, подменяющий или затеняющий классы игры.",
        };
        foreach (var x in game.Concat(dup.Except(game)).Take(400))
            f.Add($"{x.Key}: " + string.Join(", ", x.Select(r => $"{r.Loader} (0x{r.K.Loader!.Address:X})").Distinct()));
        Findings.Add(f);
    }

    private void CheckPrivilegedLoaders(ClassGraph g, string commandLine)
    {
        var hits = new List<ClassRow>();
        foreach (var r in Rows)
        {
            var l = r.K.Loader;
            if (l is null || l.LoaderOop == ulong.MaxValue || l.HiddenClassHolder || !l.Privileged) continue;
            if (!Live(r) || r.Origin is Origin.Runtime or Origin.Generated) continue;
            hits.Add(r);
        }
        if (hits.Count == 0) return;

        bool bootcp = commandLine.Contains("-Xbootclasspath", StringComparison.OrdinalIgnoreCase);
        var f = new Finding
        {
            Severity = Severity.Critical,
            Category = "ЗАГРУЗЧИКИ",
            Title = $"{hits.Count} классов загружены привилегированным загрузчиком, хотя не принадлежат образу JDK",
            Why = "Загрузчик начальной загрузки и платформенный берут классы только из образа рантайма JDK " +
                  "(java/, jdk/, sun/, javax/). Классы игры и модов грузит загрузчик Fabric и попасть сюда не могут. " +
                  "Способов ровно два: -Xbootclasspath/a: в командной строке" +
                  (bootcp ? " (В КОМАНДНОЙ СТРОКЕ ЕСТЬ -Xbootclasspath)" : " (в командной строке его нет)") +
                  " либо JNI DefineClass с пустым загрузчиком из нативного кода — так шеллкод определяет " +
                  "принесённый с собой байт-код, не оставляя ни файла, ни записи в графе пользовательских загрузчиков.",
        };
        foreach (var r in hits.OrderBy(x => x.Name, StringComparer.Ordinal))
            f.Add($"{r.Name}   [{r.Loader}]   " + (r.InJar ? "есть в архивах на диске"
                : r.Origin == Origin.OwnedPackage ? $"нет в архивах, пакет-предок «{r.OwningPackage}» есть"
                : "НЕТ В АРХИВАХ"));
        Findings.Add(f);
    }

    private void CheckHiddenLoaders(ClassGraph g)
    {
        var hits = g.Loaders.Where(l => l.LoaderOop != ulong.MaxValue && l.LoaderIsHiddenClass).ToList();
        if (hits.Count == 0) return;

        var f = new Finding
        {
            Severity = Severity.Critical,
            Category = "ЗАГРУЗЧИКИ",
            Title = $"{hits.Count} загрузчиков классов сами являются скрытыми классами " +
                    $"(загружено ими классов: {hits.Sum(l => l.Klasses.Count)})",
            Why = "Скрытый класс лишён имени, по которому его можно найти: в имени адрес, в словари имён он не попадает. " +
                  "Штатно так делают только лямбды и переходники java.lang.invoke, и они классов не грузят. " +
                  "Загрузчик делают скрытым ровно затем, чтобы происхождение загруженного им кода нельзя было " +
                  "установить по имени загрузчика.",
        };
        foreach (var l in hits)
        {
            f.Add($"{l.LoaderClass}   ClassLoaderData 0x{l.Address:X}, классов {l.Klasses.Count}");
            foreach (var k in l.Klasses.Take(12)) f.Add($"    загружен им: {k.Name}");
        }
        Findings.Add(f);
    }

    private void CheckIsolatedLoaders(ClassGraph g)
    {
        var byCld = Rows.GroupBy(r => r.K.Loader!.Address).ToDictionary(x => x.Key, x => x.ToList());
        foreach (var l in g.Loaders)
        {
            if (l.HiddenClassHolder || l.Bootstrap || l.LoaderIsHiddenClass) continue;
            if (!byCld.TryGetValue(l.Address, out var rows)) continue;
            var named = rows.Where(Live).ToList();
            if (named.Count == 0 || named.Count > 64) continue;
            if (named.Any(r => r.Origin == Origin.Runtime)) continue;

            var orphans = named.Where(r => r.Origin is Origin.None or Origin.VanillaForeign).ToList();
            var f = new Finding
            {
                Severity = orphans.Count > 0 ? Severity.High : Severity.Info,
                Category = "ЗАГРУЗЧИКИ",
                Title = $"Отдельный загрузчик {l.LoaderClass} (0x{l.Address:X}) содержит {named.Count} классов" +
                        (orphans.Count > 0 ? $", из них {orphans.Count} без происхождения на диске" : ""),
                Why = "Небольшой изолированный набор классов под собственным загрузчиком. Так выглядят и штатные " +
                      "загрузчики скриптов и плагинов, и инжект через собственный URLClassLoader. Решает " +
                      "происхождение: классы штатного загрузчика лежат в архивах, классы инжекта — нет.",
            };
            foreach (var r in named.OrderByDescending(r => r.Origin is Origin.None or Origin.VanillaForeign)
                         .ThenBy(r => r.Name, StringComparer.Ordinal))
                f.Add($"{(HasOrigin(r) ? "  " : "!!")} {r.Name}   " + (HasOrigin(r) ? "" : "НЕТ В АРХИВАХ"));
            Findings.Add(f);
        }
    }

    private void CheckNames()
    {
        var live = Rows.Where(r => r.Origin != Origin.Torn && !r.Name.StartsWith('[')).ToList();

        var nonAscii = live.Where(r => r.NonAscii || r.IllegalChar).ToList();
        if (nonAscii.Count > 0)
        {
            var blocks = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var r in nonAscii.Take(400))
            {
                string d = JavaNames.DescribeCodePoints(r.Name);
                if (d.Length > 0) foreach (string x in d.Split(", ")) blocks.Add(x);
            }
            var f = new Finding
            {
                Severity = Severity.Critical,
                Category = "ИМЕНА",
                Title = $"{nonAscii.Count} имён классов содержат символы вне печатаемого ASCII или недопустимые в имени",
                Why = "Имена классов в Minecraft, Fabric и любом моде состоят только из букв, цифр, «_», «$» и «/» — " +
                      "это верно и для обфусцированных сборок. Символы вне ASCII в имени класса — почерк обфускаторов " +
                      "читов: невидимые символы, метки направления письма, омоглифы других алфавитов." +
                      (blocks.Count > 0 ? " Найдены: " + string.Join("; ", blocks) + "." : ""),
            };
            foreach (var grp in nonAscii.GroupBy(r => JavaNames.Package(r.Name)).OrderByDescending(x => x.Count()))
                f.Add($"пакет «{grp.Key}»: {grp.Count()} классов, в архивах: {grp.Count(r => r.InJar)}");
            f.Add("");
            foreach (var r in nonAscii.Take(200))
                f.Add($"{r.Name}   [{r.Loader}]" +
                      (JavaNames.DescribeCodePoints(r.Name) is { Length: > 0 } d ? $"   ← {d}" : ""));
            Findings.Add(f);
        }

        var confusable = live.Where(r => r.Confusable).ToList();
        if (confusable.Count > 0)
            Findings.Add(new Finding
            {
                Severity = Severity.High,
                Category = "ИМЕНА",
                Title = $"{confusable.Count} имён классов состоят только из неразличимых глазом символов (I, l, O, 0, 1)",
                Why = "Приём обфускации: все символы имени выглядят одинаково. Обфускатор Minecraft так не делает, " +
                      "ни один штатный компонент игры и ни один обычный мод таких имён не содержит.",
                Lines = confusable.Select(r => $"{r.Name}   [{r.Loader}]   в архивах: {(r.InJar ? "есть" : "НЕТ")}").ToList(),
            });

        var random = live.Where(r => r.RandomLike && !r.NonAscii && !r.Confusable && !HasOrigin(r)).ToList();
        if (random.Count > 0)
            Findings.Add(new Finding
            {
                Severity = Severity.High,
                Category = "ИМЕНА",
                Title = $"{random.Count} имён классов с почерком стороннего обфускатора отсутствуют в архивах на диске",
                Why = "Длинное имя со смешанным регистром, высокой энтропией и без структуры слова — вывод обфускатора, " +
                      "переименовывающего классы в случайные строки. Само по себе это не улика (часть модов " +
                      "обфусцирована), решает сверка с архивами: класса с таким именем на диске нет.",
                Lines = random.Select(r => $"{r.Name}   [{r.Loader}]").ToList(),
            });
    }
}
