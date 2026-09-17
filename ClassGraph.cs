using System.Text;

namespace ClassScan;

internal sealed class KlassRec
{
    public ulong Address;
    public ulong Cld;
    public string Name = "";
    public Loader? Loader;
}

internal sealed class Loader
{
    public ulong Address;
    public ulong LoaderOop;
    public string LoaderClass = "";
    public bool HiddenClassHolder;
    public List<KlassRec> Klasses = new();

    public bool Bootstrap => LoaderOop == 0 && !HiddenClassHolder;
    public bool Privileged =>
        LoaderOop == 0 ||
        LoaderClass.EndsWith("$PlatformClassLoader", StringComparison.Ordinal) ||
        LoaderClass.EndsWith("BootClassLoader", StringComparison.Ordinal);
    public bool LoaderIsHiddenClass =>
        LoaderOop != 0 &&
        (LoaderClass.Contains("+0x", StringComparison.Ordinal) ||
         LoaderClass.Contains("/0x", StringComparison.Ordinal));
}

internal sealed class ClassGraph
{
    public List<Loader> Loaders = new();
    public List<KlassRec> Klasses = new();
    public string Source = "";
    public string Problem = "";
    public long BytesScanned;

    public bool Walked => Loaders.Count > 0 && Klasses.Count > 0;

    public static ClassGraph Build(Target t, PeImage jvm, VmStructs vm)
    {
        var g = new ClassGraph();
        if (vm.Valid)
        {
            g.WalkExact(t, vm);
            if (g.Walked) { g.Source = "ClassLoaderDataGraph (" + vm.Source + ")"; return g; }
        }
        g.Loaders.Clear();
        g.Klasses.Clear();
        g.ScanHeuristic(t, jvm);
        g.Source = g.Walked ? "поиск объектов Klass в памяти (без раскладки ВМ)" : "не построен";
        return g;
    }

    private void WalkExact(Target t, VmStructs vm)
    {
        var c = new PageCache(t);

        ulong headVar = vm.StaticAddr("ClassLoaderDataGraph", "_head");
        int offNext = vm.Off("ClassLoaderData", "_next");
        int offKlasses = vm.Off("ClassLoaderData", "_klasses");
        int offLoader = vm.Off("ClassLoaderData", "_class_loader");
        int offMirrorHolder = vm.OffAny("ClassLoaderData", "_has_class_mirror_holder", "_is_unsafe_anonymous");
        int offNextLink = vm.Off("Klass", "_next_link");
        int offName = vm.Off("Klass", "_name");
        int offCld = vm.Off("Klass", "_class_loader_data");

        if (headVar == 0 || offNext < 0 || offKlasses < 0 || offNextLink < 0 || offName < 0)
        {
            Problem = "в таблицах ВМ нет полей для обхода графа загрузчиков";
            return;
        }

        int symLen = vm.Off("Symbol", "_length");
        int symBody = vm.OffAny("Symbol", "_body[0]", "_body");
        if (symLen < 0) symLen = 4;
        if (symBody < 0) symBody = 6;

        var seenK = new HashSet<ulong>();
        ulong cld = c.U64(headVar);
        int guard = 0;
        var seenCld = new HashSet<ulong>();
        while (cld is >= 0x10000 and <= 0x7FFFFFFFFFFF && guard++ < 100_000)
        {
            if (!seenCld.Add(cld)) break;
            var ld = new Loader { Address = cld };

            if (offLoader >= 0)
            {
                ulong handle = c.U64(cld + (ulong)offLoader);
                ld.LoaderOop = handle == 0 ? 0 : c.U64(handle);
                ld.LoaderClass = ld.LoaderOop == 0
                    ? "<загрузчик начальной загрузки>"
                    : NameOfOopKlass(c, vm, ld.LoaderOop, offName, symLen, symBody) ?? "<не определён>";
            }
            if (offMirrorHolder >= 0) ld.HiddenClassHolder = c.U8(cld + (ulong)offMirrorHolder) != 0;

            ulong k = c.U64(cld + (ulong)offKlasses);
            int kguard = 0;
            while (k is >= 0x10000 and <= 0x7FFFFFFFFFFF && kguard++ < 200_000)
            {
                if (!seenK.Add(k)) break;
                var kr = new KlassRec
                {
                    Address = k,
                    Cld = offCld >= 0 ? c.U64(k + (ulong)offCld) : cld,
                    Name = ReadSymbol(c, c.U64(k + (ulong)offName), symLen, symBody) ?? "",
                    Loader = ld,
                };
                Klasses.Add(kr);
                ld.Klasses.Add(kr);
                k = c.U64(k + (ulong)offNextLink);
            }
            Loaders.Add(ld);
            cld = c.U64(cld + (ulong)offNext);
        }
    }

    private static string? ReadSymbol(PageCache c, ulong sym, int offLen, int offBody)
    {
        if (sym is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        Span<byte> head = stackalloc byte[8];
        if (!c.Read(sym, head)) return null;
        int len = BitConverter.ToUInt16(head[offLen..]);
        if (len is < 1 or > 512) return null;
        var body = new byte[len];
        if (!c.Read(sym + (ulong)offBody, body)) return null;
        return JavaNames.DecodeModifiedUtf8(body);
    }

    private static string? NameOfOopKlass(PageCache c, VmStructs vm, ulong oop, int offName,
        int symLen, int symBody)
    {
        int off = vm.OffAny("oopDesc", "_metadata._compressed_klass", "_metadata._klass");
        if (off < 0) off = 8;
        ulong k;
        if (vm.Field("oopDesc", "_metadata._compressed_klass") is null)
            k = c.U64(oop + (ulong)off);
        else
        {
            ulong bv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._base"),
                ("Universe", "_narrow_klass._base"));
            ulong sv = vm.StaticAddrAny(("CompressedKlassPointers", "_narrow_klass._shift"),
                ("Universe", "_narrow_klass._shift"));
            ulong baseAddr = bv != 0 ? c.U64(bv) : 0;
            int shift = sv != 0 ? (int)c.U32(sv) : 0;
            uint narrow = c.U32(oop + (ulong)off);
            if (narrow == 0) return null;
            k = baseAddr + ((ulong)narrow << shift);
        }
        if (k is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        return ReadSymbol(c, c.U64(k + (ulong)offName), symLen, symBody);
    }

    // ---------------------------------------------------------------- запасной путь

    private void ScanHeuristic(Target t, PeImage jvm)
    {
        var ranges = jvm.Sections
            .Where(s => !s.Executable && s.VSize > 0)
            .Select(s => (Lo: jvm.Base + s.Va, Hi: jvm.Base + s.Va + s.VSize))
            .ToList();
        bool InJvmData(ulong v)
        {
            foreach (var x in ranges) if (v >= x.Lo && v < x.Hi) return true;
            return false;
        }

        const int Window = 0x110;
        const int Chunk = 32 * 1024 * 1024;
        var candidates = new List<(ulong Addr, byte[] Buf)>();
        var buf = new byte[Chunk];
        ulong prev = 0;

        foreach (var r in t.Regions)
        {
            if (!r.Readable || r.Executable || r.Image) continue;
            ulong off = 0;
            while (off < r.Size)
            {
                int len = (int)Math.Min((ulong)Chunk, r.Size - off);
                int read = t.ReadPartial(r.Base + off, buf.AsSpan(0, len));
                BytesScanned += len;
                if (read > 0)
                {
                    for (int i = 0; i + Window <= len; i += 8)
                    {
                        ulong v = BitConverter.ToUInt64(buf, i);
                        if (!InJvmData(v)) continue;
                        ulong at = r.Base + off + (ulong)i;
                        if (at == prev) continue;
                        prev = at;
                        candidates.Add((at, buf.AsSpan(i, Window).ToArray()));
                        if (candidates.Count > 400_000) break;
                    }
                }
                if (candidates.Count > 400_000) break;
                if (off + (ulong)len >= r.Size) break;
                off += (ulong)Math.Max(1, len - Window);
            }
            if (candidates.Count > 400_000) break;
        }
        if (candidates.Count == 0) { Problem = "кандидатов в объекты Klass не найдено"; return; }

        var vtabCount = new Dictionary<ulong, int>();
        foreach (var c in candidates)
        {
            ulong v = BitConverter.ToUInt64(c.Buf, 0);
            vtabCount[v] = vtabCount.GetValueOrDefault(v) + 1;
        }
        var popular = vtabCount.Where(kv => kv.Value >= 32).Select(kv => kv.Key).ToHashSet();
        if (popular.Count > 0)
            candidates = candidates.Where(c => popular.Contains(BitConverter.ToUInt64(c.Buf, 0))).ToList();

        var cache = new PageCache(t);
        int bestOff = -1, bestHits = 0;
        HashSet<ulong> klassVtables = new();
        var byVtable = candidates.GroupBy(c => BitConverter.ToUInt64(c.Buf, 0))
            .ToDictionary(g => g.Key, g => g.Take(2000).ToList());
        for (int off = 8; off <= 0x100; off += 8)
        {
            int total = 0;
            var good = new HashSet<ulong>();
            foreach (var (vt, list) in byVtable)
            {
                var seenSym = new HashSet<ulong>();
                int hits = 0;
                foreach (var c in list)
                {
                    ulong sym = BitConverter.ToUInt64(c.Buf, off);
                    if (sym is < 0x10000 or > 0x7FFFFFFFFFFF || !seenSym.Add(sym)) continue;
                    if (ReadClassSymbol(cache, sym) is not null) hits++;
                }
                if (hits * 3 >= list.Count && hits >= 8) { good.Add(vt); total += hits; }
            }
            if (total > bestHits) { bestHits = total; bestOff = off; klassVtables = good; }
        }
        if (bestOff < 0 || bestHits < 16) { Problem = "смещение имени класса не откалибровано"; return; }
        candidates = candidates.Where(c => klassVtables.Contains(BitConverter.ToUInt64(c.Buf, 0))).ToList();

        var klasses = new List<(ulong Addr, byte[] Buf, string Name)>();
        foreach (var c in candidates)
        {
            ulong sym = BitConverter.ToUInt64(c.Buf, bestOff);
            string? name = sym is >= 0x10000 and <= 0x7FFFFFFFFFFF ? ReadClassSymbol(cache, sym, strict: false) : null;
            if (name is not null) klasses.Add((c.Addr, c.Buf, name));
        }
        if (klasses.Count < 32) { Problem = $"опознано лишь {klasses.Count} классов"; return; }
        var klassSet = klasses.Select(k => k.Addr).ToHashSet();

        int cldOff = -1;
        double bestScore = 0;
        for (int off = 8; off <= 0x100; off += 8)
        {
            if (off == bestOff) continue;
            var groups = new Dictionary<ulong, List<ulong>>();
            int valid = 0, pointsToKlass = 0;
            foreach (var c in klasses.Take(20000))
            {
                ulong v = BitConverter.ToUInt64(c.Buf, off);
                if (v is < 0x10000 or > 0x7FFFFFFFFFFF || (v & 7) != 0) continue;
                if (klassSet.Contains(v)) { pointsToKlass++; continue; }
                var reg = t.RegionAt(v);
                if (reg is null || !reg.Committed || reg.Image) continue;
                valid++;
                if (!groups.TryGetValue(v, out var members)) groups[v] = members = new List<ulong>();
                if (members.Count < 64) members.Add(c.Addr);
            }
            if (valid < 32 || pointsToKlass * 2 >= valid + pointsToKlass) continue;
            if (groups.Count == 0 || groups.Count > 16384) continue;
            double score = valid / (double)groups.Count;
            if (score < 2 || score <= bestScore) continue;

            int tested = 0, consistent = 0;
            var body = new byte[0x200];
            foreach (var (v, members) in groups.Take(64))
            {
                tested++;
                if (!cache.Read(v, body)) continue;
                var set = members.ToHashSet();
                for (int i = 0; i + 8 <= body.Length; i += 8)
                    if (set.Contains(BitConverter.ToUInt64(body, i))) { consistent++; break; }
            }
            if (consistent * 2 < tested) continue;
            bestScore = score;
            cldOff = off;
        }
        if (cldOff < 0) { Problem = "смещение загрузчика не откалибровано"; return; }

        var byCld = new Dictionary<ulong, Loader>();
        foreach (var (addr, b, name) in klasses)
        {
            ulong cld = BitConverter.ToUInt64(b, cldOff);
            if (cld is < 0x10000 or > 0x7FFFFFFFFFFF) continue;
            if (!byCld.TryGetValue(cld, out var ld))
            {
                byCld[cld] = ld = new Loader { Address = cld, LoaderOop = ulong.MaxValue, LoaderClass = "<неизвестен>" };
                Loaders.Add(ld);
            }
            var kr = new KlassRec { Address = addr, Cld = cld, Name = name, Loader = ld };
            Klasses.Add(kr);
            ld.Klasses.Add(kr);
        }
    }

    private static string? ReadClassSymbol(PageCache cache, ulong addr, bool strict = true)
    {
        Span<byte> head = stackalloc byte[8];
        if (!cache.Read(addr, head)) return null;
        int len = BitConverter.ToUInt16(head[4..]);
        if (len is < 1 or > 255) return null;

        var body = new byte[len];
        if (!cache.Read(addr + 6, body)) return null;

        if (!strict)
        {
            foreach (byte c in body)
                if (c == 0 || c is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>') return null;
            string d = JavaNames.DecodeModifiedUtf8(body);
            return JavaNames.LooksLikeFreedMemory(d) ? null : d;
        }

        foreach (byte c in body)
            if (c < 0x21 || c > 0x7E) return null;
        string s = Encoding.ASCII.GetString(body);
        foreach (char c in s)
            if (!(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9'
                  or '/' or '$' or '_' or '[' or ']' or ';' or '.'))
                return null;
        if (!s.Contains('/') && !s.StartsWith('[')) return null;
        return s;
    }
}
