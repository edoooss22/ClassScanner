namespace ClassScan;

internal sealed class VmField
{
    public string TypeName = "";
    public string FieldName = "";
    public bool IsStatic;
    public ulong Offset;
    public ulong Address;
}

internal sealed class VmStructs
{
    public bool Valid;
    public string Source = "";
    public int Count;
    private readonly Dictionary<string, Dictionary<string, VmField>> _fields = new(StringComparer.Ordinal);

    public VmField? Field(string type, string field) =>
        _fields.TryGetValue(type, out var m) && m.TryGetValue(field, out var f) ? f : null;

    public int Off(string type, string field)
    {
        var f = Field(type, field);
        return f is null || f.IsStatic || f.Offset > 0x10000 ? -1 : (int)f.Offset;
    }

    public int OffAny(string type, params string[] names)
    {
        foreach (var n in names)
        {
            int o = Off(type, n);
            if (o >= 0) return o;
        }
        return -1;
    }

    public ulong StaticAddr(string type, string field)
    {
        var f = Field(type, field);
        return f is null || !f.IsStatic ? 0 : f.Address;
    }

    public ulong StaticAddrAny(params (string Type, string Field)[] candidates)
    {
        foreach (var (t, f) in candidates)
        {
            ulong a = StaticAddr(t, f);
            if (a != 0) return a;
        }
        return 0;
    }

    private const int MaxEntries = 20000;

    public static VmStructs Load(Target t, PeImage jvm)
    {
        var v = new VmStructs();
        try { v.Init(t, jvm); }
        catch { }
        v.Valid = v.Count > 0;
        return v;
    }

    private void Init(Target t, PeImage jvm)
    {
        var cache = new PageCache(t, 32768);
        ulong pStructs = jvm.Export("gHotSpotVMStructs");

        if (pStructs != 0)
        {
            Source = "экспорты jvm.dll";
            ulong U(string n) { ulong a = jvm.Export(n); return a == 0 ? 0 : cache.U64(a); }

            int typeName = (int)U("gHotSpotVMStructEntryTypeNameOffset");
            int fieldName = (int)U("gHotSpotVMStructEntryFieldNameOffset");
            int isStatic = (int)U("gHotSpotVMStructEntryIsStaticOffset");
            int offset = (int)U("gHotSpotVMStructEntryOffsetOffset");
            int address = (int)U("gHotSpotVMStructEntryAddressOffset");
            int stride = (int)U("gHotSpotVMStructEntryArrayStride");
            if (stride is <= 0 or > 256)
            {
                typeName = 0; fieldName = 8; isStatic = 0x18; offset = 0x20; address = 0x28; stride = 0x30;
            }
            Parse(cache, cache.U64(pStructs), typeName, fieldName, isStatic, offset, address, stride);
            return;
        }

        Source = "поиск по данным jvm.dll";
        ulong found = FindArray(t, cache, jvm);
        if (found != 0) Parse(cache, found, 0, 8, 0x18, 0x20, 0x28, 0x30);
    }

    private void Parse(PageCache cache, ulong array, int typeName, int fieldName, int isStatic,
        int offset, int address, int stride)
    {
        if (array is < 0x10000 or > 0x7FFFFFFFFFFF) return;
        for (int i = 0; i < MaxEntries; i++)
        {
            ulong e = array + (ulong)(i * stride);
            ulong pType = cache.U64(e + (ulong)typeName);
            if (pType == 0) break;
            ulong pField = cache.U64(e + (ulong)fieldName);
            if (pField == 0) break;

            string? type = cache.CString(pType, 128);
            string? field = cache.CString(pField, 128);
            if (type is null || field is null) break;

            var f = new VmField
            {
                TypeName = type,
                FieldName = field,
                IsStatic = cache.U32(e + (ulong)isStatic) != 0,
            };
            if (f.IsStatic) f.Address = cache.U64(e + (ulong)address);
            else f.Offset = cache.U64(e + (ulong)offset);

            Count++;
            if (!_fields.TryGetValue(type, out var map))
                _fields[type] = map = new Dictionary<string, VmField>(StringComparer.Ordinal);
            map[field] = f;
        }
    }

    private static ulong FindArray(Target t, PageCache cache, PeImage jvm)
    {
        const int stride = 0x30;
        ulong lo = jvm.Base, hi = jvm.Base + jvm.SizeOfImage;
        foreach (var sec in jvm.Sections)
        {
            if (sec.Executable || sec.VSize is 0 or > 64 * 1024 * 1024) continue;
            if (sec.Name is not (".data" or ".rdata")) continue;

            var buf = new byte[sec.VSize];
            ulong secVa = jvm.Base + sec.Va;
            t.ReadPartial(secVa, buf);

            for (int i = 0; i + stride * 6 <= buf.Length; i += 8)
            {
                bool ok = true;
                for (int k = 0; k < 6 && ok; k++)
                {
                    int o = i + k * stride;
                    ulong a = BitConverter.ToUInt64(buf, o);
                    ulong b = BitConverter.ToUInt64(buf, o + 8);
                    uint st = BitConverter.ToUInt32(buf, o + 0x18);
                    ok = st <= 1 && a >= lo && a < hi && b >= lo && b < hi &&
                         cache.CString(a, 128) is { Length: > 0 } &&
                         cache.CString(b, 128) is { Length: > 0 };
                }
                if (ok) return secVa + (ulong)i;
            }
        }
        return 0;
    }
}
