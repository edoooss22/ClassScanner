using System.Diagnostics;
using System.Text;
using static ClassScan.Native;

namespace ClassScan;

internal sealed class Region
{
    public ulong Base;
    public ulong Size;
    public ulong AllocationBase;
    public uint State;
    public uint Type;
    public uint Protect;
    public string? MappedFile;

    public ulong End => Base + Size;
    public bool Committed => State == MEM_COMMIT;
    public bool Private => Type == MEM_PRIVATE;
    public bool Image => Type == MEM_IMAGE;
    public bool Executable => (Protect & EXEC_MASK) != 0;
    public bool Readable => Committed && (Protect & PAGE_GUARD) == 0 && (Protect & 0xFF) != PAGE_NOACCESS;
    public bool PrivateData => Readable && Private && !Executable;
}

internal sealed unsafe class Target : IDisposable
{
    public IntPtr Handle { get; private set; }
    public int Pid { get; }
    public string Name = "";
    public string Path = "";
    public string Window = "";
    public long WorkingSet;
    public bool Wow64;
    public ulong Peb;
    public List<Region> Regions = new();

    private Target(int pid) { Pid = pid; }

    public static Target Open(Process p)
    {
        var t = new Target(p.Id);
        try { t.Name = p.ProcessName; } catch { }
        try { t.WorkingSet = p.WorkingSet64; } catch { }
        try { t.Window = p.MainWindowTitle; } catch { }

        IntPtr h = OpenProcess(ProcessAccess.QueryInformation | ProcessAccess.VmRead, false, p.Id);
        if (h == IntPtr.Zero)
            h = OpenProcess(ProcessAccess.QueryLimitedInformation | ProcessAccess.VmRead, false, p.Id);
        if (h == IntPtr.Zero)
            throw new InvalidOperationException(
                $"OpenProcess({p.Id}) = {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
        t.Handle = h;

        uint cap = 4096;
        var buf = stackalloc char[(int)cap];
        if (QueryFullProcessImageNameW(h, 0, buf, ref cap)) t.Path = new string(buf, 0, (int)cap);
        if (IsWow64Process(h, out bool wow)) t.Wow64 = wow;

        PROCESS_BASIC_INFORMATION pbi;
        uint ret;
        if (NtQueryInformationProcess(h, 0, &pbi, (uint)sizeof(PROCESS_BASIC_INFORMATION), &ret) == 0)
            t.Peb = (ulong)pbi.PebBaseAddress.ToInt64();

        t.EnumerateRegions();
        return t;
    }

    public static Process? FindJavaw()
    {
        Process? best = null;
        long bestSize = -1;
        foreach (var p in Process.GetProcesses())
        {
            string name;
            try { name = p.ProcessName; }
            catch { p.Dispose(); continue; }
            if (!name.Equals("javaw", StringComparison.OrdinalIgnoreCase) &&
                !name.Equals("java", StringComparison.OrdinalIgnoreCase)) { p.Dispose(); continue; }

            long size;
            try { size = p.WorkingSet64; }
            catch { p.Dispose(); continue; }
            if (size > bestSize) { best?.Dispose(); best = p; bestSize = size; }
            else p.Dispose();
        }
        return best;
    }

    private void EnumerateRegions()
    {
        GetSystemInfo(out var si);
        ulong to = (ulong)si.MaximumApplicationAddress.ToInt64();
        ulong addr = 0;
        var fileCache = new Dictionary<ulong, string?>();
        while (addr < to)
        {
            if (VirtualQueryEx(Handle, (IntPtr)addr, out var mbi, (nuint)sizeof(MEMORY_BASIC_INFORMATION)) == 0)
            {
                addr += 0x1000;
                continue;
            }
            ulong size = mbi.RegionSize;
            if (size == 0) { addr += 0x1000; continue; }
            if (mbi.State != MEM_FREE)
            {
                var r = new Region
                {
                    Base = (ulong)mbi.BaseAddress.ToInt64(),
                    Size = size,
                    AllocationBase = (ulong)mbi.AllocationBase.ToInt64(),
                    State = mbi.State,
                    Type = mbi.Type,
                    Protect = mbi.Protect,
                };
                if (r.Type is MEM_IMAGE or MEM_MAPPED && r.AllocationBase != 0)
                {
                    if (!fileCache.TryGetValue(r.AllocationBase, out var f))
                        fileCache[r.AllocationBase] = f = MappedFile(Handle, r.AllocationBase);
                    r.MappedFile = f;
                }
                Regions.Add(r);
            }
            ulong next = (ulong)mbi.BaseAddress.ToInt64() + size;
            if (next <= addr) break;
            addr = next;
        }
    }

    public Region? RegionAt(ulong addr)
    {
        int lo = 0, hi = Regions.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            var r = Regions[mid];
            if (addr < r.Base) hi = mid - 1;
            else if (addr >= r.End) lo = mid + 1;
            else return r;
        }
        return null;
    }

    public List<(ulong Base, string Path)> FindImages(string fileName)
    {
        var seen = new HashSet<ulong>();
        var res = new List<(ulong, string)>();
        foreach (var r in Regions)
        {
            if (!r.Image || r.MappedFile is null || !seen.Add(r.AllocationBase)) continue;
            if (System.IO.Path.GetFileName(r.MappedFile).Equals(fileName, StringComparison.OrdinalIgnoreCase))
                res.Add((r.AllocationBase, r.MappedFile));
        }
        return res;
    }

    public bool TryRead(ulong address, Span<byte> dest)
    {
        fixed (byte* p = dest)
        {
            return ReadProcessMemory(Handle, (IntPtr)address, p, (nuint)dest.Length, out var read)
                   && read == (nuint)dest.Length;
        }
    }

    public byte[]? ReadBytes(ulong address, int len)
    {
        var b = new byte[len];
        return TryRead(address, b) ? b : null;
    }

    public int ReadPartial(ulong address, Span<byte> dest)
    {
        if (TryRead(address, dest)) return dest.Length;
        const int page = 0x1000;
        int total = 0;
        for (int off = 0; off < dest.Length; off += page)
        {
            int len = Math.Min(page, dest.Length - off);
            if (TryRead(address + (ulong)off, dest.Slice(off, len))) total += len;
            else dest.Slice(off, len).Clear();
        }
        return total;
    }

    public ulong U64(ulong addr)
    {
        Span<byte> b = stackalloc byte[8];
        return TryRead(addr, b) ? BitConverter.ToUInt64(b) : 0;
    }

    public string? ReadUnicodeString(ulong at)
    {
        Span<byte> us = stackalloc byte[16];
        if (!TryRead(at, us)) return null;
        ushort len = BitConverter.ToUInt16(us);
        ulong ptr = BitConverter.ToUInt64(us[8..]);
        if (len == 0 || ptr == 0) return null;
        var raw = ReadBytes(ptr, len);
        return raw is null ? null : Encoding.Unicode.GetString(raw);
    }

    public string? CommandLine => ProcessParameters is var pp && pp != 0 ? ReadUnicodeString(pp + 0x70) : null;
    public string? CurrentDirectory => ProcessParameters is var pp && pp != 0 ? ReadUnicodeString(pp + 0x38) : null;
    private ulong ProcessParameters => Peb == 0 ? 0 : U64(Peb + 0x20);

    public void Dispose()
    {
        if (Handle != IntPtr.Zero) CloseHandle(Handle);
        Handle = IntPtr.Zero;
    }
}

internal sealed class PageCache
{
    private readonly Target _t;
    private readonly Dictionary<ulong, byte[]?> _pages = new();
    private readonly int _limit;

    public PageCache(Target t, int maxPages = 65536)
    {
        _t = t;
        _limit = maxPages;
    }

    public bool Read(ulong addr, Span<byte> dest)
    {
        for (int i = 0; i < dest.Length;)
        {
            ulong a = addr + (ulong)i;
            ulong page = a & ~0xFFFUL;
            if (!_pages.TryGetValue(page, out var buf))
            {
                buf = _t.ReadBytes(page, 0x1000);
                if (_pages.Count >= _limit) _pages.Clear();
                _pages[page] = buf;
            }
            if (buf is null) return false;
            int off = (int)(a - page);
            int n = Math.Min(0x1000 - off, dest.Length - i);
            buf.AsSpan(off, n).CopyTo(dest.Slice(i, n));
            i += n;
        }
        return true;
    }

    public uint U32(ulong addr)
    {
        Span<byte> b = stackalloc byte[4];
        return Read(addr, b) ? BitConverter.ToUInt32(b) : 0;
    }

    public ulong U64(ulong addr)
    {
        Span<byte> b = stackalloc byte[8];
        return Read(addr, b) ? BitConverter.ToUInt64(b) : 0;
    }

    public byte U8(ulong addr)
    {
        Span<byte> b = stackalloc byte[1];
        return Read(addr, b) ? b[0] : (byte)0;
    }

    public string? CString(ulong addr, int max = 160)
    {
        if (addr is < 0x10000 or > 0x7FFFFFFFFFFF) return null;
        var b = new byte[max];
        Span<byte> one = stackalloc byte[1];
        int n = 0;
        while (n < max)
        {
            if (!Read(addr + (ulong)n, one)) return null;
            if (one[0] == 0) break;
            if (one[0] < 0x20 || one[0] > 0x7E) return null;
            b[n++] = one[0];
        }
        return n is 0 or >= 160 ? null : Encoding.ASCII.GetString(b, 0, n);
    }
}
