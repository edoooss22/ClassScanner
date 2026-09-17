using System.Text;

namespace ClassScan;

internal sealed class Section
{
    public string Name = "";
    public uint Va;
    public uint VSize;
    public uint Characteristics;

    public bool Executable => (Characteristics & 0x20000000) != 0;
}

internal sealed class PeImage
{
    public ulong Base;
    public uint SizeOfImage;
    public List<Section> Sections = new();
    public Dictionary<string, uint> Exports = new(StringComparer.Ordinal);

    public ulong Export(string name) => Exports.TryGetValue(name, out uint rva) ? Base + rva : 0;

    public static PeImage? FromMemory(Target t, ulong baseAddr)
    {
        var head = t.ReadBytes(baseAddr, 0x1000);
        if (head is null || head[0] != (byte)'M' || head[1] != (byte)'Z') return null;

        int lfanew = BitConverter.ToInt32(head, 0x3C);
        if (lfanew <= 0 || lfanew + 0x108 > head.Length) return null;
        if (BitConverter.ToUInt32(head, lfanew) != 0x00004550) return null;

        int opt = lfanew + 24;
        if (BitConverter.ToUInt16(head, opt) != 0x20B) return null;

        var img = new PeImage
        {
            Base = baseAddr,
            SizeOfImage = BitConverter.ToUInt32(head, opt + 56),
        };

        int nsec = BitConverter.ToUInt16(head, lfanew + 6);
        int optSize = BitConverter.ToUInt16(head, lfanew + 20);
        int secTable = opt + optSize;
        if (nsec <= 0 || nsec > 96 || secTable + nsec * 40 > head.Length) return img;
        for (int i = 0; i < nsec; i++)
        {
            int o = secTable + i * 40;
            int nameEnd = 0;
            while (nameEnd < 8 && head[o + nameEnd] != 0) nameEnd++;
            img.Sections.Add(new Section
            {
                Name = Encoding.ASCII.GetString(head, o, nameEnd),
                VSize = BitConverter.ToUInt32(head, o + 8),
                Va = BitConverter.ToUInt32(head, o + 12),
                Characteristics = BitConverter.ToUInt32(head, o + 36),
            });
        }

        uint expRva = BitConverter.ToUInt32(head, opt + 112);
        uint expSize = BitConverter.ToUInt32(head, opt + 116);
        ParseExports(t, img, expRva, expSize);
        return img;
    }

    private static void ParseExports(Target t, PeImage img, uint rva, uint size)
    {
        if (rva == 0 || size < 40 || size > 16 * 1024 * 1024) return;
        var d = new byte[size];
        if (t.ReadPartial(img.Base + rva, d) == 0) return;

        uint numberOfFunctions = BitConverter.ToUInt32(d, 0x14);
        uint numberOfNames = BitConverter.ToUInt32(d, 0x18);
        uint addressOfFunctions = BitConverter.ToUInt32(d, 0x1C);
        uint addressOfNames = BitConverter.ToUInt32(d, 0x20);
        uint addressOfOrdinals = BitConverter.ToUInt32(d, 0x24);
        if (numberOfNames == 0 || numberOfNames > 200000) return;
        if (numberOfFunctions == 0 || numberOfFunctions > 200000) return;

        byte[]? Slice(uint at, int len)
        {
            if (at == 0 || len <= 0) return null;
            long inside = (long)at - rva;
            if (inside >= 0 && inside + len <= d.Length)
            {
                var res = new byte[len];
                Buffer.BlockCopy(d, (int)inside, res, 0, len);
                return res;
            }
            return t.ReadBytes(img.Base + at, len);
        }

        var names = Slice(addressOfNames, (int)numberOfNames * 4);
        var ordinals = Slice(addressOfOrdinals, (int)numberOfNames * 2);
        var functions = Slice(addressOfFunctions, (int)numberOfFunctions * 4);
        if (names is null || ordinals is null || functions is null) return;

        for (int i = 0; i < numberOfNames; i++)
        {
            uint nameRva = BitConverter.ToUInt32(names, i * 4);
            int ord = BitConverter.ToUInt16(ordinals, i * 2);
            if (ord * 4 + 4 > functions.Length) continue;
            uint funcRva = BitConverter.ToUInt32(functions, ord * 4);
            if (funcRva == 0) continue;
            if (funcRva >= rva && funcRva < rva + size) continue;

            long inside = (long)nameRva - rva;
            string name;
            if (inside >= 0 && inside < d.Length)
            {
                int end = (int)inside;
                while (end < d.Length && d[end] != 0) end++;
                name = Encoding.ASCII.GetString(d, (int)inside, end - (int)inside);
            }
            else
            {
                var buf = t.ReadBytes(img.Base + nameRva, 256);
                if (buf is null) continue;
                int n = Array.IndexOf(buf, (byte)0);
                name = Encoding.ASCII.GetString(buf, 0, n < 0 ? buf.Length : n);
            }
            if (name.Length > 0) img.Exports.TryAdd(name, funcRva);
        }
    }
}
