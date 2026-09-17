using System.Text;

namespace ClassScan;

internal static class JavaNames
{
    public const string EscapePrefix = "\\u";

    private const string NameChars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$/";

    public static string DecodeModifiedUtf8(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length);
        for (int i = 0; i < b.Length; i++)
        {
            byte c = b[i];
            int cp;
            if (c < 0x80) cp = c;
            else if ((c & 0xE0) == 0xC0 && i + 1 < b.Length)
            {
                cp = ((c & 0x1F) << 6) | (b[i + 1] & 0x3F);
                i += 1;
            }
            else if ((c & 0xF0) == 0xE0 && i + 2 < b.Length)
            {
                cp = ((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F);
                i += 2;
            }
            else cp = c;

            if (cp is >= 0x20 and < 0x7F) sb.Append((char)cp);
            else sb.Append(EscapePrefix).Append(cp.ToString("X4"));
        }
        return sb.ToString();
    }

    public static bool HasNonAscii(string decoded) =>
        decoded.Contains(EscapePrefix, StringComparison.Ordinal);

    public static bool LooksLikeFreedMemory(string decoded)
    {
        if (decoded.Contains("\\u0000", StringComparison.Ordinal)) return true;

        int high = 0, escapes = 0;
        int i = 0;
        while ((i = decoded.IndexOf(EscapePrefix, i, StringComparison.Ordinal)) >= 0)
        {
            if (i + 6 > decoded.Length) break;
            escapes++;
            if (int.TryParse(decoded.AsSpan(i + 2, 4),
                    System.Globalization.NumberStyles.HexNumber, null, out int cp) &&
                cp is >= 0x80 and <= 0xFF) high++;
            i += 6;
        }
        return escapes > 0 && high * 2 >= escapes;
    }

    public static string DescribeCodePoints(string decoded)
    {
        var kinds = new SortedSet<string>(StringComparer.Ordinal);
        int i = 0;
        while ((i = decoded.IndexOf(EscapePrefix, i, StringComparison.Ordinal)) >= 0)
        {
            if (i + 6 > decoded.Length) break;
            if (!int.TryParse(decoded.AsSpan(i + 2, 4),
                    System.Globalization.NumberStyles.HexNumber, null, out int cp)) { i += 2; continue; }
            kinds.Add(Classify(cp));
            i += 6;
        }
        return kinds.Count == 0 ? "" : string.Join(", ", kinds);
    }

    private static string Classify(int cp) => cp switch
    {
        < 0x20 => "управляющий символ",
        0x7F => "управляющий символ",
        >= 0x0080 and <= 0x00FF => "латиница-1 (диакритика)",
        >= 0x0400 and <= 0x04FF => "кириллица (омоглифы латиницы)",
        >= 0x0370 and <= 0x03FF => "греческий (омоглифы латиницы)",
        >= 0x0590 and <= 0x08FF => "письмо справа налево",
        0x200B or 0x200C or 0x200D or 0xFEFF => "невидимый символ нулевой ширины",
        >= 0x200E and <= 0x200F => "метка направления письма",
        >= 0x2000 and <= 0x206F => "типографские пробелы и метки",
        >= 0x2100 and <= 0x214F => "буквоподобные знаки",
        >= 0x3000 and <= 0x303F => "японская пунктуация",
        >= 0x4E00 and <= 0x9FFF => "иероглифы",
        >= 0xE000 and <= 0xF8FF => "область частного использования",
        >= 0xFF00 and <= 0xFFEF => "полноширинные формы (омоглифы ASCII)",
        _ => $"иной блок Юникода (U+{cp:X4})",
    };

    public static string StripEscapes(string s)
    {
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 5 < s.Length && s[i + 1] == 'u') { i += 5; sb.Append('�'); }
            else sb.Append(s[i]);
        }
        return sb.ToString();
    }

    public static string StripHiddenMarker(string plain)
    {
        int marker = plain.IndexOf("+0x", StringComparison.Ordinal);
        if (marker < 0) marker = plain.IndexOf("/0x", StringComparison.Ordinal);
        return marker > 0 ? plain[..marker] : plain;
    }

    public static bool HasIllegalChar(string plain)
    {
        foreach (char c in plain)
            if (NameChars.IndexOf(c) < 0) return true;
        return false;
    }

    public static string SimpleName(string n)
    {
        int slash = n.LastIndexOf('/');
        string s = slash >= 0 ? n[(slash + 1)..] : n;
        int dollar = s.LastIndexOf('$');
        if (dollar > 0 && dollar < s.Length - 1 && !char.IsDigit(s[dollar + 1]))
            s = s[(dollar + 1)..];
        return s;
    }

    public static string Package(string n)
    {
        int i = n.LastIndexOf('/');
        return i > 0 ? n[..i] : "<без пакета>";
    }

    public static bool IsIntermediary(string simple)
    {
        foreach (string p in new[] { "class_", "method_", "field_", "comp_" })
        {
            if (!simple.StartsWith(p, StringComparison.Ordinal)) continue;
            string rest = simple[p.Length..];
            if (rest.Length > 0 && rest.All(char.IsDigit)) return true;
        }
        return false;
    }

    public static bool IsVanillaObf(string name)
    {
        foreach (string part in name.Split('/', '$'))
        {
            if (part.Length is 0 or > 3) return false;
            foreach (char c in part)
                if (c is < 'a' or > 'z') return false;
        }
        return true;
    }

    public static bool IsConfusable(string simple)
    {
        if (simple.Length < 4) return false;
        foreach (char c in simple)
            if ("IlO01".IndexOf(c) < 0) return false;
        return true;
    }

    public static bool IsRandomLike(string simple)
    {
        if (simple.Length < 8) return false;
        bool up = false, low = false;
        foreach (char c in simple)
        {
            if (char.IsUpper(c)) up = true;
            else if (char.IsLower(c)) low = true;
        }
        if (!up || !low) return false;
        if (LooksLikeWords(simple)) return false;
        return Entropy(simple) >= 3.2;
    }

    private static List<string> CamelParts(string s)
    {
        var res = new List<string>();
        var cur = new StringBuilder();
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (!char.IsLetter(c))
            {
                if (cur.Length > 0) { res.Add(cur.ToString()); cur.Clear(); }
                continue;
            }
            bool boundary = cur.Length > 0 && char.IsUpper(c) &&
                            (char.IsLower(s[i - 1]) ||
                             (i + 1 < s.Length && char.IsLower(s[i + 1]) && char.IsUpper(s[i - 1])));
            if (boundary) { res.Add(cur.ToString()); cur.Clear(); }
            cur.Append(c);
        }
        if (cur.Length > 0) res.Add(cur.ToString());
        return res;
    }

    private static bool LooksLikeWords(string simple)
    {
        var parts = CamelParts(simple).Where(p => p.Length >= 3).ToList();
        if (parts.Count == 0) return false;
        int good = parts.Count(Pronounceable);
        return good * 2 >= parts.Count;
    }

    private static bool Pronounceable(string s)
    {
        if (s.Length <= 5 && s.All(char.IsUpper)) return true;

        int letters = 0, vowels = 0, run = 0;
        foreach (char c in s)
        {
            if (!char.IsLetter(c)) continue;
            letters++;
            if ("aeiouyAEIOUY".IndexOf(c) >= 0) { vowels++; run = 0; }
            else if (++run >= 5) return false;
        }
        if (letters < 3) return false;
        double v = vowels / (double)letters;
        return v is >= 0.15 and <= 0.70;
    }

    private static double Entropy(string s)
    {
        var freq = new Dictionary<char, int>();
        foreach (char c in s) freq[c] = freq.GetValueOrDefault(c) + 1;
        double e = 0;
        foreach (int v in freq.Values)
        {
            double p = v / (double)s.Length;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}
