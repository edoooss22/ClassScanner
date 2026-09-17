using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;

namespace ClassScan;

internal sealed class ReportInput
{
    public Target Target = null!;
    public string JvmPath = "";
    public ulong JvmBase;
    public VmStructs Vm = null!;
    public ClassGraph Graph = null!;
    public JarIndex Jars = null!;
    public Analysis Analysis = null!;
    public TimeSpan Elapsed;
}

internal static class HtmlReport
{
    private static JsonSerializerOptions JsonOpts() => new()
    {
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
        WriteIndented = false,
    };

    private const int MaxSectionChars = 4_000_000;

    public static string Render(ReportInput r)
    {
        var sb = new StringBuilder(1 << 20);
        sb.Append(Head);
        sb.Append(Body);
        sb.Append("<script id=\"csdata\" type=\"application/json\">");
        sb.Append(BuildPayload(r).ToJsonString(JsonOpts()));
        sb.Append("</script>\n<script>");
        sb.Append(Script);
        sb.Append("</script>\n</body>\n</html>\n");
        return sb.ToString();
    }

    // ------------------------------------------------------------------ данные

    private static JsonObject BuildPayload(ReportInput r)
    {
        var a = r.Analysis;
        var findings = new JsonArray();
        int n = 0;
        foreach (var f in a.Findings)
        {
            n++;
            var blocks = new JsonArray();
            if (f.Lines.Count > 0)
                blocks.Add(new JsonArray((JsonNode)"Записи", (JsonNode)string.Join("\n", f.Lines)));
            findings.Add(new JsonObject
            {
                ["n"] = n,
                ["sev"] = (int)f.Severity,
                ["cat"] = f.Category,
                ["title"] = f.Title,
                ["expl"] = f.Why,
                ["count"] = f.Lines.Count(l => l.Length > 0),
                ["blocks"] = blocks,
            });
        }

        var sections = new JsonArray();
        void Section(string title, string text)
        {
            bool cut = text.Length > MaxSectionChars;
            sections.Add(new JsonObject
            {
                ["title"] = title,
                ["text"] = cut ? text[..MaxSectionChars] : text,
                ["cut"] = cut,
                ["size"] = text.Length,
            });
        }
        Section("ЗАГРУЗЧИКИ КЛАССОВ", Sections.Loaders(r));
        Section("КЛАССЫ ПО ПРОИСХОЖДЕНИЮ", Sections.Origins(a));
        Section("КЛАССЫ БЕЗ ПРОИСХОЖДЕНИЯ", Sections.Orphans(a));
        Section("ПОЧЕРК ИМЁН", Sections.Names(a));
        Section("ПРОИНДЕКСИРОВАННЫЕ АРХИВЫ", Sections.Jars(r.Jars));
        Section("ВСЕ КЛАССЫ", Sections.AllClasses(a));

        var t = r.Target;
        var meta = new JsonArray
        {
            new JsonArray((JsonNode)"Образ", (JsonNode)t.Path),
            new JsonArray((JsonNode)"Окно", (JsonNode)(t.Window.Length > 0 ? t.Window : "(без окна)")),
            new JsonArray((JsonNode)"Рабочее множество", (JsonNode)$"{t.WorkingSet / (1024 * 1024)} МБ"),
            new JsonArray((JsonNode)"Командная строка", (JsonNode)(t.CommandLine ?? "")),
            new JsonArray((JsonNode)"Рабочий каталог", (JsonNode)(t.CurrentDirectory ?? "")),
            new JsonArray((JsonNode)"jvm.dll", (JsonNode)$"0x{r.JvmBase:X}  {r.JvmPath}"),
            new JsonArray((JsonNode)"Раскладка структур ВМ",
                (JsonNode)(r.Vm.Valid ? $"{r.Vm.Count} полей ({r.Vm.Source})" : "не найдена")),
            new JsonArray((JsonNode)"Источник графа классов", (JsonNode)r.Graph.Source),
            new JsonArray((JsonNode)"Загрузчиков / классов",
                (JsonNode)$"{r.Graph.Loaders.Count} / {r.Graph.Klasses.Count}"),
            new JsonArray((JsonNode)"Архивов / классов в архивах",
                (JsonNode)$"{r.Jars.Jars.Count} / {r.Jars.ClassCount}"),
            new JsonArray((JsonNode)"Игра на промежуточных именах Fabric",
                (JsonNode)($"{(a.GameIsRemapped ? "да" : "нет")} (class_NNN в процессе: {a.IntermediaryCount}, " +
                           $"имён в стиле обфускатора игры в архивах: {a.VanillaInJars})")),
        };

        return new JsonObject
        {
            ["tool"] = "ClassScan",
            ["version"] = Program.Version,
            ["pid"] = t.Pid,
            ["generated"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            ["elapsed"] = Math.Round(r.Elapsed.TotalSeconds, 1),
            ["machine"] = Environment.MachineName,
            ["user"] = Environment.UserName,
            ["os"] = Environment.OSVersion.VersionString,
            ["verdict"] = a.Detected ? "DETECTED" : "UNDETECTED",
            ["meta"] = meta,
            ["summary"] = new JsonObject
            {
                ["4"] = a.Findings.Count(f => f.Severity == Severity.Critical),
                ["3"] = a.Findings.Count(f => f.Severity == Severity.High),
                ["2"] = a.Findings.Count(f => f.Severity == Severity.Medium),
                ["1"] = a.Findings.Count(f => f.Severity == Severity.Low),
                ["0"] = a.Findings.Count(f => f.Severity == Severity.Info),
            },
            ["findings"] = findings,
            ["sections"] = sections,
        };
    }

    // ------------------------------------------------------------------ разметка

    private const string Head = """
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClassScan — отчёт</title>
<style>
:root{
  --bg:#0f1216; --bg2:#161a20; --bg3:#1d222a; --line:#272d37;
  --fg:#e6e9ef; --fg2:#a4adbb; --fg3:#6b7482;
  --crit:#f0454b; --high:#f59f00; --med:#22b8cf; --low:#7c8695; --info:#5f6b7a;
  --ok:#37b24d; --accent:#4c8dff;
  --mono:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
}
:root[data-theme="light"]{
  --bg:#f4f6f9; --bg2:#ffffff; --bg3:#eef1f5; --line:#d7dde5;
  --fg:#12161c; --fg2:#4a5462; --fg3:#79838f;
  --crit:#d0323a; --high:#b56a00; --med:#0b7285; --low:#5c6570; --info:#6b7480;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased}
a{color:var(--accent)}
.wrap{max-width:1500px;margin:0 auto;padding:0 20px 80px}
header{border-bottom:1px solid var(--line);background:var(--bg2)}
.hd{max-width:1500px;margin:0 auto;padding:18px 20px;display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap}
.brand{font-size:19px;font-weight:650;letter-spacing:.2px}
.brand small{color:var(--fg3);font-weight:400;font-size:12px;margin-left:8px}
.hd-right{margin-left:auto;display:flex;gap:8px;align-items:center}
.btn{background:var(--bg3);color:var(--fg2);border:1px solid var(--line);border-radius:7px;
     padding:6px 11px;font-size:12.5px;cursor:pointer;font-family:inherit}
.btn:hover{color:var(--fg);border-color:var(--fg3)}
.verdict{padding:12px 16px;border-radius:10px;border:1px solid var(--line);display:flex;gap:12px;
         align-items:center;font-size:14.5px;margin:18px 0}
.verdict b{font-weight:650}
.verdict.red{background:rgba(240,69,75,.10);border-color:rgba(240,69,75,.45)}
.verdict.yellow{background:rgba(245,159,0,.10);border-color:rgba(245,159,0,.45)}
.verdict.green{background:rgba(55,178,77,.10);border-color:rgba(55,178,77,.40)}
.verdict .dot{width:10px;height:10px;border-radius:50%;flex:none}
.verdict.red .dot{background:var(--crit)} .verdict.yellow .dot{background:var(--high)}
.verdict.green .dot{background:var(--ok)}
.verdict span.note{color:var(--fg2);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.stat{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:11px 13px;
      cursor:pointer;transition:.12s;border-left-width:3px}
.stat:hover{border-color:var(--fg3)}
.stat.off{opacity:.4}
.stat .num{font-size:23px;font-weight:650;line-height:1.15}
.stat .lbl{font-size:11.5px;color:var(--fg2);text-transform:uppercase;letter-spacing:.5px}
.s4{border-left-color:var(--crit)} .s4 .num{color:var(--crit)}
.s3{border-left-color:var(--high)} .s3 .num{color:var(--high)}
.s2{border-left-color:var(--med)}  .s2 .num{color:var(--med)}
.s1{border-left-color:var(--low)}  .s1 .num{color:var(--low)}
.s0{border-left-color:var(--info)} .s0 .num{color:var(--info)}
.meta{background:var(--bg2);border:1px solid var(--line);border-radius:10px;margin:16px 0}
.meta summary{padding:11px 14px;cursor:pointer;font-weight:600;font-size:13.5px;user-select:none}
.meta summary::marker{color:var(--fg3)}
.meta .in{padding:0 14px 13px;display:grid;grid-template-columns:minmax(160px,260px) 1fr;gap:5px 16px;font-size:13px}
.meta .k{color:var(--fg2)}
.meta .v{font-family:var(--mono);font-size:12.5px;word-break:break-word;white-space:pre-wrap}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:20px 0 0}
.tab{padding:9px 15px;cursor:pointer;color:var(--fg2);font-size:13.5px;border:1px solid transparent;
     border-bottom:none;border-radius:8px 8px 0 0}
.tab:hover{color:var(--fg)}
.tab.act{background:var(--bg2);border-color:var(--line);color:var(--fg);font-weight:600}
.tab .c{color:var(--fg3);font-size:12px;margin-left:5px}
.bar{position:sticky;top:0;z-index:20;background:var(--bg);padding:12px 0 10px;border-bottom:1px solid var(--line);margin-bottom:14px}
.bar .row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.search{flex:1;min-width:240px;background:var(--bg2);border:1px solid var(--line);border-radius:8px;
        padding:8px 11px;color:var(--fg);font-size:13.5px;font-family:inherit}
.search:focus{outline:none;border-color:var(--accent)}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}
.chip{background:var(--bg2);border:1px solid var(--line);border-radius:20px;padding:4px 11px;
      font-size:12px;cursor:pointer;color:var(--fg2);user-select:none}
.chip:hover{border-color:var(--fg3);color:var(--fg)}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff}
.chip .n{opacity:.65;margin-left:5px}
.hint{color:var(--fg3);font-size:12px;margin-top:8px}
.card{background:var(--bg2);border:1px solid var(--line);border-left-width:3px;border-radius:10px;margin-bottom:9px;overflow:hidden}
.card.c4{border-left-color:var(--crit)} .card.c3{border-left-color:var(--high)}
.card.c2{border-left-color:var(--med)}  .card.c1{border-left-color:var(--low)}
.card.c0{border-left-color:var(--info)}
.chd{display:flex;gap:11px;align-items:flex-start;padding:11px 14px;cursor:pointer}
.chd:hover{background:var(--bg3)}
.badge{font-size:10.5px;font-weight:700;letter-spacing:.6px;padding:3px 7px;border-radius:5px;flex:none;margin-top:1px;white-space:nowrap}
.b4{background:rgba(240,69,75,.16);color:var(--crit)}
.b3{background:rgba(245,159,0,.16);color:var(--high)}
.b2{background:rgba(34,184,207,.14);color:var(--med)}
.b1{background:rgba(124,134,149,.16);color:var(--low)}
.b0{background:rgba(95,107,122,.16);color:var(--info)}
.cat{font-size:11px;color:var(--fg3);border:1px solid var(--line);border-radius:5px;padding:2px 7px;flex:none;margin-top:1px}
.ttl{flex:1;font-size:13.8px;line-height:1.45;word-break:break-word}
.idx{color:var(--fg3);font-size:11.5px;flex:none;margin-top:2px;font-family:var(--mono)}
.cbody{padding:0 14px 13px;border-top:1px solid var(--line);display:none}
.card.open .cbody{display:block}
.expl{color:var(--fg2);font-size:13px;line-height:1.6;margin:11px 0;padding-left:11px;border-left:2px solid var(--line)}
.blk{margin:9px 0;border:1px solid var(--line);border-radius:8px;background:var(--bg3)}
.blk summary{padding:7px 11px;cursor:pointer;font-size:12.5px;color:var(--fg2);user-select:none}
.blk summary:hover{color:var(--fg)}
.blk pre{margin:0;padding:11px;overflow-x:auto;font-family:var(--mono);font-size:12px;line-height:1.45;white-space:pre;border-top:1px solid var(--line)}
mark{background:rgba(76,141,255,.32);color:inherit;border-radius:2px}
.sec-wrap{display:grid;grid-template-columns:300px 1fr;gap:16px;align-items:start}
.sec-nav{position:sticky;top:64px;max-height:calc(100vh - 90px);overflow:auto;background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:7px}
.sec-nav div{padding:7px 10px;border-radius:6px;cursor:pointer;font-size:12.5px;color:var(--fg2);word-break:break-word}
.sec-nav div:hover{background:var(--bg3);color:var(--fg)}
.sec-nav div.act{background:var(--accent);color:#fff}
.sec-nav div .sz{float:right;font-size:11px;opacity:.6}
.sec-body{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}
.sec-body h3{margin:0 0 10px;font-size:15px}
.sec-body pre{margin:0;overflow-x:auto;font-family:var(--mono);font-size:12px;line-height:1.45;white-space:pre;max-height:75vh;overflow-y:auto}
.cutwarn{color:var(--high);font-size:12.5px;margin-bottom:9px}
.empty{color:var(--fg3);text-align:center;padding:50px 0;font-size:14px}
footer{color:var(--fg3);font-size:12px;text-align:center;padding:26px 0}
@media(max-width:900px){.sec-wrap{grid-template-columns:1fr}.sec-nav{position:static;max-height:260px}}
</style>
</head>
<body>
""";

    private const string Body = """
<header>
  <div class="hd">
    <div>
      <div class="brand">ClassScan <small id="hd-sub"></small></div>
      <div id="hd-target" style="color:var(--fg2);font-size:12.5px;margin-top:3px"></div>
    </div>
    <div class="hd-right">
      <button class="btn" id="btn-expand">Развернуть всё</button>
      <button class="btn" id="btn-collapse">Свернуть всё</button>
      <button class="btn" id="btn-theme">Тема</button>
    </div>
  </div>
</header>

<div class="wrap">
  <div id="verdict"></div>
  <div class="stats" id="stats"></div>

  <details class="meta" id="meta-box">
    <summary>Сведения о процессе и о проверке</summary>
    <div class="in" id="meta"></div>
  </details>

  <details class="meta">
    <summary>Как читать этот отчёт</summary>
    <div class="in" style="grid-template-columns:1fr">
      <div style="color:var(--fg2);font-size:13px;line-height:1.65">
        <p style="margin-top:0"><b>Что проверяется.</b> Только классы Java, загруженные в виртуальную
        машину прямо сейчас: они читаются из графа загрузчиков самой ВМ, а не поиском байт-кода в памяти.
        Для каждого класса устанавливается происхождение — есть ли он в одном из архивов, доступных игре
        (командная строка, mods, versions, libraries, открытые процессом jar), — и проверяются пакет,
        загрузчик и почерк имени.</p>
        <p><b>Значимость.</b>
        <span style="color:var(--crit)">КРИТИЧНО</span> — состояние, которого в чистом клиенте не бывает;
        <span style="color:var(--high)">ВЫСОКАЯ</span> — сильная аномалия, требующая объяснения;
        <span style="color:var(--med)">СРЕДНЯЯ</span> — требует ручной проверки, бывает и штатно;
        <span style="color:var(--low)">НИЗКАЯ</span> — слабый признак либо проверка не выполнена;
        <span style="color:var(--info)">ИНФО</span> — справка для протокола.</p>
        <p><b>Про отрицательный результат.</b> Сканер видит только то, что загружено в ВМ на момент
        проверки: выгруженный или так и не загруженный код здесь не отразится. Раздел «Полные данные»
        содержит все загрузчики и все классы — просматривайте его глазами и при нулевом счёте.</p>
        <p><b>Поиск</b> ищет по заголовкам, пояснениям и записям находок, а на вкладке
        «Полные данные» — по содержимому разделов. Клавиша <b>/</b> ставит курсор в поиск.</p>
      </div>
    </div>
  </details>

  <div class="tabs" id="tabs">
    <div class="tab act" data-tab="find">Находки <span class="c" id="t-find"></span></div>
    <div class="tab" data-tab="sect">Полные данные <span class="c" id="t-sect"></span></div>
  </div>

  <div id="pane-find">
    <div class="bar">
      <div class="row">
        <input class="search" id="q" placeholder="Поиск по находкам: имя класса, пакет, загрузчик…">
        <button class="btn" id="btn-clear">Сбросить фильтры</button>
      </div>
      <div class="chips" id="cats"></div>
      <div class="hint" id="hint"></div>
    </div>
    <div id="findings"></div>
  </div>

  <div id="pane-sect" style="display:none">
    <div class="bar">
      <div class="row">
        <input class="search" id="qs" placeholder="Поиск по содержимому разделов…">
      </div>
      <div class="hint" id="hint-s"></div>
    </div>
    <div class="sec-wrap">
      <div class="sec-nav" id="sec-nav"></div>
      <div class="sec-body" id="sec-body"></div>
    </div>
  </div>

  <footer id="foot"></footer>
</div>
""";

    // ------------------------------------------------------------------ скрипт

    private const string Script = """
const D = JSON.parse(document.getElementById('csdata').textContent);
const SEV = {4:['КРИТИЧНО','crit'],3:['ВЫСОКАЯ','high'],2:['СРЕДНЯЯ','med'],1:['НИЗКАЯ','low'],0:['ИНФО','info']};
const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

D.findings.forEach(f => {
  f.idx = (f.title + ' ' + f.cat + ' ' + f.expl + ' ' + f.blocks.map(b => b[1]).join(' ')).toLowerCase();
});

const state = { sev: new Set([4,3,2,1,0]), cats: new Set(), q: '', tab: 'find', sec: 0 };

document.getElementById('hd-sub').textContent =
  D.version + ' · отчёт от ' + D.generated + ' · ' + D.elapsed + ' с';
document.getElementById('hd-target').textContent =
  'PID ' + D.pid + ' · ' + (D.meta.find(m => m[0] === 'Образ') || ['', ''])[1] + ' · ' + D.machine + '\\' + D.user;

const crit = D.summary['4'], high = D.summary['3'];
const v = document.getElementById('verdict');
if (crit > 0) {
  v.className = 'verdict red';
  v.innerHTML = '<span class="dot"></span><div><b>' + D.verdict + ': обнаружены классы, которых в чистом клиенте не бывает.</b>' +
    '<div class="note">Разберите критические находки: каждая содержит пояснение и полный список классов.</div></div>';
} else if (high > 0) {
  v.className = 'verdict yellow';
  v.innerHTML = '<span class="dot"></span><div><b>' + D.verdict + ': есть аномалии, требующие объяснения.</b>' +
    '<div class="note">Критических признаков нет, но найденное нуждается в ручной проверке.</div></div>';
} else {
  v.className = 'verdict green';
  v.innerHTML = '<span class="dot"></span><div><b>' + D.verdict + ': посторонних классов не найдено.</b>' +
    '<div class="note">Проверены только классы, загруженные в ВМ на момент сканирования. Просмотрите раздел «Полные данные».</div></div>';
}

const stats = document.getElementById('stats');
[4,3,2,1,0].forEach(s => {
  const d = document.createElement('div');
  d.className = 'stat s' + s;
  d.dataset.sev = s;
  d.innerHTML = '<div class="num">' + D.summary[s] + '</div><div class="lbl">' + SEV[s][0] + '</div>';
  d.onclick = () => { toggleSev(s); };
  stats.appendChild(d);
});

const meta = document.getElementById('meta');
D.meta.forEach(([k, val]) => {
  meta.insertAdjacentHTML('beforeend', '<div class="k">' + esc(k) + '</div><div class="v">' + esc(val) + '</div>');
});
meta.insertAdjacentHTML('beforeend',
  '<div class="k">Система</div><div class="v">' + esc(D.os) + '</div>' +
  '<div class="k">Проверку выполнил</div><div class="v">' + esc(D.machine + '\\' + D.user) + '</div>' +
  '<div class="k">Длительность проверки</div><div class="v">' + D.elapsed + ' с</div>');

document.getElementById('foot').textContent =
  'ClassScan ' + D.version + ' · находок: ' + D.findings.length + ' · разделов с полными данными: ' + D.sections.length;

const catCounts = {};
D.findings.forEach(f => catCounts[f.cat] = (catCounts[f.cat] || 0) + 1);
const catsBox = document.getElementById('cats');
Object.keys(catCounts).sort((a, b) => catCounts[b] - catCounts[a]).forEach(c => {
  const el = document.createElement('div');
  el.className = 'chip';
  el.innerHTML = esc(c) + '<span class="n">' + catCounts[c] + '</span>';
  el.onclick = () => {
    if (state.cats.has(c)) state.cats.delete(c); else state.cats.add(c);
    el.classList.toggle('on');
    render();
  };
  catsBox.appendChild(el);
});

function toggleSev(s) {
  if (state.sev.has(s)) state.sev.delete(s); else state.sev.add(s);
  document.querySelectorAll('.stat').forEach(el => el.classList.toggle('off', !state.sev.has(+el.dataset.sev)));
  render();
}

document.getElementById('q').oninput = e => { state.q = e.target.value.toLowerCase(); render(); };
document.getElementById('btn-clear').onclick = () => {
  state.sev = new Set([4,3,2,1,0]);
  state.cats.clear();
  state.q = '';
  document.getElementById('q').value = '';
  document.querySelectorAll('.stat').forEach(el => el.classList.remove('off'));
  document.querySelectorAll('#cats .chip').forEach(el => el.classList.remove('on'));
  render();
};
document.getElementById('btn-expand').onclick = () => document.querySelectorAll('#findings .card').forEach(c => c.classList.add('open'));
document.getElementById('btn-collapse').onclick = () => document.querySelectorAll('#findings .card').forEach(c => c.classList.remove('open'));
document.getElementById('btn-theme').onclick = () => {
  const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', cur);
  try { localStorage.setItem('classscan-theme', cur); } catch (e) {}
};
try { const t = localStorage.getItem('classscan-theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch (e) {}

document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
    e.preventDefault();
    (state.tab === 'sect' ? document.getElementById('qs') : document.getElementById('q')).focus();
  }
  if (e.key === 'Escape' && document.activeElement.tagName === 'INPUT') {
    document.activeElement.value = '';
    document.activeElement.dispatchEvent(new Event('input'));
  }
});

document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    state.tab = t.dataset.tab;
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('act', x === t));
    document.getElementById('pane-find').style.display = state.tab === 'find' ? '' : 'none';
    document.getElementById('pane-sect').style.display = state.tab === 'sect' ? '' : 'none';
  };
});
document.getElementById('t-find').textContent = D.findings.length;
document.getElementById('t-sect').textContent = D.sections.length;

function hl(text, q) {
  const s = esc(text);
  if (!q) return s;
  try {
    return s.replace(new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'), '<mark>$1</mark>');
  } catch (e) { return s; }
}

function cardHtml(f) {
  let h = '<div class="card c' + f.sev + '" data-n="' + f.n + '">';
  h += '<div class="chd"><span class="badge b' + f.sev + '">' + SEV[f.sev][0] + '</span>' +
       '<span class="cat">' + esc(f.cat) + '</span>' +
       '<span class="ttl">' + hl(f.title, state.q) + '</span>' +
       '<span class="idx">#' + f.n + '</span></div>';
  h += '<div class="cbody">';
  if (f.expl) h += '<div class="expl">' + hl(f.expl, state.q) + '</div>';
  f.blocks.forEach(([t, txt]) => {
    h += '<details class="blk" open><summary>' + esc(t) + ' — ' + f.count + '</summary><pre>' + hl(txt, state.q) + '</pre></details>';
  });
  h += '</div></div>';
  return h;
}

function render() {
  const list = D.findings.filter(f =>
    state.sev.has(f.sev) && (state.cats.size === 0 || state.cats.has(f.cat)) &&
    (state.q === '' || f.idx.indexOf(state.q) >= 0));
  const box = document.getElementById('findings');
  if (list.length === 0) {
    box.innerHTML = '<div class="empty">Ничего не найдено по текущим фильтрам.</div>';
  } else {
    box.innerHTML = list.map(cardHtml).join('');
    box.querySelectorAll('.chd').forEach(h => { h.onclick = () => h.parentElement.classList.toggle('open'); });
    box.querySelectorAll('.card.c4, .card.c3').forEach(c => c.classList.add('open'));
    if (state.q) {
      list.forEach(f => {
        if (f.title.toLowerCase().indexOf(state.q) < 0)
          box.querySelector('.card[data-n="' + f.n + '"]').classList.add('open');
      });
    }
  }
  const bySev = {};
  list.forEach(f => bySev[f.sev] = (bySev[f.sev] || 0) + 1);
  document.getElementById('hint').textContent =
    'Показано ' + list.length + ' из ' + D.findings.length + ' находок' +
    (list.length ? ' (' + [4,3,2,1,0].filter(s => bySev[s]).map(s => SEV[s][0].toLowerCase() + ': ' + bySev[s]).join(', ') + ')' : '') +
    '. Щёлкните по находке, чтобы раскрыть или свернуть подробности.';
}

const secNav = document.getElementById('sec-nav');
function countIn(text, q) {
  if (!q) return 0;
  let n = 0, i = 0;
  const low = text.toLowerCase();
  while ((i = low.indexOf(q, i)) >= 0) { n++; i += q.length; }
  return n;
}
function renderNav(q) {
  secNav.innerHTML = '';
  const hits = [];
  D.sections.forEach((s, i) => {
    if (!q) { hits.push([i, 0]); return; }
    const inTitle = s.title.toLowerCase().indexOf(q) >= 0;
    const c = countIn(s.text, q);
    if (inTitle || c > 0) hits.push([i, c]);
  });
  if (q && hits.length && !hits.some(h => h[0] === state.sec)) state.sec = hits[0][0];
  if (hits.length === 0) secNav.innerHTML = '<div style="color:var(--fg3);padding:9px 10px">Совпадений нет</div>';
  hits.forEach(([i, c]) => {
    const s = D.sections[i];
    const d = document.createElement('div');
    d.className = i === state.sec ? 'act' : '';
    d.innerHTML = esc(s.title) + '<span class="sz">' + (q && c ? '×' + c : Math.round(s.size / 1024) + 'К') + '</span>';
    d.onclick = () => { state.sec = i; renderNav(q); renderSec(q); };
    secNav.appendChild(d);
  });
  document.getElementById('hint-s').textContent = q
    ? 'Разделов с совпадением: ' + hits.length + ' из ' + D.sections.length + '. Число рядом с названием — сколько раз строка встречается в разделе.'
    : 'Разделов: ' + D.sections.length + '. Это полные данные, из которых сделаны находки.';
}
function renderSec(q) {
  const s = D.sections[state.sec];
  const body = document.getElementById('sec-body');
  if (!s) { body.innerHTML = '<div class="empty">Раздел не выбран.</div>'; return; }
  let h = '<h3>' + esc(s.title) + '</h3>';
  if (s.cut) h += '<div class="cutwarn">Раздел обрезан для HTML (' + Math.round(s.size / 1024) + ' КБ).</div>';
  h += '<pre>' + hl(s.text, q) + '</pre>';
  body.innerHTML = h;
  const m = body.querySelector('mark');
  if (m) m.scrollIntoView({block: 'center'});
}
document.getElementById('qs').oninput = e => { const q = e.target.value.toLowerCase(); renderNav(q); renderSec(q); };

render();
renderNav('');
renderSec('');
""";
}

internal static class Sections
{
    public static string OriginLabel(Origin o) => o switch
    {
        Origin.Runtime => "стандартная библиотека Java",
        Origin.Generated => "порождён рантаймом (лямбда, прокси, скрытый класс)",
        Origin.Array => "массив",
        Origin.Jar => "есть в архиве на диске",
        Origin.OwnedPackage => "нет в архиве, пакет принадлежит архиву",
        Origin.VanillaForeign => "имя в стиле обфускатора игры при игре на промежуточных именах",
        Origin.Torn => "имя из освобождённой памяти",
        _ => "БЕЗ ПРОИСХОЖДЕНИЯ",
    };

    public static string Loaders(ReportInput r)
    {
        var sb = new StringBuilder();
        var byCld = r.Analysis.Rows.GroupBy(x => x.K.Loader!.Address).ToDictionary(x => x.Key, x => x.ToList());
        sb.AppendLine($"Источник: {r.Graph.Source}");
        sb.AppendLine($"Записей ClassLoaderData: {r.Graph.Loaders.Count}, классов: {r.Graph.Klasses.Count}");
        sb.AppendLine();
        sb.AppendLine($"{"CLD",-18} {"КЛАССОВ",-8} {"БЕЗ ПРОИСХ.",-12} {"ПРИЗНАКИ",-30} КЛАСС ЗАГРУЗЧИКА");
        sb.AppendLine(new string('-', 140));
        int hidden = 0;
        foreach (var l in r.Graph.Loaders.OrderByDescending(x => x.Klasses.Count))
        {
            if (l.HiddenClassHolder) { hidden++; continue; }
            byCld.TryGetValue(l.Address, out var rows);
            int noOrigin = rows?.Count(x => x.Origin is Origin.None or Origin.VanillaForeign) ?? 0;
            string flags = (l.Bootstrap ? "начальный " : l.Privileged ? "привилегированный " : "") +
                           (l.LoaderIsHiddenClass ? "СКРЫТЫЙ КЛАСС" : "");
            sb.AppendLine($"0x{l.Address:X16} {l.Klasses.Count,-8} {noOrigin,-12} {flags,-30} {l.LoaderClass}");
        }
        if (hidden > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Записей скрытых классов (по одной на класс, не показаны): {hidden}");
        }
        sb.AppendLine();
        sb.AppendLine("КЛАССЫ КАЖДОГО ЗАГРУЗЧИКА (кроме начального и записей скрытых классов)");
        foreach (var l in r.Graph.Loaders.OrderByDescending(x => x.Klasses.Count))
        {
            if (l.HiddenClassHolder || l.Bootstrap) continue;
            sb.AppendLine();
            sb.AppendLine($"  {l.LoaderClass}  (0x{l.Address:X})  классов {l.Klasses.Count}");
            if (!byCld.TryGetValue(l.Address, out var rows)) continue;
            foreach (var x in rows.OrderBy(x => x.Name, StringComparer.Ordinal).Take(3000))
                sb.AppendLine($"      {x.Name,-100} {OriginLabel(x.Origin)}");
            if (rows.Count > 3000) sb.AppendLine($"      … ещё {rows.Count - 3000} (см. раздел «Все классы»)");
        }
        return sb.ToString();
    }

    public static string Origins(Analysis a)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Всего классов: {a.Rows.Count}");
        sb.AppendLine($"Игра на промежуточных именах Fabric: {(a.GameIsRemapped ? "да" : "нет")} " +
                      $"(class_NNN в процессе: {a.IntermediaryCount}, имён в стиле обфускатора игры в архивах: {a.VanillaInJars})");
        sb.AppendLine();
        foreach (var g in a.Rows.GroupBy(x => x.Origin).OrderByDescending(g => g.Count()))
            sb.AppendLine($"  {g.Count(),8}  {OriginLabel(g.Key)}");
        sb.AppendLine();
        sb.AppendLine("ПОРОЖДЁННЫЕ РАНТАЙМОМ, ПО ВИДАМ");
        foreach (var g in a.Rows.Where(x => x.Origin == Origin.Generated)
                     .GroupBy(x => JarIndex.GeneratedKind(x.Plain) ?? "?").OrderByDescending(g => g.Count()))
            sb.AppendLine($"  {g.Count(),8}  {g.Key}");
        sb.AppendLine();
        sb.AppendLine("ПАКЕТЫ, ПО ЧИСЛУ КЛАССОВ");
        foreach (var g in a.Rows.Where(x => x.Origin is not (Origin.Array or Origin.Torn))
                     .GroupBy(x => JavaNames.Package(x.Plain)).OrderByDescending(g => g.Count()).Take(400))
            sb.AppendLine($"  {g.Count(),8}  {g.Key,-80} без происхождения: {g.Count(x => x.Origin is Origin.None or Origin.VanillaForeign)}");
        return sb.ToString();
    }

    public static string Orphans(Analysis a)
    {
        var sb = new StringBuilder();
        var rows = a.Rows.Where(x => x.Origin is Origin.None or Origin.VanillaForeign).ToList();
        sb.AppendLine($"Классов без происхождения на диске: {rows.Count}");
        sb.AppendLine();
        sb.AppendLine($"{"КЛАСС",-90} {"В АРХИВЕ",-9} {"ПАКЕТ",-4}  ЗАГРУЗЧИК");
        sb.AppendLine(new string('-', 160));
        foreach (var x in rows.OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"{x.Name,-90} {(x.InJar ? "есть" : "НЕТ"),-9} {(x.NoPackage ? "нет" : "да"),-4}  {x.Loader} (0x{x.K.Loader!.Address:X})");
        sb.AppendLine();
        var owned = a.Rows.Where(x => x.Origin == Origin.OwnedPackage).ToList();
        sb.AppendLine($"Классов без файла в архиве, но с пакетом-предком в архиве: {owned.Count}");
        foreach (var x in owned.OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"  {x.Name,-90} пакет «{x.OwningPackage}»   {x.Loader}");
        return sb.ToString();
    }

    public static string Names(Analysis a)
    {
        var sb = new StringBuilder();
        var live = a.Rows.Where(x => x.Origin is not (Origin.Array or Origin.Torn)).ToList();
        sb.AppendLine($"  {live.Count(x => x.Origin == Origin.Runtime),8}  стандартная библиотека Java");
        sb.AppendLine($"  {live.Count(x => x.Origin == Origin.Generated),8}  порождены рантаймом");
        sb.AppendLine($"  {live.Count(x => x.Intermediary),8}  промежуточные имена Fabric (class_NNN)");
        sb.AppendLine($"  {live.Count(x => x.VanillaStyle),8}  обфускация Minecraft (короткие строчные)");
        sb.AppendLine($"  {live.Count(x => x.NonAscii || x.IllegalChar),8}  не-ASCII или недопустимый символ");
        sb.AppendLine($"  {live.Count(x => x.Confusable),8}  однотипные символы (I, l, O, 0, 1)");
        sb.AppendLine($"  {live.Count(x => x.RandomLike),8}  случайный вид (смешанный регистр без структуры слова)");
        sb.AppendLine($"  {live.Count(x => x.NoPackage),8}  без пакета");
        sb.AppendLine();
        sb.AppendLine($"{"НЕ-ASCII",-9} {"СИМВОЛ",-7} {"ОДНОТИП",-8} {"СЛУЧАЙН",-8} {"БЕЗ ПКТ",-8} {"В АРХИВЕ",-9} ИМЯ");
        sb.AppendLine(new string('-', 150));
        foreach (var x in live.Where(x => x.NonAscii || x.IllegalChar || x.Confusable || x.RandomLike || x.NoPackage)
                     .OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"{(x.NonAscii ? "да" : "-"),-9} {(x.IllegalChar ? "да" : "-"),-7} {(x.Confusable ? "да" : "-"),-8} " +
                          $"{(x.RandomLike ? "да" : "-"),-8} {(x.NoPackage ? "да" : "-"),-8} {(x.InJar ? "да" : "НЕТ"),-9} {x.Name}" +
                          (x.NonAscii && JavaNames.DescribeCodePoints(x.Name) is { Length: > 0 } d ? $"   ← {d}" : ""));
        return sb.ToString();
    }

    public static string Jars(JarIndex jars)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Архивов: {jars.Jars.Count}, классов в архивах: {jars.ClassCount}");
        sb.AppendLine();
        foreach (var j in jars.Jars.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) sb.AppendLine("  " + j);
        if (jars.Errors.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Не прочитаны:");
            foreach (var e in jars.Errors) sb.AppendLine("  " + e);
        }
        return sb.ToString();
    }

    public static string AllClasses(Analysis a)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{"КЛАСС",-100} {"ПРОИСХОЖДЕНИЕ",-58} ЗАГРУЗЧИК");
        sb.AppendLine(new string('-', 200));
        foreach (var x in a.Rows.OrderBy(x => x.Name, StringComparer.Ordinal))
            sb.AppendLine($"{x.Name,-100} {OriginLabel(x.Origin),-58} {x.Loader}");
        return sb.ToString();
    }
}
