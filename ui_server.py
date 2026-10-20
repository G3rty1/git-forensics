#!/usr/bin/env python3
"""Локальный веб-интерфейс для git_forensics.py.

Положите рядом с git_forensics.py и запустите:  py ui_server.py
Откроется http://127.0.0.1:8765  (доступно только с вашего компьютера).
Только стандартная библиотека, ничего устанавливать не нужно.
"""
import http.server
import json
import os
import sys
import threading
import webbrowser
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import git_forensics

HOST, PORT = "127.0.0.1", 8765
MAX_BODY_BYTES = 100_000
LOCAL_HOSTNAMES = ("localhost", "127.0.0.1", "::1")


def _header_hostname(value):
    """Имя хоста из заголовка Host или Origin (без порта)."""
    try:
        if "://" in value:
            host = urlparse(value).hostname or ""
        else:
            host = value.split(":")[0]
        return host.strip("[]").lower()
    except Exception:
        return ""


def run_analysis(repo, file):
    repo = os.path.abspath(os.path.expanduser((repo or "").strip().strip('"')))
    file = (file or "").strip().strip('"')
    if not os.path.isdir(repo):
        return 400, {"error": "Папка репозитория не найдена: " + repo}
    if not file or file.startswith("-"):
        return 400, {"error": "Укажите путь к файлу внутри репозитория."}
    # Папка репозитория передаётся напрямую: рабочая папка процесса
    # не меняется, параллельные запросы друг другу не мешают.
    try:
        data = git_forensics.analyze(file, repo=repo)
    except Exception as error:
        data = {"analysis_status": "failed", "error": str(error)}
    return 200, data


class Handler(http.server.BaseHTTPRequestHandler):
    def _local_origins(self):
        """Разрешённые источники: localhost с фактическим портом сервера."""
        port = self.server.server_address[1]
        return {
            f"http://{host}:{port}"
            for host in LOCAL_HOSTNAMES
        }

    def _host_allowed(self, value):
        """Host должен быть localhost и, если порт указан, совпадать с портом сервера."""
        if _header_hostname(value) not in LOCAL_HOSTNAMES:
            return False
        if ":" in value:
            port = value.rsplit(":", 1)[-1]
            if port != str(self.server.server_address[1]):
                return False
        return True

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path != "/analyze":
            return self._send(404, json.dumps({"error": "not found"}))
        # Тело читается до ответа: ответ не должен обгонять запрос,
        # иначе клиент может получить обрыв соединения.
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n <= 0 or n > MAX_BODY_BYTES:
            return self._send(400, json.dumps({"error": "Некорректный запрос."}))
        body = self.rfile.read(n)
        # защита от запросов с чужих сайтов
        if not self._host_allowed(self.headers.get("Host", "")):
            return self._send(403, json.dumps({"error": "forbidden"}))
        origin = self.headers.get("Origin")
        if origin and origin not in self._local_origins():
            return self._send(403, json.dumps({"error": "forbidden"}))
        if self.headers.get_content_type() != "application/json":
            return self._send(400, json.dumps({"error": "Ожидается application/json."}))
        try:
            req = json.loads(body.decode("utf-8"))
        except Exception:
            return self._send(400, json.dumps({"error": "Некорректный запрос."}))
        if not isinstance(req, dict):
            return self._send(400, json.dumps({"error": "Некорректный запрос."}))
        repo, file = req.get("repo"), req.get("file")
        if not isinstance(repo, str) or not isinstance(file, str):
            return self._send(400, json.dumps({"error": "Некорректный запрос."}))
        code, data = run_analysis(repo, file)
        self._send(code, json.dumps(data, ensure_ascii=False))

    def log_message(self, *args):
        pass


PAGE = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Git Forensics</title>
<style>
:root{--bg:#eef0f3;--surface:#fff;--ink:#1b2430;--muted:#5d6877;--line:#d3d8df;
--ok:#1f6f4a;--ok-bg:#e3f2ea;--warn:#a4410e;--warn-bg:#fbeadf;--info:#244f8f;--info-bg:#e5edf8}
@media(prefers-color-scheme:dark){:root{--bg:#14181e;--surface:#1d232b;--ink:#e6e9ee;--muted:#9aa5b4;--line:#323b47;
--ok:#6fd1a0;--ok-bg:#183326;--warn:#f0a06c;--warn-bg:#3a2415;--info:#8db4ef;--info-bg:#1a2a44}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:28px 18px 60px}
	h1{font:600 26px/1.2 Georgia,"Times New Roman",serif;margin:0 0 4px}
	.sub{color:var(--muted);margin:0 0 22px}
	form{display:grid;gap:12px;background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:16px}
	label{display:grid;gap:4px;font-weight:600;font-size:14px}
	input{font:inherit;padding:9px 10px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--ink)}
	input:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--info);outline-offset:2px}
	button{font:inherit;font-weight:600;padding:10px 16px;border:0;border-radius:4px;background:var(--ink);color:var(--bg);cursor:pointer;justify-self:start}
	button:disabled{opacity:.55;cursor:wait}
#out{margin-top:22px;display:grid;gap:14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:14px 16px}
.verdict{border-left:6px solid var(--info);background:var(--info-bg)}
.verdict.ok{border-color:var(--ok);background:var(--ok-bg)}
.verdict.warn{border-left-color:var(--warn);background:var(--warn-bg)}
.verdict h2{margin:0 0 4px;font-size:19px}
.verdict p{margin:0}
	h3{margin:0 0 8px;font-size:16px}
.row{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;font-size:15px}
.row dt{color:var(--muted)}.row dd{margin:0;overflow-wrap:anywhere}
code{font:13px Consolas,monospace;background:var(--bg);padding:1px 5px;border-radius:3px}
.anom{border-left:4px solid var(--warn);padding:2px 0 2px 12px;margin:10px 0}
.anom b{display:block}.anom span{color:var(--muted);font-size:14px;overflow-wrap:anywhere}
.err{border-left:6px solid var(--warn);background:var(--warn-bg)}
pre{overflow-x:auto;font:12.5px/1.5 Consolas,monospace;margin:8px 0 0;white-space:pre-wrap}
summary{cursor:pointer;font-weight:600}
@media(max-width:520px){.row{grid-template-columns:1fr}}
</style></head><body><main>
<h1>Проверка дат файла в Git</h1>
<p class="sub">Показывает, когда файл появился в истории, и ищет несостыковки в датах коммитов.</p>
<form id="f">
<label>Папка репозитория<input id="repo" required placeholder="например: C:\projects\my-repo"></label>
<label>Файл внутри репозитория<input id="file" required placeholder="test.txt"></label>
<button id="go" type="submit">Проверить файл</button>
</form>
<div id="out" aria-live="polite"></div>
</main>
<script>
const LABELS={
 author_commit_date_mismatch:"Дата автора и дата коммита сильно расходятся",
 parent_child_order_violation:"Родительский коммит датирован позже дочернего",
 future_commit_date:"Коммит датирован будущим числом",
 reflog_commit_date_mismatch:"Дата коммита не совпадает с журналом reflog (вспомогательный признак)"};
const VERDICTS={
 anomalies_found:["warn","Найдены аномалии","В датах коммитов есть несостыковки. Подробности ниже."],
 no_anomalies_detected:["ok","Аномалий не найдено","Это не доказывает подлинность истории: даты в Git задаёт клиент."],
 insufficient_data:["info","Данных недостаточно","История неполная (shallow-клон), вывод сделать нельзя."]};
const $=id=>document.getElementById(id);
function el(tag,props,...kids){const e=document.createElement(tag);
 if(props)for(const k in props){if(k==="class")e.className=props[k];else e[k]=props[k]}
 for(const c of kids)e.append(c instanceof Node?c:document.createTextNode(c));return e}
function fmt(d){if(!d)return"—";const t=new Date(d);return isNaN(t)?d:t.toLocaleString("ru-RU")+" ("+d+")"}
function commitCard(title,info,tech){
 const c=el("div",{class:"card"},el("h3",null,title));
 const dl=el("dl",{class:"row"});
 const add=(k,v)=>{dl.append(el("dt",null,k),el("dd",null,v))};
 add("Дата",fmt(info.value));
 add("Коммит",el("code",null,(info.commit||"").slice(0,12)));
 if(tech){add("Автор",tech.author+", "+fmt(tech.author_date));
  add("Коммиттер",tech.committer+", "+fmt(tech.commit_date));
  add("Сообщение",tech.message)}
 add("Уверенность",info.confidence||"—");
 c.append(dl);return c}
function render(d){
 const out=$("out");out.replaceChildren();
 if(d.error){out.append(el("div",{class:"card err"},el("h3",null,"Не удалось выполнить проверку"),d.error,
  d.details?el("pre",null,d.details):""));return}
 const v=VERDICTS[d.final_verdict]||["info","Вердикт: "+d.final_verdict,""];
 out.append(el("div",{class:"card verdict "+v[0]},el("h2",null,v[1]),el("p",null,d.summary||v[2])));
 if(d.analysis_status&&d.analysis_status!=="completed")
  out.append(el("div",{class:"card"},"Анализ выполнен не полностью (статус: "+d.analysis_status+"). Причины смотрите в блоке «Ограничения метода»."));
 const t=d.technical||{};
 if(d.created_at)out.append(commitCard("Файл появился в истории",d.created_at,t.creation_commit));
 if(d.last_modified_at)out.append(commitCard("Последнее изменение",d.last_modified_at,t.last_modified_commit));
 if((d.anomalies||[]).length){
  const c=el("div",{class:"card"},el("h3",null,"Аномалии ("+d.anomalies.length+")"));
  for(const a of d.anomalies){
   const ids=(a.commits||[a.commit]).filter(Boolean).map(x=>x.slice(0,10)).join(", ");
   c.append(el("div",{class:"anom"},el("b",null,LABELS[a.type]||a.type),
    el("span",null,"Коммиты: "+ids+". "+(a.details||""))))}
  out.append(c)}
 const g=d.gpg_verification;
 if(g)out.append(el("div",{class:"card"},el("h3",null,"Подпись GPG"),
  g.signed?"Подпись проверена. Ключ: "+(g.key_id||"?")+(g.source?", источник: "+g.source:""):
  g.verification_status==="unsigned"?"Коммит не подписан.":"Подпись есть, но проверить её не удалось."+(g.details?" "+g.details:"")));
 if((d.limitations||[]).length){
  const c=el("div",{class:"card"},el("h3",null,"Ограничения метода"));
  for(const l of d.limitations)c.append(el("p",{style:"margin:6px 0"},l.details));
  out.append(c)}
 if(t.file_history_commits)out.append(el("div",{class:"card"},el("details",null,
  el("summary",null,"Коммиты, затронувшие файл ("+t.file_history_commits.length+")"),
  el("pre",null,t.file_history_commits.join("\n")),
  t.dag_creation?el("p",{style:"margin:12px 0 0;color:var(--muted);font-size:14px"},"Весь граф репозитория (не только этот файл):"):"",
  t.dag_creation?el("pre",null,t.dag_creation):"")));
 out.append(el("div",{class:"card"},el("details",null,el("summary",null,"Полный JSON-отчёт"),
  el("pre",null,JSON.stringify(d,null,2)))))}
$("f").addEventListener("submit",async e=>{
 e.preventDefault();$("go").disabled=true;$("go").textContent="Проверяю…";
 try{const r=await fetch("/analyze",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({repo:$("repo").value,file:$("file").value})});render(await r.json())}
 catch(x){render({error:"Сервер недоступен. Запущен ли ui_server.py?"})}
 $("go").disabled=false;$("go").textContent="Проверить файл"});
try{const s=localStorage.getItem("gf");if(s){const o=JSON.parse(s);$("repo").value=o.r||"";$("file").value=o.f||""}}catch(_){}
$("f").addEventListener("submit",()=>{try{localStorage.setItem("gf",JSON.stringify({r:$("repo").value,f:$("file").value}))}catch(_){}});
</script></body></html>"""


def make_server(host=HOST, port=PORT):
    """Создать HTTP-сервер (используется и в тестах)."""
    return http.server.ThreadingHTTPServer((host, port), Handler)


def main():
    srv = make_server()
    url = f"http://{HOST}:{PORT}"
    print("Интерфейс запущен:", url, "\nОстановить: Ctrl+C")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
        srv.server_close()


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main()
