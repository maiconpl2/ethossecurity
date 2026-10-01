"""A local, script-free overview; all scanner-provided strings are escaped."""
from html import escape
from pathlib import Path

def html_report(report, output, language='pt-BR'):
    pt = language == 'pt-BR'
    def t(a, b):
        return a if pt else b
    def e(value):
        return escape(str(value or '—'), quote=True)
    state = t('Verificações habilitadas concluídas', 'Enabled checks completed') if report['complete'] else t('Análise incompleta', 'Incomplete analysis')
    rows = ''.join('<tr><td>' + e(r['scanner']) + '</td><td>' + e(r['status']) + '</td><td>' + e(' '.join(filter(None, [r.get('reason'), ', '.join(r.get('unanalyzed_files', []))]))) + '</td></tr>' for r in report['executions'])
    cards = []
    for f in report['findings']:
        location = (f.get('file') or f.get('endpoint') or '—') + (':' + str(f['line']) if f.get('line') else '')
        cards.append('<article><h2>' + e(f['title']) + '</h2><p>' + e(f['severity']) + ' · ' + e(f['scanner_source']) + ' · ' + e(f['validation_status']) + '</p><p><strong>' + e(location) + '</strong></p><p>' + e(f['evidence']) + '</p><p>' + e(f['recommendation']) + '</p></article>')
    text = '''<!doctype html><html lang="''' + e(language) + '''"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>EthosSecurity</title><style>body{font:17px/1.55 system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 24px;color:#182c36;background:#f7fafb}h1{color:#075d65}article,section{background:white;border:1px solid #d7e4e7;border-radius:12px;padding:20px;margin:20px 0}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #d7e4e7;overflow-wrap:anywhere}p{overflow-wrap:anywhere}.notice{border-left:5px solid #c28211;padding:14px;background:#fff5df}</style><h1>EthosSecurity</h1><p>''' + e(report['root']) + '</p><h2>' + state + '</h2><p>' + str(len(report['findings'])) + ' ' + t('alertas para investigar.', 'alerts to investigate.') + '</p><p class="notice">' + t('Alertas ainda precisam de validação. Ausência de alertas não comprova segurança. As regras iniciais de código têm cobertura limitada; autenticação, permissões e isolamento entre clientes precisam de revisão contextual pelo assistente.', 'Alerts still need validation. No alerts does not prove security. Starter code rules have limited coverage; authentication, permissions and tenant isolation need contextual review by the assistant.') + '</p><section><h2>' + t('O que foi executado', 'What ran') + '</h2><table><thead><tr><th>' + t('Ferramenta', 'Tool') + '</th><th>Status</th><th>' + t('Observação', 'Note') + '</th></tr></thead><tbody>' + rows + '</tbody></table></section>' + ''.join(cards) + '<p>' + t('Relatório local. Valores de credenciais detectadas pelo Gitleaks são omitidos. Trate este arquivo como informação privada do projeto.', 'Local report. Credential values detected by Gitleaks are omitted. Treat this file as private project information.') + '</p></html>'
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(text, encoding='utf-8')
    return str(Path(output).resolve())
