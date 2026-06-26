"""
Sistema de Cadastro de Currículos
Segurança: SQL Injection, XSS, Cross-site History Manipulation
"""

import sqlite3
import secrets
import html
import re
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, abort
)

app = Flask(__name__)
# Chave secreta forte para sessões e tokens CSRF
app.secret_key = secrets.token_hex(32)

DATABASE = "curriculos.db"

# ─── Banco de dados ──────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS curriculos (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                nome     TEXT    NOT NULL,
                email    TEXT    NOT NULL,
                telefone TEXT,
                site     TEXT,
                experiencia TEXT NOT NULL
            )
        """)
        db.commit()

# ─── Segurança ────────────────────────────────────────────────────────────────

def gerar_csrf_token():
    """Gera e armazena token CSRF na sessão."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def verificar_csrf(token_enviado):
    """Valida token CSRF (proteção contra CSRF / history manipulation)."""
    token_sessao = session.get("csrf_token")
    if not token_sessao or not secrets.compare_digest(token_sessao, token_enviado or ""):
        abort(403)

def sanitizar(texto):
    """
    Escapa caracteres HTML para prevenir XSS.
    Flask/Jinja2 já faz auto-escape nos templates, mas esta função
    é uma camada extra para dados exibidos fora do contexto de template.
    """
    if texto is None:
        return ""
    return html.escape(str(texto).strip())

def validar_email(email):
    padrao = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(padrao, email) is not None

def validar_url(url):
    if not url:
        return True  # campo opcional
    padrao = r"^https?://[^\s]+"
    return re.match(padrao, url) is not None

# ─── Cabeçalhos de segurança ──────────────────────────────────────────────────

@app.after_request
def adicionar_cabecalhos_seguranca(response):
    # Impede que o browser renderize conteúdo de tipo diferente do declarado
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Impede clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Habilita filtro XSS em browsers mais antigos
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Content Security Policy: bloqueia scripts inline não autorizados
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'none';"
    )
    # Evita que o browser armazene páginas sensíveis no histórico/cache
    # Proteção contra Cross-site History Manipulation
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# ─── Rotas ────────────────────────────────────────────────────────────────────

@app.route("/")
def listar():
    """Tela 1 – listagem de currículos (nome + e-mail)."""
    db = get_db()
    # Consulta parametrizada: sem SQL Injection possível
    curriculos = db.execute(
        "SELECT id, nome, email FROM curriculos ORDER BY nome COLLATE NOCASE"
    ).fetchall()
    return render_template("listar.html", curriculos=curriculos)


@app.route("/cadastrar", methods=["GET", "POST"])
def cadastrar():
    """Tela 2 – cadastro de novo currículo."""
    erros = []

    if request.method == "POST":
        # 1. Validação CSRF (Cross-site History Manipulation / CSRF)
        verificar_csrf(request.form.get("csrf_token"))

        # 2. Coleta e sanitização dos campos
        nome        = sanitizar(request.form.get("nome", ""))
        email       = sanitizar(request.form.get("email", ""))
        telefone    = sanitizar(request.form.get("telefone", ""))
        site        = sanitizar(request.form.get("site", ""))
        experiencia = sanitizar(request.form.get("experiencia", ""))

        # 3. Validação de obrigatoriedade
        if not nome:
            erros.append("Nome é obrigatório.")
        if not email:
            erros.append("E-mail é obrigatório.")
        elif not validar_email(email):
            erros.append("Formato de e-mail inválido.")
        if not experiencia:
            erros.append("Experiência profissional é obrigatória.")
        if site and not validar_url(site):
            erros.append("URL do site deve começar com http:// ou https://")

        if not erros:
            db = get_db()
            # Inserção parametrizada: previne SQL Injection
            db.execute(
                """INSERT INTO curriculos (nome, email, telefone, site, experiencia)
                   VALUES (?, ?, ?, ?, ?)""",
                (nome, email, telefone or None, site or None, experiencia)
            )
            db.commit()
            # Regenera o token CSRF após uso bem-sucedido
            session.pop("csrf_token", None)
            return redirect(url_for("listar"))

    csrf_token = gerar_csrf_token()
    return render_template("cadastrar.html", erros=erros, csrf_token=csrf_token)


@app.route("/curriculo/<int:curriculo_id>")
def consultar(curriculo_id):
    """Tela 3 – detalhes de um currículo."""
    db = get_db()
    # Consulta parametrizada: sem SQL Injection possível
    curriculo = db.execute(
        "SELECT * FROM curriculos WHERE id = ?", (curriculo_id,)
    ).fetchone()

    if curriculo is None:
        abort(404)

    return render_template("consultar.html", curriculo=curriculo)


@app.errorhandler(403)
def erro_403(e):
    return render_template("erro.html", codigo=403,
                           mensagem="Requisição inválida ou token de segurança expirado."), 403

@app.errorhandler(404)
def erro_404(e):
    return render_template("erro.html", codigo=404,
                           mensagem="Currículo não encontrado."), 404


# ─── Inicialização ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=False)
