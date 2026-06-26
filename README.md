# CurriculoApp — Sistema de Cadastro de Currículos

Sistema web desenvolvido em **Python + Flask + SQLite** com proteções contra
SQL Injection, XSS e Cross-site History Manipulation.

---

## Requisitos

```
Python 3.9+
Flask >= 3.0
```

## Instalação e execução

```bash
# 1. Instalar dependências
pip install flask

# 2. Executar
python app.py

# 3. Acessar no browser
http://localhost:5000
```

---

## Telas

| Rota | Tela | Descrição |
|---|---|---|
| `/` | Tela 1 | Lista todos os currículos (nome + e-mail) |
| `/cadastrar` | Tela 2 | Formulário de cadastro de novo currículo |
| `/curriculo/<id>` | Tela 3 | Detalhes completos de um currículo |

---

## Campos do cadastro

| Campo | Obrigatório |
|---|---|
| Nome | ✅ |
| E-mail | ✅ |
| Experiência Profissional | ✅ |
| Telefone | Opcional |
| Endereço WEB | Opcional |

---

## Proteções de segurança implementadas

### 1. SQL Injection

**Problema:** concatenar entrada do usuário diretamente numa query SQL permite que um
atacante altere a lógica da query (ex.: `' OR '1'='1`).

**Solução implementada:** todas as queries usam **parâmetros preparados** (`?`) do
sqlite3. A entrada do usuário **nunca** é concatenada à string SQL.

```python
# ✅ SEGURO — parâmetro parametrizado
db.execute("SELECT * FROM curriculos WHERE id = ?", (curriculo_id,))

# ❌ INSEGURO — não usado no projeto
db.execute(f"SELECT * FROM curriculos WHERE id = {curriculo_id}")
```

---

### 2. Cross-site Scripting (XSS)

**Problema:** se dados do usuário forem renderizados sem escape no HTML, um atacante
pode injetar `<script>alert('XSS')</script>` e executar código no browser da vítima.

**Soluções implementadas (camadas múltiplas):**

**a) Jinja2 auto-escape (padrão no Flask)**  
Toda variável `{{ valor }}` é automaticamente escapada para entidades HTML.
`<script>` vira `&lt;script&gt;` e nunca é executado.

**b) `html.escape()` antes de persistir**  
A função `sanitizar()` em `app.py` aplica escape antes de gravar no banco,
adicionando uma segunda linha de defesa.

**c) Content Security Policy (CSP)**  
O cabeçalho HTTP bloqueia scripts inline e de origens externas não autorizadas:
```
Content-Security-Policy: default-src 'self'; script-src 'none';
```

**d) `rel="noopener noreferrer"` em links externos**  
Impede tab-napping (a página aberta não acessa `window.opener`).

---

### 3. Cross-site History Manipulation (CSHM)

**Problema:** se dados sensíveis forem enviados via GET, eles aparecem na URL e ficam
armazenados no histórico do browser e em logs de servidor. Um atacante com acesso ao
histórico pode recuperar esses dados. Além disso, formulários sem proteção CSRF
permitem que um site malicioso envie requisições em nome do usuário autenticado.

**Soluções implementadas:**

**a) Formulários via POST (nunca GET)**  
Parâmetros não aparecem na URL e, portanto, não são armazenados no histórico.

**b) Token CSRF por sessão**  
Cada formulário inclui um token aleatório de 32 bytes gerado pelo servidor.
O servidor valida o token antes de processar qualquer POST.
Sem o token correto, a requisição é rejeitada com HTTP 403.

```python
# Geração
session["csrf_token"] = secrets.token_hex(32)

# Validação — secrets.compare_digest evita timing attacks
secrets.compare_digest(token_sessao, token_enviado)
```

**c) Cabeçalhos de cache**  
```
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
```
Impedem que o browser armazene páginas com dados sensíveis em cache ou
histórico de navegação.

**d) Referrer-Policy**  
```
Referrer-Policy: no-referrer
```
Impede que a URL da página atual vaze para sites externos via header Referer.

---

## Estrutura de arquivos

```
curriculos/
├── app.py                  # Aplicação principal
├── curriculos.db           # Banco SQLite (gerado automaticamente)
└── templates/
    ├── base.html           # Layout base com CSS e cabeçalhos de segurança
    ├── listar.html         # Tela 1 — listagem
    ├── cadastrar.html      # Tela 2 — cadastro
    ├── consultar.html      # Tela 3 — detalhes
    └── erro.html           # Páginas de erro (403, 404)
```

---

## Resumo das proteções por camada

| Ataque | Camada 1 | Camada 2 | Camada 3 |
|---|---|---|---|
| SQL Injection | Queries parametrizadas | — | — |
| XSS | Jinja2 auto-escape | `html.escape()` no servidor | CSP header |
| CSRF / History Manipulation | Formulários POST | Token CSRF | `Cache-Control: no-store` |
