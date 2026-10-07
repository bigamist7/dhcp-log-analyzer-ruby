# DHCP Log Analyzer (Ruby)

Scripts em Ruby para analisar logs DHCP e detetar comportamentos suspeitos de rede.
Trabalho da UFCD 01482, CET em Cibersegurança, IEFP Alcoitão.

O repositório reúne três tarefas independentes:

| Pasta | Script | O que faz |
|---|---|---|
| `T1_normalizar_log/` | `normalizar_log.rb` | Normaliza datas (`AAAA-MM-DD`) e MACs (`AA:BB:CC:DD:EE:FF`) de um log |
| `T2_dif_temps/` | `dif_temps_v2.rb` | Analisador de logs DHCP com 11 regras de deteção (trabalho final) |
| `T3_comparar_logs/` | `comparar_logs.rb` | Compara dois logs linha a linha com a distância de Levenshtein |

## Requisitos

- Ruby 3.x
- T3: gem `text` (`gem install text`)
- T2: ligação à internet só para localizar IPs externos (opcional, o resto funciona offline)

## T2 · dif_temps_v2.rb

Lê o log **uma única vez** e assinala os IPs suspeitos. Os alertas ficam gravados em `anomalias.txt`.

### Deteções (11 regras)

1. Reconexões em menos de 1 minuto
2. Hora anterior à da ocorrência anterior (relógio dessincronizado ou log adulterado)
3. Beaconing (intervalos regulares e curtos)
4. Classificação do IP (rede interna, privado de outra rede, APIPA, loopback, documentação, público, formato inválido)
5. MAC partilhado por vários IPs
6. Vários hostnames no mesmo IP
7. Vários MACs no mesmo IP
8. Esgotamento do pool DHCP (starvation, eventos ID 10 e ID 14)
9. IP na blacklist (`ipnegras.txt`, IPs isolados num `Set` e gamas CIDR)
10. Acesso fora do horário de funcionamento (8h-20h)
11. País suspeito (Rússia e China), só para IPs externos

### Leitura flexível

Sem posições ou colunas fixas. Cada campo é reconhecido por expressões regulares:

- separadores `,` `;` tabulação ou espaços
- datas ISO (`2024-02-20`), `20/02/2024`, `02/20/24`
- MAC com `:` `-` ou sem separadores
- campos por qualquer ordem

`Logs_Teste_3.log` tem os mesmos eventos de `Logs_Teste_2.log`, noutro formato e com os campos baralhados, e o resultado da análise é idêntico.

### Utilização

```powershell
cd T2_dif_temps
ruby dif_temps_v2.rb                      # analisa Logs_Teste_2.log
ruby dif_temps_v2.rb Logs_Teste_3.log     # outro formato, mesmo resultado
ruby dif_temps_v2.rb "C:\caminho\outro_log.log"
```

Resultado esperado para os logs de teste: 24 IPs distintos, 22 suspeitos. Com a lista de exemplo (`ipnegras.txt`) há 2 IPs na blacklist.

### Ficheiros

| Ficheiro | Descrição |
|---|---|
| `dif_temps_v2.rb` | Script principal |
| `ipnegras.txt` | Blacklist de exemplo (um IP ou gama CIDR por linha) |
| `Logs_Teste_2.log` | Log de teste que demonstra todas as situações |
| `Logs_Teste_3.log` | O mesmo log noutro formato |
| `cache_ips.json` | Cache de localizações (gerado automaticamente) |
| `anomalias.txt` | Alertas (gerado a cada execução) |

### Limitações

- Datas ambíguas (por exemplo `02/03/24`) assumem o mês primeiro
- O hostname é reconhecido por heurística
- O beaconing só apanha intervalos praticamente constantes
- Uma rajada legítima de atribuições pode parecer starvation
- A localização de IPs anycast é pouco fiável (API gratuita ip-api.com, HTTP, 45 pedidos por minuto)
- O script assinala, não decide: "suspeito" significa investigar, não malicioso

## T1 · normalizar_log.rb

```powershell
cd T1_normalizar_log
ruby normalizar_log.rb log1.log log2.log
```

Lê `log1.log` e grava `log2.log` com datas e MACs normalizados. Valores que não reconhece são mantidos e assinalados com um aviso.

## T3 · comparar_logs.rb

```powershell
gem install text
cd T3_comparar_logs
ruby comparar_logs.rb log1.log log2.log
```

Mostra as linhas diferentes com a distância de Levenshtein, e no fim indica se os ficheiros são iguais, o número de linhas diferentes e a distância total.

## Autor

João Casanova Pinto · CET Cibersegurança · IEFP Alcoitão
