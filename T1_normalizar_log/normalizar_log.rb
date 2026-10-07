#!/usr/bin/env ruby
# frozen_string_literal: true

# ==========================================================
# NORMALIZAÇÃO DE LOGS (T1)
# ==========================================================
#
# Objetivo: ler um log ("log1.log") cujas linhas podem vir de sistemas
# diferentes, com datas e MACs escritos de formas diferentes, e gravar um
# novo log ("log2.log") com tudo no MESMO formato:
#
#   - Data: sempre AAAA-MM-DD (formato ISO), seja qual for o formato de
#     origem (MM/DD/AA, DD/MM/AA, MM/DD/AAAA ou DD/MM/AAAA);
#   - MAC:  sempre AA:BB:CC:DD:EE:FF (maiúsculas, dois pontos), seja qual
#     for o formato de origem (sem separador, com traços ou com dois pontos).
#
# Pressuposto sobre o log: usa o mesmo formato CSV dos logs DHCP já usados
# no resto do trabalho (campos separados por vírgula: ID, Data, Hora,
# Descrição, IP, Hostname, MAC, ...). Se o teu log1.log tiver outra
# estrutura, basta ajustar as duas constantes IDX_DATA / IDX_MAC abaixo.
#
# USO
# ---
#   ruby normalizar_log.rb
#   ruby normalizar_log.rb log1.log
#   ruby normalizar_log.rb log1.log log2_novo.log
# ==========================================================

# ----------------------------------------------------------
# CONFIGURAÇÃO
# ----------------------------------------------------------

CAMINHO_LOG_ORIGINAL    = "log1.log"
CAMINHO_LOG_NORMALIZADO = "log2.log"

# Posição dos campos no CSV (0 = primeiro campo).
IDX_DATA = 1
IDX_MAC  = 6

# Nº mínimo de campos para uma linha ser considerada "linha de dados".
# Linhas com menos campos (cabeçalho, linhas em branco, texto solto) são
# copiadas para o log novo tal como estão, sem tentar normalizar.
MIN_CAMPOS_LINHA_DE_DADOS = 7

# Quando a data é ambígua (ex.: 03/04/24 — pode ser 3 de abril OU 4 de
# março), não há forma de saber ao certo qual é o formato certo só a olhar
# para a data. Nesse caso, assumimos MÊS/DIA (o formato mm/dd usado no
# resto dos nossos logs DHCP). Muda para false se o teu log1.log vier
# tipicamente no formato dia/mês.
ASSUMIR_MES_PRIMEIRO_SE_AMBIGUO = true

# ----------------------------------------------------------
# EXPRESSÕES REGULARES
# ----------------------------------------------------------

# Datas com ano de 4 dígitos: MM/DD/AAAA ou DD/MM/AAAA
REGEX_DATA_ANO_4 = %r{\A(\d{1,2})/(\d{1,2})/(\d{4})\z}

# Datas com ano de 2 dígitos: MM/DD/AA ou DD/MM/AA
REGEX_DATA_ANO_2 = %r{\A(\d{1,2})/(\d{1,2})/(\d{2})\z}

# MAC sem separadores: 080027ECA6CE (12 carateres hexadecimais)
REGEX_MAC_SEM_SEPARADOR = /\A[0-9A-Fa-f]{12}\z/

# MAC com separador (":" ou "-"): 08:00:27:EC:A6:CE ou 08-00-27-EC-A6-CE
REGEX_MAC_COM_SEPARADOR =
  %r{\A([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})
      [:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})\z}x

# ----------------------------------------------------------
# NORMALIZAÇÃO DA DATA
# ----------------------------------------------------------

# Recebe uma data em qualquer dos 4 formatos aceites e devolve-a em
# "AAAA-MM-DD", ou nil se não conseguir interpretá-la.
def normalizar_data(texto)
  texto = texto.to_s.strip

  if (m = texto.match(REGEX_DATA_ANO_4))
    a, b, ano = m.captures
    ano = ano.to_i
  elsif (m = texto.match(REGEX_DATA_ANO_2))
    a, b, ano2 = m.captures
    # Ano com 2 dígitos: 00-69 -> 20xx, 70-99 -> 19xx (heurística comum;
    # não há forma de saber ao certo só a partir de 2 dígitos).
    ano2 = ano2.to_i
    ano  = ano2 < 70 ? 2000 + ano2 : 1900 + ano2
  else
    return nil   # não corresponde a nenhum dos 4 formatos aceites
  end

  a = a.to_i
  b = b.to_i

  # Descobrir qual dos dois números é o mês e qual é o dia.
  if a > 12 && b <= 12
    dia, mes = a, b                              # só pode ser DD/MM
  elsif b > 12 && a <= 12
    mes, dia = a, b                               # só pode ser MM/DD
  elsif a <= 12 && b <= 12
    # Ambíguo (os dois números são <= 12): aplicar a convenção definida
    # no topo do script.
    if ASSUMIR_MES_PRIMEIRO_SE_AMBIGUO
      mes, dia = a, b
    else
      dia, mes = a, b
    end
  else
    return nil   # os dois números > 12: não é uma data válida
  end

  return nil unless (1..12).cover?(mes) && (1..31).cover?(dia)

  format("%04d-%02d-%02d", ano, mes, dia)
end

# ----------------------------------------------------------
# NORMALIZAÇÃO DO MAC
# ----------------------------------------------------------

# Recebe um MAC em qualquer dos 3 formatos aceites e devolve-o em
# "AA:BB:CC:DD:EE:FF", ou nil se não conseguir interpretá-lo.
def normalizar_mac(texto)
  texto = texto.to_s.strip
  return nil if texto.empty?

  if texto.match?(REGEX_MAC_SEM_SEPARADOR)
    pares = texto.scan(/../)                      # divide em pares de 2
  elsif (m = texto.match(REGEX_MAC_COM_SEPARADOR))
    pares = m.captures
  else
    return nil   # não corresponde a nenhum dos 3 formatos aceites
  end

  pares.map(&:upcase).join(":")
end

# ==========================================================
# PROGRAMA PRINCIPAL
# ==========================================================

caminho_origem = ARGV[0] || CAMINHO_LOG_ORIGINAL
caminho_destino = ARGV[1] || CAMINHO_LOG_NORMALIZADO

unless File.exist?(caminho_origem)
  puts "ERRO: não encontrei o ficheiro '#{caminho_origem}'."
  puts "Uso: ruby normalizar_log.rb [log_origem] [log_destino]"
  exit 1
end

puts "=========================================="
puts " Normalização de log (T1)"
puts " Origem:  #{caminho_origem}"
puts " Destino: #{caminho_destino}"
puts "=========================================="
puts

total_linhas       = 0
linhas_dados       = 0
linhas_copiadas    = 0
datas_normalizadas = 0
datas_invalidas    = 0
macs_normalizados  = 0
macs_invalidos     = 0

File.open(caminho_destino, "w") do |saida|
  File.foreach(caminho_origem, encoding: "bom|utf-8") do |linha|
    total_linhas += 1
    linha_sem_fim = linha.chomp

    campos = linha_sem_fim.split(",", -1)   # -1: mantém campos vazios no fim

    # Uma linha de dados tem campos suficientes E começa por um número (o ID
    # do evento). Isto evita confundir, por exemplo, a linha de cabeçalho
    # "ID,Date,Time,..." com uma linha de dados a sério.
    if campos.length < MIN_CAMPOS_LINHA_DE_DADOS || !campos[0].match?(/\A\d+\z/)
      # Não parece uma linha de dados (cabeçalho, linha em branco, etc.):
      # copiar tal como está, sem tentar normalizar.
      saida.puts linha_sem_fim
      linhas_copiadas += 1
      next
    end

    linhas_dados += 1

    # --- Data ---
    data_original = campos[IDX_DATA]
    data_normalizada = normalizar_data(data_original)
    if data_normalizada
      campos[IDX_DATA] = data_normalizada
      datas_normalizadas += 1
    elsif data_original.to_s.strip.empty?
      # Campo vazio: não é um erro, só não há nada para normalizar.
    else
      datas_invalidas += 1
      warn "Aviso (linha #{total_linhas}): data '#{data_original}' não reconhecida; mantida como estava."
    end

    # --- MAC ---
    mac_original = campos[IDX_MAC]
    mac_normalizado = normalizar_mac(mac_original)
    if mac_normalizado
      campos[IDX_MAC] = mac_normalizado
      macs_normalizados += 1
    elsif mac_original.to_s.strip.empty?
      # Campo vazio: não é um erro.
    else
      macs_invalidos += 1
      warn "Aviso (linha #{total_linhas}): MAC '#{mac_original}' não reconhecido; mantido como estava."
    end

    saida.puts campos.join(",")
  end
end

puts "Linhas lidas:                #{total_linhas}"
puts "Linhas de dados processadas: #{linhas_dados}"
puts "Linhas copiadas sem alterar: #{linhas_copiadas}"
puts
puts "Datas normalizadas:  #{datas_normalizadas}"
puts "Datas não reconhecidas (mantidas como estavam): #{datas_invalidas}"
puts "MACs normalizados:   #{macs_normalizados}"
puts "MACs não reconhecidos (mantidos como estavam):  #{macs_invalidos}"
puts
puts "=========================================="
puts " Log normalizado gravado em: #{caminho_destino}"
puts "=========================================="
