#!/usr/bin/env ruby
# frozen_string_literal: true

# ==========================================================
# COMPARAÇÃO DE LOGS COM DISTÂNCIA DE LEVENSHTEIN (T3)
# ==========================================================
#
# Objetivo: comparar dois ficheiros (por omissão, "log1.log" e "log2.log",
# o resultado do T1) linha a linha, e para cada par de linhas diferentes,
# calcular a distância de Levenshtein — o número mínimo de inserções,
# remoções ou substituições de caráteres para transformar uma linha na
# outra. Quanto menor a distância, mais parecidas são as duas linhas.
#
# INSTALAÇÃO DA GEM
# ------------------
#   gem install text
#
# A gem "text" (https://github.com/threedaymonk/text) é a implementação
# mais conhecida em Ruby deste algoritmo, entre várias gems possíveis.
# Fornece Text::Levenshtein.distance(a, b).
#
# USO
# ---
#   ruby comparar_logs.rb
#   ruby comparar_logs.rb log1.log log2.log
#   ruby comparar_logs.rb ficheiro_a.log ficheiro_b.log
# ==========================================================

begin
  require "text"
rescue LoadError
  warn "ERRO: a gem 'text' não está instalada."
  warn "      Instala com: gem install text"
  exit 1
end

# ----------------------------------------------------------
# CONFIGURAÇÃO
# ----------------------------------------------------------

CAMINHO_LOG_A_PADRAO = "log1.log"
CAMINHO_LOG_B_PADRAO = "log2.log"

# ----------------------------------------------------------
# PROGRAMA PRINCIPAL
# ----------------------------------------------------------

caminho_a = ARGV[0] || CAMINHO_LOG_A_PADRAO
caminho_b = ARGV[1] || CAMINHO_LOG_B_PADRAO

[caminho_a, caminho_b].each do |caminho|
  unless File.exist?(caminho)
    puts "ERRO: não encontrei o ficheiro '#{caminho}'."
    puts "Uso: ruby comparar_logs.rb [ficheiro_a] [ficheiro_b]"
    exit 1
  end
end

# chomp: true tira o \n (e o \r, se vier do Windows) do fim de cada linha,
# para a comparação não falhar só por causa da quebra de linha.
linhas_a = File.readlines(caminho_a, chomp: true)
linhas_b = File.readlines(caminho_b, chomp: true)

puts "=========================================="
puts " Comparação de ficheiros (Levenshtein)"
puts " Ficheiro A: #{caminho_a} (#{linhas_a.length} linhas)"
puts " Ficheiro B: #{caminho_b} (#{linhas_b.length} linhas)"
puts "=========================================="
puts

# Percorremos até ao maior dos dois ficheiros, para não deixar de fora
# linhas a mais que só existam num deles.
total_linhas  = [linhas_a.length, linhas_b.length].max
diferencas    = []   # { linha:, texto_a:, texto_b:, distancia: }
distancia_total = 0

(0...total_linhas).each do |indice|
  numero_linha = indice + 1
  texto_a = linhas_a[indice]
  texto_b = linhas_b[indice]

  if texto_a.nil?
    # Esta linha só existe no ficheiro B (B é mais comprido).
    distancia = texto_b.length
    diferencas << { linha: numero_linha, texto_a: nil, texto_b: texto_b, distancia: distancia }
    distancia_total += distancia

  elsif texto_b.nil?
    # Esta linha só existe no ficheiro A (A é mais comprido).
    distancia = texto_a.length
    diferencas << { linha: numero_linha, texto_a: texto_a, texto_b: nil, distancia: distancia }
    distancia_total += distancia

  elsif texto_a != texto_b
    distancia = Text::Levenshtein.distance(texto_a, texto_b)
    diferencas << { linha: numero_linha, texto_a: texto_a, texto_b: texto_b, distancia: distancia }
    distancia_total += distancia
  end
  # Se texto_a == texto_b, a linha é igual: distância 0, nada a registar.
end

ficheiros_iguais = diferencas.empty?

if ficheiros_iguais
  puts "Os ficheiros são EXATAMENTE IGUAIS, linha a linha."
else
  puts "Os ficheiros são DIFERENTES."
  puts "Linhas diferentes: #{diferencas.length} (de #{total_linhas} no total)"
  puts

  diferencas.each do |d|
    puts "-- Linha #{d[:linha]} " + ("-" * 40)
    puts "  A: #{d[:texto_a].nil? ? '(linha não existe neste ficheiro)' : d[:texto_a]}"
    puts "  B: #{d[:texto_b].nil? ? '(linha não existe neste ficheiro)' : d[:texto_b]}"
    puts "  Distância de Levenshtein: #{d[:distancia]}"
    puts
  end
end

puts "=========================================="
puts " RESUMO"
puts "=========================================="
puts "Ficheiros iguais: #{ficheiros_iguais ? 'Sim' : 'Não'}"
puts "Linhas comparadas: #{total_linhas}"
puts "Linhas diferentes: #{diferencas.length}"
puts "Distância total entre os ficheiros: #{distancia_total}"
puts "=========================================="
