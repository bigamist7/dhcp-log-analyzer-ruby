# ==========================================
# ANÁLISE DE RECONEXÕES DHCP (Logs Microsoft DHCP)
# ==========================================
#
# Objetivo:
#   Ler um log de atividade DHCP (formato Microsoft) e, para cada IP
#   com eventos de "Renew" (ID 11):
#     1) Calcular o tempo decorrido entre reconexões sucessivas do mesmo IP.
#     2) Assinalar como SUSPEITAS as reconexões com menos de 1 minuto
#        de intervalo (possível sintoma de spoofing, flapping ou ataque).
#     3) Assinalar como SUSPEITOS os IPs fora da rede interna (192.168.x.x),
#        distinguindo o tipo: IPs públicos (localizados via API, com cache),
#        IPs privados de outras redes (10.x, 172.16-31.x), endereços APIPA
#        (169.254.x.x), loopback, gamas reservadas para documentação e
#        IPs com formato inválido.
#     4) Detetar MACs partilhados por vários IPs, e IPs usados por vários
#        hostnames ou por vários MACs (possível spoofing ou sequestro de IP).
#     5) Detetar linhas com hora anterior à ocorrência anterior do mesmo IP
#        (relógio dessincronizado ou log adulterado).
#     6) Detetar possível "beaconing": vários intervalos curtos e quase
#        iguais seguidos (ex.: reconexões de 65 em 65 segundos).
#     7) Detetar possível esgotamento do pool DHCP (starvation): rajada de
#        atribuições de IP (ID 10) em poucos segundos, e eventos de pool
#        esgotado (ID 14).
#     8) Assinalar IPs que constem de uma blacklist, lida do ficheiro
#        "ipnegras.txt" (um IP ou gama CIDR por linha) para um Set.
#     9) Gravar um resumo só com as anomalias (ficheiro "anomalias.txt"),
#        sem o detalhe das renovações normais.
#    10) Detetar acessos fora do horário de funcionamento definido
#        (HORA_INICIO_EXPEDIENTE a HORA_FIM_EXPEDIENTE).
#    11) Assinalar IPs públicos de países a vigiar (Rússia, China),
#        além do motivo genérico de "IP público".
#
#   Leitura flexível do log: o script não depende de colunas fixas. Cada campo
#   da linha (data, hora, IP, MAC, hostname, descrição do evento) é reconhecido
#   por expressões regulares, pelo seu aspeto, e não pela posição. Funciona
#   assim com logs em que os campos vêm por outra ordem, com separadores
#   diferentes (vírgula, ponto e vírgula, tabulação ou espaços), com várias
#   formas de escrever a data (2024-02-20, 20/02/2024, 02/20/24, ...) e com
#   MACs com ou sem separadores (ver "LEITURA FLEXÍVEL DE UMA LINHA DO LOG").
#
#   Por omissão, o ecrã também não mostra o detalhe de cada renovação (só a
#   primeira ocorrência de cada IP e o resumo final) — ver MOSTRAR_DETALHE_RENOVACOES.
#
#   No fim, mostra um resumo com todos os IPs encontrados, indicando
#   quais são normais e quais levantam suspeitas.
#
# Autor: João Casanova Pinto
# ==========================================

require "time"
require "set"        # (desnecessário no Ruby 4.0, onde o Set já é nativo, mas inofensivo)
require "net/http"   # para fazer o pedido à API de localização
require "json"       # para ler a resposta da API e gravar a cache
require "ipaddr"     # para saber se um IP é privado

puts "=========================================="
puts " Análise das reconexões dos equipamentos"
puts " (Tempo entre reconexões - eventos Renew)"
puts "=========================================="
puts

# ==========================================
# CAMINHO DO FICHEIRO DE LOG
# ==========================================
#
# Podes correr o script de duas formas:
#
#   1) Sem argumentos -> usa o caminho definido em CAMINHO_LOG abaixo.
#        ruby dif_temps.rb
#
#   2) Passando o caminho do ficheiro como argumento na linha de comandos
#      (útil para testares vários logs sem editar o script):
#        ruby dif_temps.rb Logs_Teste_2.log
#
# Nota: em Ruby, no Windows, é mais seguro usar barras normais "/"
# em vez de barras invertidas "\", para não teres de as duplicar.

CAMINHO_LOG = File.join(File.dirname(File.expand_path(__FILE__)), "Logs_Teste_2.log")

# Em logs reais, com milhares de linhas, o detalhe de CADA renovação
# (Anterior/Atual/Diferença, um bloco por cada linha Renew) torna o ecrã
# enorme e difícil de ler. Por omissão, mostramos só o essencial: a primeira
# ocorrência de cada IP e o resumo final. Muda para "true" se precisares de
# ver o detalhe linha a linha (por exemplo, para depurar um caso específico).
MOSTRAR_DETALHE_RENOVACOES = false

# ==========================================
# HORÁRIO DE FUNCIONAMENTO
# ==========================================
#
# Fora deste intervalo (em horas, formato 24h), uma renovação é considerada
# fora de horas — por exemplo, um equipamento a "falar" com o servidor a
# meio da noite, quando ninguém devia lá estar.
# HORA_INICIO_EXPEDIENTE incluída, HORA_FIM_EXPEDIENTE excluída: com os
# valores por omissão, das 08:00 às 19:59 é expediente; a partir das 20:00
# (inclusive) já não é.

HORA_INICIO_EXPEDIENTE = 8
HORA_FIM_EXPEDIENTE    = 20

def fora_do_horario?(data_hora)
  data_hora.hour < HORA_INICIO_EXPEDIENTE || data_hora.hour >= HORA_FIM_EXPEDIENTE
end

caminho_ficheiro = ARGV[0] || CAMINHO_LOG

unless File.exist?(caminho_ficheiro)
  puts "ERRO: não encontrei o ficheiro '#{caminho_ficheiro}'."
  puts "Verifica o caminho ou indica-o como argumento ao correr o script."
  exit 1
end

# ==========================================
# LOCALIZAÇÃO DE IPs (com cache)
# ==========================================
#
# Cada IP externo é consultado na API UMA ÚNICA VEZ. O resultado fica
# guardado em "cache_ips.json" (na mesma pasta do script), e nas execuções
# seguintes (mesmo com logs diferentes) o IP é lido da cache, sem novo pedido.
#
# Nota: a API gratuita ip-api.com tem um limite de pedidos por minuto
# (na altura em que escrevi isto, cerca de 45). Confirma os limites atuais
# na documentação da API. A pausa abaixo evita ultrapassá-lo.

FICHEIRO_CACHE      = File.join(File.dirname(File.expand_path(__FILE__)), "cache_ips.json")
PAUSA_ENTRE_PEDIDOS = 1.5   # segundos de espera após cada pedido real à API
TIMEOUT_API         = 5     # tempo MÁXIMO de espera (segundos) por cada pedido à API
URL_API             = "http://ip-api.com/json/"

# Países para os quais queremos um alerta específico, além do motivo genérico
# "IP público". Usa o código de país ISO de 2 letras (o que a API devolve em
# "countryCode").
PAISES_SUSPEITOS = %w[RU CN].freeze
NOMES_PAISES_SUSPEITOS = { "RU" => "Rússia", "CN" => "China" }.freeze

# Sobre o TIMEOUT_API: não é "tentar ligar durante 5 segundos". É o tempo
# máximo que esperamos por UM pedido (para ligar e para receber a resposta).
# Sem isto o Ruby espera 60 s por omissão, e com a API inacessível o script
# ficava minutos parado, um IP de cada vez.

# Carregar a cache existente (se o ficheiro não existir ou estiver
# corrompido, começamos com uma cache vazia).
cache_localizacao =
  begin
    File.exist?(FICHEIRO_CACHE) ? JSON.parse(File.read(FICHEIRO_CACHE)) : {}
  rescue JSON::ParserError
    {}
  end

# Devolve um Hash { "texto" => ..., "codigo" => ... } com a localização do IP
# e o código de país (ISO 2 letras, ex.: "RU"), usado no alerta de país.
#   - Se o IP já estiver na cache, no formato novo -> devolve logo, SEM
#     consultar a API.
#   - Se estiver numa cache ANTIGA (só tinha o texto, sem código de país) ->
#     não chega para o alerta de país; consultamos mais uma vez, e a cache
#     fica atualizada com o código a partir daí.
#   - Se for um IP privado -> não consulta (não tem localização pública).
#   - Caso contrário -> consulta a API, guarda na cache e devolve.
def localizar_ip(ip, cache)
  return cache[ip] if cache.key?(ip) && cache[ip].is_a?(Hash)

  begin
    return { "texto" => "rede privada (sem consulta)", "codigo" => nil } if IPAddr.new(ip).private?

    url = URI("#{URL_API}#{ip}?fields=status,message,country,countryCode,city,isp")

    # Pedido com tempo limite: open_timeout = tempo para estabelecer a ligação,
    # read_timeout = tempo para receber a resposta.
    # max_retries = 0: por omissão o Net::HTTP repete UMA vez um GET que deu
    # timeout, o que duplicava a espera (5 s virava 10 s).
    http = Net::HTTP.new(url.host, url.port)
    http.open_timeout = TIMEOUT_API
    http.read_timeout = TIMEOUT_API
    http.max_retries  = 0
    resposta = http.get(url.request_uri)
    dados = JSON.parse(resposta.body)

    if dados["status"] == "success"
      resultado = {
        "texto"  => "#{dados['city']}, #{dados['country']} (#{dados['isp']})",
        "codigo" => dados["countryCode"]
      }
    else
      # A API respondeu, mas sem localização (ex.: IP reservado).
      # Guardamos na cache porque a resposta não vai mudar.
      resultado = { "texto" => "sem localização (#{dados['message']})", "codigo" => nil }
    end

    cache[ip] = resultado
    sleep PAUSA_ENTRE_PEDIDOS   # respeitar o limite de pedidos da API
    resultado

  rescue IPAddr::InvalidAddressError
    # O texto parece um IP mas não é válido (ex.: 999.999.999.999).
    { "texto" => "IP inválido (não consultado)", "codigo" => nil }

  rescue Net::OpenTimeout, Net::ReadTimeout
    # A API não respondeu a tempo. NÃO guardamos na cache: fica para a
    # próxima execução.
    { "texto" => "sem resposta da API em #{TIMEOUT_API} s (timeout)", "codigo" => nil }

  rescue StandardError => e
    # Falha de rede, limite excedido, etc. NÃO guardamos na cache,
    # para o IP ser consultado outra vez na próxima execução.
    { "texto" => "erro na consulta (#{e.class})", "codigo" => nil }
  end
end

# ==========================================
# LEITURA FLEXÍVEL DE UMA LINHA DO LOG
# ==========================================
#
# O script NÃO depende de colunas fixas nem da ordem dos campos. Cada linha
# é partida em campos (separados por vírgula, ponto e vírgula ou tabulação;
# se não houver nenhum destes, por espaços) e CADA campo é reconhecido pelo
# seu aspeto, com expressões regulares:
#
#   - data     -> 2024-02-20, 20/02/2024, 02/20/24, 20.02.2024, ...
#   - hora     -> 08:05:11 (ou 08:05)
#   - IP       -> 4 números separados por pontos
#   - MAC      -> 12 hexadecimais, com ou sem separadores (: ou -)
#   - hostname -> texto com letras que não seja nenhum dos anteriores
#   - evento   -> reconhecido pela descrição (Renew, Assign, Pool Exhausted)
#                 ou, em alternativa, pelo ID no início da linha (11, 10, 14)
#
# Assim funciona com logs em que as colunas vêm por outra ordem.

# Datas: ano primeiro (2024-02-20) ou ano no fim (20/02/2024, 02/20/24).
DATA_ANO_PRIMEIRO = /\A(\d{4})[\/.\-](\d{1,2})[\/.\-](\d{1,2})\z/
DATA_ANO_ULTIMO   = /\A(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{4}|\d{2})\z/

# Hora: HH:MM:SS (os segundos são opcionais).
HORA_CAMPO = /\A(\d{1,2}):(\d{2})(?::(\d{2}))?\z/

# Qualquer endereço IPv4 (não só 192.x.x.x, para conseguirmos apanhar
# também IPs estrangeiros/estranhos que apareçam no log).
IP_CAMPO = /\A\d{1,3}(?:\.\d{1,3}){3}\z/

# MAC: 12 hexadecimais seguidos (080027ECA6CE) ou 6 pares separados por
# ":" ou "-" (08:00:27:EC:A6:CE, 08-00-27-EC-A6-CE). Maiúsculas ou minúsculas.
MAC_CAMPO = /\A(?:[0-9A-Fa-f]{12}|[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5})\z/

# Hostname: começa por letra ou número e só tem letras, números, "_", "." e "-".
# Exige pelo menos uma letra (para não confundir com números) e não pode ser
# um valor hexadecimal tipo "0x4D5346..." (campo de classe do fabricante).
HOSTNAME_CAMPO = /\A[A-Za-z0-9][A-Za-z0-9_.\-]*\z/

# Descrição do evento (procurada na linha toda, por palavras inteiras):
#   Renew          -> renovação de concessão (ID 11)
#   Assign         -> novo IP atribuído a um cliente (ID 10)
#   Pool Exhausted -> pool de endereços esgotado (ID 14)
EVENTO_POOL   = /pool\s*exhaust|exhausted|esgotad/i
EVENTO_ATRIB  = /\b(?:assign|atribu)/i
EVENTO_RENEW  = /\b(?:renew\b|renov)/i

# Se a linha não tiver descrição reconhecível, usamos o ID no início da linha.
ID_NO_INICIO = /\A\s*(10|11|14),/
TIPO_POR_ID  = { "10" => :atribuicao, "11" => :renovacao, "14" => :pool }.freeze

# Converte o texto de uma data em [ano, mês, dia], ou nil se não parecer data.
# Quando os dois primeiros números são ambíguos (ambos <= 12), assume-se
# MÊS primeiro (é o formato do log DHCP da Microsoft: mm/dd/aa).
# Se o primeiro for > 12, só pode ser o dia.
def interpretar_data(texto)
  if (m = texto.match(DATA_ANO_PRIMEIRO))
    [m[1].to_i, m[2].to_i, m[3].to_i]
  elsif (m = texto.match(DATA_ANO_ULTIMO))
    a, b, ano = m[1].to_i, m[2].to_i, m[3].to_i
    ano += (ano < 70 ? 2000 : 1900) if m[3].length == 2
    a > 12 ? [ano, b, a] : [ano, a, b]
  end
end

# Lê UMA linha do log e devolve um hash com o que conseguiu reconhecer:
#   { tipo:, data_hora:, ip:, mac:, hostname: }
# Devolve nil se a linha não for um evento que nos interesse
# (Renew, Assign ou pool esgotado).
def extrair_evento(linha)
  tipo = if    linha =~ EVENTO_POOL  then :pool
         elsif linha =~ EVENTO_ATRIB then :atribuicao
         elsif linha =~ EVENTO_RENEW then :renovacao
         elsif (m = linha.match(ID_NO_INICIO)) then TIPO_POR_ID[m[1]]
         end
  return nil unless tipo

  separador = linha =~ /[,;\t]/ ? /[,;\t]/ : /\s+/
  data = hora = ip = mac = hostname = nil

  linha.split(separador).each do |bruto|
    campo = bruto.strip
    next if campo.empty?

    if (m = campo.match(/\A(\S+?)[ T](\d{1,2}:\d{2}(?::\d{2})?)\z/)) && interpretar_data(m[1])
      # data e hora juntas no mesmo campo (2024-02-20 08:05:11)
      data ||= interpretar_data(m[1])
      hora ||= m[2].match(HORA_CAMPO)
    elsif (d = interpretar_data(campo))
      data ||= d
    elsif campo =~ MAC_CAMPO
      mac ||= campo.delete(":-").upcase
    elsif (h = campo.match(HORA_CAMPO))
      hora ||= h
    elsif campo =~ IP_CAMPO
      ip ||= campo
    elsif campo =~ EVENTO_POOL || campo =~ EVENTO_ATRIB || campo =~ EVENTO_RENEW
      next   # é a descrição do evento, não um hostname
    elsif hostname.nil? && campo =~ HOSTNAME_CAMPO && campo =~ /[A-Za-z]/ && campo !~ /\A0x/i
      hostname = campo
    end
  end

  # Juntar data + hora num objeto Time (assim podemos subtrair datas).
  # Se a data for impossível (ex.: mês 99), fica nil e a linha é ignorada.
  data_hora = nil
  if data && hora
    begin
      data_hora = Time.local(data[0], data[1], data[2],
                             hora[1].to_i, hora[2].to_i, hora[3].to_i)
    rescue ArgumentError
      data_hora = nil
    end
  end

  { tipo: tipo, data_hora: data_hora, ip: ip, mac: mac, hostname: hostname }
end

# ==========================================
# CLASSIFICAÇÃO DOS IPs
# ==========================================
#
# Cada IP é classificado num destes tipos:
#   :interno  -> 192.168.x.x (a rede da empresa; considerado normal)
#   :especial -> privado de outra rede, APIPA, loopback ou gama reservada
#                (não faz sentido consultar a API de localização)
#   :externo  -> IP público (é localizado através da API, com cache)
#   :invalido -> texto que parece um IP mas não é válido (ex.: 999.1.1.1)

REDE_INTERNA = IPAddr.new("192.168.0.0/16")

# Cada entrada: [descrição que aparece no resumo, lista de faixas de IPs]
FAIXAS_ESPECIAIS = [
  ["IP privado de outra rede (fora de 192.168.x.x)",
   [IPAddr.new("10.0.0.0/8"), IPAddr.new("172.16.0.0/12")]],
  ["endereço APIPA 169.254.x.x (cliente sem resposta do DHCP)",
   [IPAddr.new("169.254.0.0/16")]],
  ["endereço de loopback 127.x.x.x",
   [IPAddr.new("127.0.0.0/8")]],
  ["IP de gama reservada para documentação (não é um IP real)",
   [IPAddr.new("192.0.2.0/24"), IPAddr.new("198.51.100.0/24"), IPAddr.new("203.0.113.0/24")]]
].freeze

# Devolve [tipo, descrição]. A descrição só existe para o tipo :especial.
def classificar_ip(ip)
  endereco = IPAddr.new(ip)
  return [:interno, nil] if REDE_INTERNA.include?(endereco)

  FAIXAS_ESPECIAIS.each do |descricao, faixas|
    return [:especial, descricao] if faixas.any? { |faixa| faixa.include?(endereco) }
  end

  [:externo, nil]
rescue IPAddr::InvalidAddressError
  [:invalido, nil]
end

# ==========================================
# BLACKLIST DE IPs (lida de um ficheiro)
# ==========================================
#
# A lista de IPs proibidos fica num ficheiro de texto, "ipnegras.txt" (na
# mesma pasta do script), e não dentro do código. Assim, muda-se a lista sem
# mexer no script. Formato do ficheiro:
#   - um IP ou uma gama CIDR por linha (ex.: 34.192.125.239  ou  45.33.32.0/24);
#   - linhas em branco são ignoradas;
#   - tudo o que vem depois de "#" é comentário.
#
# Os IPs isolados são guardados num SET e as gamas CIDR num ARRAY à parte:
#   - Set: não tem repetidos e a pesquisa com include? é muito rápida
#     (é uma tabela de hash), mesmo com listas grandes;
#   - Array de IPAddr: uma gama (ex.: 45.33.32.0/24) não se procura com
#     include? de texto, porque é preciso ver se o IP "cabe" dentro da gama.

FICHEIRO_BLACKLIST = File.join(File.dirname(File.expand_path(__FILE__)), "ipnegras.txt")

# Ficheiro onde fica guardado, no fim de cada execução, um resumo SÓ com os
# IPs suspeitos e os respetivos motivos (sem o detalhe das renovações nem os
# IPs normais). É reescrito a cada execução, refletindo sempre a última
# análise feita.
FICHEIRO_ANOMALIAS = File.join(File.dirname(File.expand_path(__FILE__)), "anomalias.txt")

# Lê o ficheiro e devolve:
#   [Set de IPs isolados, array de gamas CIDR, linhas inválidas, ficheiro existe?]
def carregar_blacklist(caminho)
  ips_exatos = Set.new   # IPs isolados
  gamas      = []        # gamas CIDR (IPAddr)
  invalidas  = []        # linhas que não são IPs válidos

  return [ips_exatos, gamas, invalidas, false] unless File.exist?(caminho)

  # "bom|utf-8" ignora o BOM que alguns editores do Windows acrescentam
  File.foreach(caminho, encoding: "bom|utf-8").with_index(1) do |linha, numero|
    texto = linha.sub(/#.*/, "").strip   # tira o comentário e os espaços
    next if texto.empty?

    begin
      entrada = IPAddr.new(texto)        # valida o IP ou a gama CIDR
      if texto.include?("/")
        gamas << entrada
      else
        ips_exatos << entrada.to_s       # forma normalizada do IP
      end
    rescue ArgumentError
      invalidas << "linha #{numero}: #{texto}"
    end
  end

  [ips_exatos, gamas, invalidas, true]
end

# Devolve nil se o IP não estiver na blacklist, ou o texto do motivo:
#   1) primeiro procura o IP no Set (rápido);
#   2) só se não estiver lá, vê se cai dentro de alguma gama CIDR.
def verificar_blacklist(ip, ips_exatos, gamas)
  return "IP na BLACKLIST" if ips_exatos.include?(ip)

  endereco = IPAddr.new(ip)
  gama = gamas.find { |g| g.include?(endereco) }
  return nil unless gama

  gama.prefix == 32 ? "IP na BLACKLIST" : "IP na BLACKLIST (gama #{gama}/#{gama.prefix})"
rescue ArgumentError
  nil   # IP com formato inválido: não pode estar na blacklist
end

# ==========================================
# DETEÇÃO DE BEACONING (intervalos regulares e curtos)
# ==========================================
#
# "Beaconing" = um equipamento que contacta o servidor a intervalos quase
# idênticos e curtos (ex.: de 65 em 65 segundos), como faz malware a "dar
# sinal" a um servidor de comando e controlo. Uma renovação DHCP normal é
# regular mas LENTA (horas), por isso só consideramos intervalos curtos.
#
# Um IP é assinalado quando tem, seguidos, pelo menos MIN_INTERVALOS_REGULARES
# intervalos que diferem entre si no máximo TOLERANCIA_BEACON segundos
# e que são todos inferiores a INTERVALO_MAXIMO_BEACON segundos.

MIN_INTERVALOS_REGULARES = 5     # nº mínimo de intervalos seguidos "iguais"
TOLERANCIA_BEACON        = 5     # diferença máxima (segundos) entre intervalos
INTERVALO_MAXIMO_BEACON  = 600   # só intervalos abaixo de 10 minutos contam

# Recebe a lista de intervalos (em segundos) de um IP e devolve a MAIOR
# sequência de intervalos regulares: { tamanho: N, intervalo: S }.
# Cada intervalo é comparado com o PRIMEIRO da sequência em curso.
def maior_sequencia_regular(intervalos, tolerancia, maximo)
  melhor        = { tamanho: 0, intervalo: nil }
  referencia    = nil   # primeiro intervalo da sequência em curso
  tamanho_atual = 0

  intervalos.each do |intervalo|
    if referencia && intervalo <= maximo && (intervalo - referencia).abs <= tolerancia
      # Continua a sequência atual
      tamanho_atual += 1
    elsif intervalo <= maximo
      # Começa uma nova sequência neste intervalo
      referencia    = intervalo
      tamanho_atual = 1
    else
      # Intervalo demasiado longo: interrompe qualquer sequência
      referencia    = nil
      tamanho_atual = 0
    end

    if tamanho_atual > melhor[:tamanho]
      melhor = { tamanho: tamanho_atual, intervalo: referencia }
    end
  end

  melhor
end

# ==========================================
# DETEÇÃO DE ESGOTAMENTO DO POOL DHCP (starvation)
# ==========================================
#
# Num ataque de "DHCP starvation", o atacante pede IPs em massa (normalmente
# com MACs falsos e diferentes em cada pedido) até o pool ficar sem endereços
# livres; a partir daí, os clientes legítimos deixam de conseguir IP.
#
# Sinais no log:
#   - uma RAJADA de atribuições (ID 10) em poucos segundos;
#   - eventos de pool esgotado (ID 14) logo a seguir.
#
# Uma "rajada" é uma sequência de atribuições em que cada uma acontece, no
# máximo, INTERVALO_MAX_ENTRE_ATRIBUICOES segundos depois da anterior, com pelo
# menos MIN_ATRIBUICOES_RAJADA atribuições. Nota: um arranque em massa de
# equipamentos legítimos (ex.: sala de aulas a ligar) também pode parecer uma
# rajada; por isso convém confirmar com os eventos ID 14 e com os MACs.

MIN_ATRIBUICOES_RAJADA          = 10   # nº mínimo de atribuições numa rajada
INTERVALO_MAX_ENTRE_ATRIBUICOES = 5    # segundos entre atribuições seguidas
JANELA_POOL_ESGOTADO            = 60   # segundos após a rajada em que um ID 14 conta como "associado"

# Recebe a lista de atribuições ({ hora:, ip:, mac: }) e devolve as rajadas
# encontradas: [{ inicio:, fim:, total:, macs: }, ...]
def detetar_rajadas_atribuicoes(atribuicoes, intervalo_max, minimo)
  ordenadas = atribuicoes.sort_by { |a| a[:hora] }

  # 1) Agrupar atribuições seguidas (intervalo curto entre cada uma e a anterior)
  grupos = []
  atual  = []
  ordenadas.each do |a|
    if atual.empty? || (a[:hora] - atual.last[:hora]) <= intervalo_max
      atual << a
    else
      grupos << atual
      atual = [a]
    end
  end
  grupos << atual unless atual.empty?

  # 2) Ficar só com os grupos suficientemente grandes
  grupos.select { |g| g.length >= minimo }.map do |g|
    { inicio: g.first[:hora],
      fim:    g.last[:hora],
      total:  g.length,
      macs:   g.map { |a| a[:mac] }.compact.uniq.length }
  end
end

# ==========================================
# ESTRUTURAS DE DADOS (HASHES)
# ==========================================

# Guarda a última data/hora vista para cada IP.
ultima_ocorrencia = {}

# Guarda o MAC associado a cada IP (última vez que foi visto).
mac_por_ip = {}

# Guarda, para cada IP, o conjunto de MACs distintos que o usaram.
# Um IP que aparece com MACs diferentes é suspeito: pode ser sequestro de IP
# (outro equipamento a ficar com o IP de alguém) ou log forjado.
macs_por_ip = {}

# Guarda, para cada MAC, o conjunto de IPs distintos onde apareceu.
# Um MAC físico real não deve aparecer associado a vários IPs diferentes
# (ainda para mais em redes/países diferentes) — se acontecer, é um forte
# indício de spoofing de MAC.
ips_por_mac = {}

# Guarda, para cada IP, o conjunto de hostnames distintos que o usaram.
# Um IP que aparece com nomes de equipamento diferentes (ex.: PCSofia e
# PCarlos) é suspeito: pode ser spoofing, roubo de lease ou log forjado.
hostnames_por_ip = {}

# Guarda quantas reconexões < 1 minuto cada IP teve.
ips_suspeitos_tempo = {}

# Guarda quantas vezes cada IP apareceu com uma hora ANTERIOR à ocorrência
# anterior (hora a andar para trás -> relógio dessincronizado ou log adulterado).
ips_hora_recuada = {}

# Guarda quantas vezes cada IP teve um acesso fora do horário de funcionamento.
ips_fora_horario = {}

# Guarda, para cada IP, a lista (por ordem) dos intervalos em segundos entre
# ocorrências sucessivas. Serve para detetar beaconing (intervalos regulares).
intervalos_por_ip = {}

# Atribuições de IP (ID 10) lidas do log: [{ hora:, ip:, mac: }, ...]
atribuicoes = []

# Horas dos eventos de pool esgotado (ID 14).
pool_esgotado = []

# Guarda a classificação dos IPs que NÃO são da rede interna:
#   ip => [tipo, descrição]   (ver "CLASSIFICAÇÃO DOS IPs" acima)
classificacao_ip = {}

# Carregar a blacklist do ficheiro (ver "BLACKLIST DE IPs"): um Set com os IPs
# isolados e um array com as gamas CIDR.
blacklist_ips, blacklist_gamas, blacklist_invalidas, blacklist_existe = carregar_blacklist(FICHEIRO_BLACKLIST)

if blacklist_existe
  puts "Blacklist: #{blacklist_ips.length} IP(s) e #{blacklist_gamas.length} gama(s) carregado(s) de #{File.basename(FICHEIRO_BLACKLIST)}"
  blacklist_invalidas.each { |i| puts "  Aviso: entrada inválida ignorada (#{i})" }
else
  puts "Blacklist: ficheiro '#{File.basename(FICHEIRO_BLACKLIST)}' não encontrado (a análise segue sem blacklist)."
end
puts

# ==========================================
# LER O FICHEIRO
# ==========================================

File.open(caminho_ficheiro, "r") do |f1|

  f1.each_line do |linha|

    # --------------------------------------
    # Ler a linha (qualquer ordem de campos) e reconhecer o tipo de evento
    # --------------------------------------
    evento = extrair_evento(linha)
    next unless evento   # linha que não é Renew, Assign nem pool esgotado

    # --------------------------------------
    # Eventos Assign (ID 10) e pool esgotado (ID 14)
    # --------------------------------------
    # Só servem para a deteção de esgotamento do pool. Guardamos e passamos
    # à linha seguinte: não entram na análise dos Renew.
    if evento[:tipo] == :atribuicao || evento[:tipo] == :pool
      if evento[:data_hora]
        if evento[:tipo] == :atribuicao
          atribuicoes << { hora: evento[:data_hora], ip: evento[:ip], mac: evento[:mac] }
        else
          pool_esgotado << evento[:data_hora]
        end
      end

      next
    end

    # --------------------------------------
    # Daqui para a frente só nos interessam linhas de "Renew" (ID 11)
    # --------------------------------------
    next unless evento[:tipo] == :renovacao

    # --------------------------------------
    # IP, MAC e hostname (reconhecidos pelo aspeto, não pela posição)
    # --------------------------------------
    ip = evento[:ip]
    next unless ip   # se não há IP na linha, ignoramos (linha incompleta/corrompida)

    # O MAC pode não existir em todas as linhas (fica nil = desconhecido).
    # Já vem normalizado: 12 hexadecimais, maiúsculas, sem separadores.
    mac = evento[:mac]
    mac_por_ip[ip] = mac if mac

    # Associar este IP ao MAC (usamos um Set para não contar duplicados),
    # nos dois sentidos: MAC -> IPs e IP -> MACs.
    if mac
      ips_por_mac[mac] ||= Set.new
      ips_por_mac[mac] << ip

      macs_por_ip[ip] ||= Set.new
      macs_por_ip[ip] << mac
    end

    hostname = evento[:hostname].to_s

    unless hostname.empty?
      hostnames_por_ip[ip] ||= Set.new
      hostnames_por_ip[ip] << hostname
    end

    # --------------------------------------
    # Classificar o IP (interno, especial, público ou inválido)
    # --------------------------------------
    tipo, descricao = classificar_ip(ip)
    classificacao_ip[ip] = [tipo, descricao] unless tipo == :interno

    # --------------------------------------
    # Data e hora (já convertidas para um objeto Time do Ruby)
    # --------------------------------------
    data_hora = evento[:data_hora]
    next unless data_hora   # sem data/hora válida, não há como comparar

    # ======================================
    # PRIMEIRA OCORRÊNCIA DESTE IP
    # ======================================
    unless ultima_ocorrencia.key?(ip)
      ultima_ocorrencia[ip] = data_hora

      if fora_do_horario?(data_hora)
        ips_fora_horario[ip] ||= 0
        ips_fora_horario[ip] += 1
      end

      aviso_horario = fora_do_horario?(data_hora) ? "  (fora do horário de funcionamento)" : ""
      puts "IP: #{ip} | MAC: #{mac}"
      puts "Primeira ocorrência: #{data_hora}#{aviso_horario}"
      puts
      next
    end

    # ======================================
    # IP JÁ TINHA APARECIDO ANTES -> calcular diferença
    # ======================================
    anterior = ultima_ocorrencia[ip]

    diferenca = (data_hora - anterior).to_i   # diferença em segundos (pode ser negativa)

    # Trabalhamos com o valor absoluto para o divmod dar horas/minutos/segundos
    # corretos, e mostramos o sinal "-" à parte quando a hora andou para trás.
    sinal = diferenca < 0 ? "-" : ""
    horas, resto = diferenca.abs.divmod(3600)
    minutos, segundos = resto.divmod(60)

    puts "IP: #{ip}" if MOSTRAR_DETALHE_RENOVACOES
    puts "MAC: #{mac}" if MOSTRAR_DETALHE_RENOVACOES
    puts "Anterior: #{anterior}" if MOSTRAR_DETALHE_RENOVACOES
    puts "Atual:    #{data_hora}" if MOSTRAR_DETALHE_RENOVACOES
    puts "Diferença: #{sinal}#{horas}h #{minutos}m #{segundos}s" if MOSTRAR_DETALHE_RENOVACOES

    # Guardar o intervalo (só se a hora não andou para trás) para a
    # deteção de beaconing no resumo final.
    intervalos_por_ip[ip] ||= []
    intervalos_por_ip[ip] << diferenca if diferenca >= 0

    if diferenca < 0
      # ======================================
      # HORA ANTERIOR À OCORRÊNCIA ANTERIOR -> suspeito
      # ======================================
      # Num log em ordem cronológica isto não devia acontecer: pode indicar
      # relógio dessincronizado ou linhas inseridas/adulteradas no log.
      if MOSTRAR_DETALHE_RENOVACOES
        puts
        puts "***** HORA ANTERIOR À OCORRÊNCIA ANTERIOR (relógio ou log adulterado?) *****"
        puts
      end

      ips_hora_recuada[ip] ||= 0
      ips_hora_recuada[ip] += 1

    elsif diferenca < 60
      # ======================================
      # RECONEXÃO INFERIOR A 1 MINUTO -> suspeito
      # ======================================
      if MOSTRAR_DETALHE_RENOVACOES
        puts
        puts "***** RECONEXÃO INFERIOR A 1 MINUTO *****"
        puts
      end

      ips_suspeitos_tempo[ip] ||= 0
      ips_suspeitos_tempo[ip] += 1
    end

    # ======================================
    # FORA DO HORÁRIO DE FUNCIONAMENTO -> suspeito
    # ======================================
    # Independente da reconexão ser rápida ou não: um acesso a meio da
    # noite é estranho mesmo que o intervalo para o anterior seja normal.
    if fora_do_horario?(data_hora)
      if MOSTRAR_DETALHE_RENOVACOES
        puts
        puts "***** FORA DO HORÁRIO DE FUNCIONAMENTO (#{HORA_INICIO_EXPEDIENTE}h-#{HORA_FIM_EXPEDIENTE}h) *****"
        puts
      end

      ips_fora_horario[ip] ||= 0
      ips_fora_horario[ip] += 1
    end

    # Atualizar a última ocorrência para a próxima comparação.
    # Se a hora andou para trás, mantemos a referência anterior (a mais
    # recente), para a linha anómala não distorcer as comparações seguintes.
    ultima_ocorrencia[ip] = data_hora if diferenca >= 0

  end

end

# ==========================================
# RESUMO FINAL
# ==========================================

puts
puts "=========================================="
puts " RESUMO DOS IPs"
puts "=========================================="
puts "IPs distintos encontrados: #{ultima_ocorrencia.length}"
puts

total_blacklist = 0   # nº de IPs do log que constam da blacklist

# Guarda { ip:, mac:, motivos:, localizacao: } de cada IP suspeito, pela
# ordem em que aparecem no resumo, para depois escrever no anomalias.txt.
anomalias = []

ultima_ocorrencia.each_key do |ip|

  mac = mac_por_ip[ip] || "desconhecido"

  motivos = []

  # Blacklist: o motivo mais grave, por isso aparece em primeiro lugar.
  motivo_bl = verificar_blacklist(ip, blacklist_ips, blacklist_gamas)
  if motivo_bl
    total_blacklist += 1
    motivos << motivo_bl
  end

  motivos << "#{ips_suspeitos_tempo[ip]} reconexões < 1 minuto" if ips_suspeitos_tempo.key?(ip)
  motivos << "#{ips_hora_recuada[ip]} linha(s) com hora anterior à ocorrência anterior (relógio/log adulterado?)" if ips_hora_recuada.key?(ip)
  motivos << "#{ips_fora_horario[ip]} acesso(s) fora do horário de funcionamento (#{HORA_INICIO_EXPEDIENTE}h-#{HORA_FIM_EXPEDIENTE}h)" if ips_fora_horario.key?(ip)

  # Beaconing: vários intervalos curtos e quase iguais, seguidos.
  sequencia = maior_sequencia_regular(intervalos_por_ip[ip] || [],
                                      TOLERANCIA_BEACON, INTERVALO_MAXIMO_BEACON)
  if sequencia[:tamanho] >= MIN_INTERVALOS_REGULARES
    motivos << "possível beaconing: #{sequencia[:tamanho]} intervalos seguidos de ~#{sequencia[:intervalo]} s"
  end

  # Motivo consoante o tipo de IP (nil, nil se for um IP interno normal).
  tipo, descricao = classificacao_ip[ip]

  # Só localizamos IPs públicos. Os restantes (internos, privados de outras
  # redes, APIPA, reservados...) não têm localização pública. Fazemos isto
  # antes de montar os motivos, para o alerta de país poder entrar na lista.
  localizacao = nil
  codigo_pais = nil
  if tipo == :externo
    info_loc    = localizar_ip(ip, cache_localizacao)
    localizacao = info_loc["texto"]
    codigo_pais = info_loc["codigo"]
  end

  case tipo
  when :externo  then motivos << "IP público (fora da rede interna 192.168.x.x)"
  when :especial then motivos << descricao
  when :invalido then motivos << "IP com formato inválido"
  end

  # País suspeito (Rússia, China): alerta específico, além do motivo "IP
  # público" acima — nem todo o IP público é de um país a vigiar.
  if PAISES_SUSPEITOS.include?(codigo_pais)
    nome_pais = NOMES_PAISES_SUSPEITOS[codigo_pais] || codigo_pais
    motivos << "país suspeito: #{nome_pais} (#{codigo_pais})"
  end

  # Se este MAC está associado a mais do que um IP, é suspeito de spoofing.
  if ips_por_mac.key?(mac) && ips_por_mac[mac].length > 1
    outros_ips = (ips_por_mac[mac].to_a - [ip]).join(", ")
    motivos << "MAC partilhado com outro(s) IP(s): #{outros_ips}"
  end

  # Se este IP foi usado por mais do que um hostname, é suspeito.
  if hostnames_por_ip.key?(ip) && hostnames_por_ip[ip].length > 1
    motivos << "vários hostnames no mesmo IP: #{hostnames_por_ip[ip].to_a.join(', ')}"
  end

  # Se este IP foi usado por mais do que um MAC, é suspeito (possível
  # sequestro de IP), mesmo que o hostname seja igual.
  if macs_por_ip.key?(ip) && macs_por_ip[ip].length > 1
    motivos << "vários MACs no mesmo IP: #{macs_por_ip[ip].to_a.join(', ')}"
  end

  if motivos.empty?
    puts "#{ip} (MAC: #{mac}) <-- normal"
  else
    puts "#{ip} (MAC: #{mac}) <-- SUSPEITO: #{motivos.join(' | ')}"
  end

  puts "    Localização: #{localizacao}" if localizacao

  anomalias << { ip: ip, mac: mac, motivos: motivos, localizacao: localizacao } unless motivos.empty?
end

puts
puts "IPs encontrados na blacklist: #{total_blacklist}"

# Gravar a cache em disco para as próximas execuções.
File.write(FICHEIRO_CACHE, JSON.pretty_generate(cache_localizacao))

# ==========================================
# ANÁLISE DE ESGOTAMENTO DO POOL DHCP
# ==========================================

puts
puts "=========================================="
puts " ESGOTAMENTO DO POOL DHCP (starvation)"
puts "=========================================="
puts "Atribuições de IP (ID 10) lidas:    #{atribuicoes.length}"
puts "Eventos de pool esgotado (ID 14):   #{pool_esgotado.length}"
puts

formato_hora = "%Y-%m-%d %H:%M:%S"

rajadas = detetar_rajadas_atribuicoes(atribuicoes,
                                      INTERVALO_MAX_ENTRE_ATRIBUICOES,
                                      MIN_ATRIBUICOES_RAJADA)

pool_associado = []   # eventos ID 14 ligados a alguma rajada
rajadas_texto  = []   # linhas das rajadas, para o anomalias.txt

if rajadas.empty?
  puts "Nenhuma rajada suspeita de atribuições."
else
  rajadas.each do |r|
    duracao = (r[:fim] - r[:inicio]).to_i

    # Eventos de pool esgotado durante a rajada ou logo a seguir
    associados = pool_esgotado.select do |h|
      h >= r[:inicio] && h <= r[:fim] + JANELA_POOL_ESGOTADO
    end
    pool_associado.concat(associados)

    linha1 = "SUSPEITO: rajada de #{r[:total]} atribuições em #{duracao} s " \
             "(#{r[:inicio].strftime(formato_hora)} até #{r[:fim].strftime(formato_hora)}), " \
             "#{r[:macs]} MACs distintos"
    puts linha1

    if associados.empty?
      linha2 = "    Sem eventos de pool esgotado associados (confirmar se é um arranque em massa legítimo)."
    else
      linha2 = "    Seguida de #{associados.length} evento(s) de pool esgotado: " \
               "#{associados.map { |h| h.strftime('%H:%M:%S') }.join(', ')}  <-- pool esgotado!"
    end
    puts linha2

    rajadas_texto << linha1
    rajadas_texto << linha2
  end
end

# Eventos de pool esgotado que não estão ligados a nenhuma rajada.
isolados = pool_esgotado - pool_associado
isolados_texto = nil
unless isolados.empty?
  puts
  isolados_texto = "Pool esgotado sem rajada associada: #{isolados.length} evento(s) às " \
                   "#{isolados.map { |h| h.strftime(formato_hora) }.join(', ')}"
  puts isolados_texto
  puts "    (pode ser falta real de endereços no scope, ou um ataque mais lento)"
end

puts
puts "=========================================="
puts " FIM DA ANÁLISE"
puts "=========================================="

# ==========================================
# GRAVAR O anomalias.txt
# ==========================================
#
# Ficheiro à parte, só com os IPs suspeitos e as rajadas de starvation (sem
# o detalhe das renovações normais nem os IPs sem suspeitas). É reescrito a
# cada execução: reflete sempre a última análise feita, não um histórico.

File.open(FICHEIRO_ANOMALIAS, "w") do |f|
  f.puts "=========================================="
  f.puts " ANOMALIAS DETETADAS"
  f.puts "=========================================="
  f.puts "Ficheiro analisado: #{caminho_ficheiro}"
  f.puts "Gerado em:          #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
  f.puts "IPs suspeitos:      #{anomalias.length} (de #{ultima_ocorrencia.length} IPs distintos)"
  f.puts "IPs na blacklist:   #{total_blacklist}"
  f.puts

  if anomalias.empty?
    f.puts "Nenhum IP suspeito encontrado."
  else
    anomalias.each do |a|
      f.puts "#{a[:ip]} (MAC: #{a[:mac]}) <-- SUSPEITO: #{a[:motivos].join(' | ')}"
      f.puts "    Localização: #{a[:localizacao]}" if a[:localizacao]
    end
  end

  unless rajadas_texto.empty?
    f.puts
    f.puts "-- Esgotamento do pool DHCP (starvation) --"
    rajadas_texto.each { |l| f.puts l }
  end

  f.puts isolados_texto if isolados_texto
end

puts
puts "Anomalias gravadas em: #{FICHEIRO_ANOMALIAS}"
