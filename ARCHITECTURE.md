# Mimari Detayı

## Modüller

```
cmd/
  mcp-audit/
    main.go              # CLI entrypoint, subcommand routing (run / serve)

internal/
  interceptor/
    interceptor.go       # JSON-RPC parse -> ToolCallEvent dönüşümü
    types.go              # ToolCallEvent, ve ilgili struct'lar

  stdio/
    wrapper.go            # os/exec ile process spawn + pipe interception

  httpproxy/
    proxy.go               # httputil.ReverseProxy tabanlı HTTP mode

  policy/
    engine.go              # Policy engine orkestrasyon
    rbac.go                 # Allow/deny listesi mantığı
    rugpull.go               # Tool description hash takibi
    poisoning.go              # Tool-poisoning heuristic taraması

  sinks/
    sink.go                # Sink interface tanımı
    jsonl.go                 # Yerel dosya sink (her zaman aktif)
    webhook.go                # Opsiyonel webhook/SIEM export
    hosted.go                  # Opsiyonel hosted backend gönderimi (Team tier)

  config/
    config.go              # config.yaml parse + validation

pkg/
  (şimdilik boş — dışa açılacak public API olursa buraya taşınır)
```

## Veri modeli

```go
// internal/interceptor/types.go

type ToolCallEvent struct {
    Timestamp   time.Time       `json:"timestamp"`
    EventID     string          `json:"event_id"`      // UUID, idempotency için
    ClientID    string          `json:"client_id"`      // hangi MCP client (varsa)
    ServerName  string          `json:"server_name"`     // hangi MCP server
    Direction   string          `json:"direction"`        // "request" | "response"
    Method      string          `json:"method"`             // JSON-RPC method adı
    ToolName    string          `json:"tool_name,omitempty"`
    Arguments   json.RawMessage `json:"arguments,omitempty"`
    Result      json.RawMessage `json:"result,omitempty"`
    Error       string          `json:"error,omitempty"`
    PolicyFlags []string        `json:"policy_flags,omitempty"` // rug_pull, poisoning_suspect vb.
}
```

## Sink interface

```go
// internal/sinks/sink.go

type Sink interface {
    Write(ctx context.Context, event ToolCallEvent) error
    Name() string
}
```

Fan-out mantığı: `sinks.Dispatcher` tüm kayıtlı sink'lere paralel `goroutine` ile
yazar. JSONL sink'in hatası proxy akışını durdurmaz (log + devam). Webhook/hosted
sink'lerde exponential backoff'lu retry kuyruğu olur (basit in-memory kuyruk,
MVP'de disk-backed olmasına gerek yok).

## Config formatı (taslak)

```yaml
# config.yaml
mode: stdio  # veya "http"

policy:
  rbac:
    default: allow  # shadow mode varsayılanı
    rules:
      - client: "*"
        deny: []
  rug_pull_detection: true
  poisoning_heuristics: true
  state_path: "~/.mcp-audit/state/tools.json"  # tool fingerprint store

sinks:
  jsonl:
    path: "~/.mcp-audit/logs/events.jsonl"
  webhook:
    enabled: false
    url: ""
  hosted:
    enabled: false
    api_key: ""
    endpoint: "https://api.mcp-audit.dev/v1/events"
```

## Policy engine akışı

Policy engine iki noktada devreye girer:

1. **`tools/call` request'inde** — RBAC allow/deny. Reddedilirse mesaj server'a
   hiç iletilmez, client'a `-32000` kodlu JSON-RPC hatası döner.
2. **`tools/list` response'unda** — rug-pull ve tool-poisoning kontrolleri.
   Response'lar **asla bloklanmaz**; sadece `PolicyFlags` işaretlenir ve
   stderr'e alarm basılır. Yan etki zaten gerçekleşmiş olur, bloklamak sadece
   kanıtı gizler.

Diğer tüm mesajlar (initialize, ping, resources/*) değişmeden geçer.

## Tool fingerprint store

Rug-pull tespiti süreçler arası hafıza gerektirir — saldırı, kullanıcı tool'u
onayladıktan **günler sonra** description'ı değiştirmektir. Bu yüzden
`policy.state_path` (varsayılan `~/.mcp-audit/state/tools.json`) altında
kalıcı bir JSON dosyası tutulur:

```json
{
  "version": 1,
  "servers": {
    "<server-name>": {
      "<tool-name>": {
        "hash": "<sha256(description + inputSchema)>",
        "first_seen": "...", "last_seen": "...", "changes": 0
      }
    }
  }
}
```

Notlar:

- Hash alınmadan önce `inputSchema` **canonicalize** edilir (JSON parse + yeniden
  encode). Aksi halde map iterasyon sırası değişen bir server her çağrıda
  rug-pull gibi görünürdü.
- Dosya atomik yazılır (temp + rename), yarım yazılmış dosya bırakılmaz.
- Bozuk ya da farklı sürümlü store **hata verir**, sessizce sıfırlanmaz —
  sessiz sıfırlama, dosyayı kurcalayan birinin tam da işine yarardı.
- Server adı ayrı bir anahtar: iki farklı MCP server'ın aynı isimli tool'u
  birbirini gölgelemez.

## Stdio mode akışı

1. `mcp-audit run -- <command> [args...]`
2. `os/exec.Command` ile alt process başlatılır
3. Alt process'in stdin/stdout'u proxy tarafından pipe edilir (`io.Pipe` + `io.TeeReader`)
4. Her satır (JSON-RPC mesajı newline-delimited gelir) interceptor'a gider
5. Interceptor `ToolCallEvent` üretir, policy engine'den geçer
6. Orijinal mesaj değişmeden alt process'e / client'a iletilir (biz sadece gözlemliyoruz,
   shadow mode'da müdahale etmiyoruz)
7. Paralel olarak sink dispatcher'a event gönderilir

## HTTP mode akışı

1. `mcp-audit serve --target <remote-url> --listen :9000`
2. `httputil.ReverseProxy` kurulur, `Director` request'i hedefe yönlendirir
3. Request body'si (JSON-RPC) okunurken interceptor'dan geçirilir (body'yi tüketmeden
   `io.TeeReader` ile kopyalanır, orijinal body hedefe değişmeden gider)
4. `ModifyResponse` hook'unda response da aynı şekilde interceptor'dan geçer
5. Policy engine + sink dispatcher aynı stdio moddaki gibi çalışır

## Performans notu

Stdio modda pipe interception ekstra bir goroutine + buffer kopyalama demek.
Hedef: p99 gecikme eklentisi <5ms olmalı (kullanıcı fark etmemeli).

`internal/interceptor/bench_test.go` bunu ölçüyor. 13th Gen i7-13700H üzerinde:

| İşlem | Süre | Alloc |
|---|---|---|
| Notification parse | 911 ns | 624 B / 9 |
| `tools/call` request parse | 3.1 µs | 1088 B / 22 |
| `tools/call` response parse | 2.9 µs | 744 B / 12 |
| **Tam round-trip (request + response)** | **8.0 µs** | 1840 B / 34 |
| 40 tool'luk `tools/list` (19 KB) parse | 149 µs | 19.8 KB / 13 |

Yani bir tool çağrısına eklenen parse maliyeti ~8 µs — 5 ms bütçesinin
~600'de biri. `tools/list` en pahalı yol ama oturum başına birkaç kez çağrılır.

`TestParseLatencyStaysUnderBudget` regresyon bekçisi olarak p99'u 250 µs'nin
altında tutuyor. Ölçüm **batch** halinde yapılıyor: tek bir Parse çağrısı
işletim sistemi saatinin çözünürlüğünden hızlı (Windows'ta tek örnek ~1 ms
tick'e yuvarlanıyor ve kodu değil saati ölçüyor).

Policy engine ve sink'ler bu bütçenin dışında: policy sadece `tools/call` ve
`tools/list` mesajlarında çalışıyor, sink'ler ayrı goroutine'lere devrediyor.