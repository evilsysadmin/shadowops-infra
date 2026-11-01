package runtime

// Optional, privileged staging-only name resolution for the Chronicles
// administrative roster. This is not a browser API or a login identity claim.
// The consumer authenticates using an independent operator-provisioned secret;
// Chronicles must authorize its own administrator BEFORE calling this RPC.
import (
  "context"
  "crypto/sha256"
  "crypto/subtle"
  "encoding/base64"
  "encoding/json"
  "errors"
  "io"
  "mime"
  "net"
  "net/http"
  "regexp"
  "strings"
  "sync"
  "time"

  "go.mongodb.org/mongo-driver/v2/bson"
  "go.mongodb.org/mongo-driver/v2/mongo"
  "go.mongodb.org/mongo-driver/v2/mongo/options"
)

const AdminAliasesPath = "/api/identity/admin-aliases"
const adminAliasLimit = 40

var adminAliasUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var adminAliasName = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)

type adminAliasReader func(context.Context, []string) (map[string]string, error)

type adminAliasHandler struct {
  digest [32]byte
  read adminAliasReader
  mu sync.Mutex
  window time.Time
  attempts int
}

func adminAliasCredentialDigest(key string) ([32]byte, bool) {
  if len(key) != 48 || !strings.HasPrefix(key, "soa1_") { return [32]byte{}, false }
  raw, err := base64.RawURLEncoding.DecodeString(key[5:])
  if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != key[5:] {
    return [32]byte{}, false
  }
  return sha256.Sum256([]byte("shadowops-admin-alias-v1:staging:" + key)), true
}

func newAdminAliasHandler(key string, read adminAliasReader) (*adminAliasHandler, error) {
  digest, ok := adminAliasCredentialDigest(key)
  if !ok || read == nil { return nil, ErrUnsafeConfiguration }
  return &adminAliasHandler{digest: digest, read: read}, nil
}

// A narrowly scoped fixed 30 requests/minute global ceiling. The API returns
// at most 40 aliases/request, never full account documents or credentials.
func (h *adminAliasHandler) allow(now time.Time) bool {
  h.mu.Lock()
  defer h.mu.Unlock()
  if h.window.IsZero() || now.Sub(h.window) >= time.Minute {
    h.window, h.attempts = now, 0
  }
  if h.attempts >= 30 { return false }
  h.attempts++
  return true
}

func (h *adminAliasHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Cache-Control", "no-store")
  w.Header().Set("X-Content-Type-Options", "nosniff")
  w.Header().Set("Referrer-Policy", "no-referrer")
  // No Origin/Cookie/CORS. Only backend-to-backend TLS calls.
  if r.TLS == nil || r.Host != serviceHost || len(r.Header.Values("Origin")) != 0 ||
    len(r.Header.Values("Cookie")) != 0 || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
    http.Error(w, "service transport required", http.StatusForbidden)
    return
  }
  if r.Method != http.MethodPost {
    w.Header().Set("Allow", "POST")
    http.Error(w, "method denied", http.StatusMethodNotAllowed)
    return
  }
  _, _, err := net.SplitHostPort(r.RemoteAddr)
  if err != nil { http.Error(w, "service peer required", http.StatusForbidden); return }
  bearer, supplied := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
  digest, canonical := adminAliasCredentialDigest(bearer)
  if len(r.Header.Values("Authorization")) != 1 || !supplied || !canonical ||
    subtle.ConstantTimeCompare(digest[:], h.digest[:]) != 1 {
    http.Error(w, "authorization denied", http.StatusUnauthorized)
    return
  }
  media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
  if err != nil || media != "application/json" || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" {
    http.Error(w, "invalid request", http.StatusBadRequest)
    return
  }
  var body struct { Subjects []string `json:"subjects"` }
  decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
  decoder.DisallowUnknownFields()
  if decoder.Decode(&body) != nil {
    http.Error(w, "invalid request", http.StatusBadRequest)
    return
  }
  var extra any
  if decoder.Decode(&extra) != io.EOF || len(body.Subjects) < 1 || len(body.Subjects) > adminAliasLimit {
    http.Error(w, "invalid request", http.StatusBadRequest)
    return
  }
  selected := make(map[string]bool, len(body.Subjects))
  for _, id := range body.Subjects {
    if !adminAliasUUID.MatchString(id) || selected[id] {
      http.Error(w, "invalid subjects", http.StatusBadRequest)
      return
    }
    selected[id] = true
  }
  if !h.allow(time.Now()) {
    w.Header().Set("Retry-After", "60")
    http.Error(w, "request limit", http.StatusTooManyRequests)
    return
  }
  ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
  defer cancel()
  resolved, err := h.read(ctx, body.Subjects)
  if err != nil {
    http.Error(w, "identity lookup unavailable", http.StatusServiceUnavailable)
    return
  }
  result := make(map[string]string)
  for subject, alias := range resolved {
    if selected[subject] && adminAliasName.MatchString(alias) {
      result[subject] = alias
    }
  }
  w.Header().Set("Content-Type", "application/json")
  _ = json.NewEncoder(w).Encode(struct {
    Aliases map[string]string `json:"aliases"`
  }{Aliases: result})
}

func adminAliasesFromMongo(collection *mongo.Collection) adminAliasReader {
  return func(ctx context.Context, subjects []string) (map[string]string, error) {
    if collection == nil { return nil, errors.New("identity store unavailable") }
    ids := bson.A{}
    for _, id := range subjects { ids = append(ids, id) }
    cursor, err := collection.Find(ctx, bson.D{
      {Key: "environment", Value: "staging"},
      {Key: "source", Value: "shadowops-identity"},
      {Key: "state", Value: "active"},
      {Key: "credentials_disabled", Value: false},
      {Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}},
    }, options.Find().SetProjection(bson.D{
      {Key: "_id", Value: 1},
      {Key: "alias_key", Value: 1},
    }).SetLimit(int64(len(subjects))))
    if err != nil { return nil, err }
    defer cursor.Close(ctx)
    aliases := make(map[string]string)
    for cursor.Next(ctx) {
      var row struct {
        Subject string `bson:"_id"`
        Alias string `bson:"alias_key"`
      }
      if err := cursor.Decode(&row); err != nil { return nil, err }
      if adminAliasUUID.MatchString(row.Subject) && adminAliasName.MatchString(row.Alias) {
        aliases[row.Subject] = row.Alias
      }
    }
    if err := cursor.Err(); err != nil { return nil, err }
    return aliases, nil
  }
}
