package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	loginPath   = "/_gate/login"
	cookieName  = "__Host-t3_gate"
	setupCookie = "__Host-gate_setup"
	sessionAge  = 365 * 24 * time.Hour
)

var base32Key = base32.StdEncoding.WithPadding(base32.NoPadding)

type state struct {
	Secret   []byte
	LastStep int64
	Sessions map[string]int64
}

type gateway struct {
	mu       sync.Mutex
	path     string
	origin   string
	state    state
	window   time.Time
	attempts int
}

type pageData struct {
	Setup  bool
	Secret string
	QRCode template.URL
	Error  string
}

func randomBytes(size int) []byte {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		log.Fatal(err)
	}
	return value
}

func save(path string, data state) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func load(path string) (state, error) {
	var data state
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data = state{
			Secret:   randomBytes(20),
			Sessions: make(map[string]int64),
		}
		return data, save(path, data)
	}
	if err != nil {
		return data, err
	}
	if err := json.Unmarshal(content, &data); err != nil {
		return data, err
	}
	if len(data.Secret) != 20 || data.Sessions == nil {
		return data, errors.New("会话状态无效")
	}
	return data, nil
}

func otp(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func sessionID(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (g *gateway) authenticated(r *http.Request, now time.Time) bool {
	cookie, err := r.Cookie(cookieName)
	return err == nil && len(cookie.Value) == 64 && g.state.Sessions[sessionID(cookie.Value)] > now.Unix()
}

func (g *gateway) verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	g.mu.Lock()
	valid := g.authenticated(r, time.Now())
	g.mu.Unlock()
	if valid {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Header.Get("X-Forwarded-Method") == "GET" &&
		(r.Header.Get("Sec-Fetch-Mode") == "navigate" ||
			(r.Header.Get("Sec-Fetch-Mode") == "" && strings.Contains(r.Header.Get("Accept"), "text/html"))) {
		http.Redirect(w, r, loginPath, http.StatusSeeOther)
		return
	}
	http.Error(w, "请先登录", http.StatusUnauthorized)
}

func render(w http.ResponseWriter, status int, data pageData) {
	if data.Setup {
		issuer := "Caddy Gate"
		uri := url.URL{
			Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":访问验证",
			RawQuery: url.Values{"secret": {data.Secret}, "issuer": {issuer}}.Encode(),
		}
		image, err := qrcode.Encode(uri.String(), qrcode.Medium, 256)
		if err != nil {
			log.Print(err)
			http.Error(w, "无法生成绑定二维码", http.StatusInternalServerError)
			return
		}
		// URI 前缀固定，内容只来自本地生成的 PNG。
		data.QRCode = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(image))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := loginPage.Execute(w, data); err != nil {
		log.Print(err)
	}
}

func (g *gateway) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")

	if r.Method == http.MethodPost {
		if r.Header.Get("Origin") != g.origin {
			http.Error(w, "请求来源无效", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "表单无效", http.StatusBadRequest)
			return
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.authenticated(r, now) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	page := pageData{Setup: g.state.LastStep == 0}
	if r.Method == http.MethodPost && !page.Setup && r.PostForm.Get("setup") == "1" {
		http.Redirect(w, r, loginPath, http.StatusSeeOther)
		return
	}
	secret := g.state.Secret
	if page.Setup {
		cookie, err := r.Cookie(setupCookie)
		if err != nil || len(cookie.Value) != 64 {
			if r.Method == http.MethodPost {
				http.Redirect(w, r, loginPath, http.StatusSeeOther)
				return
			}
			cookie = &http.Cookie{
				Name: setupCookie, Value: hex.EncodeToString(randomBytes(32)), Path: "/",
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 900,
			}
			http.SetCookie(w, cookie)
		}
		// 每个浏览器得到独立的候选密钥，只有完成绑定的密钥会生效。
		mac := hmac.New(sha256.New, g.state.Secret)
		mac.Write([]byte(cookie.Value))
		secret = mac.Sum(nil)[:20]
		page.Secret = base32Key.EncodeToString(secret)
	}
	if r.Method == http.MethodGet {
		render(w, http.StatusOK, page)
		return
	}
	if now.Sub(g.window) >= time.Minute {
		g.window, g.attempts = now, 0
	}
	if g.attempts >= 8 {
		page.Error = "尝试次数过多，请稍后再试。"
		w.Header().Set("Retry-After", "60")
		render(w, http.StatusTooManyRequests, page)
		return
	}
	g.attempts++

	step := now.Unix() / 30
	var matched int64
	for candidate := step - 1; candidate <= step+1; candidate++ {
		if candidate > g.state.LastStep && hmac.Equal([]byte(r.PostForm.Get("code")), []byte(otp(secret, candidate))) {
			matched = candidate
		}
	}
	if matched == 0 {
		page.Error = "验证码无效或已使用，请输入认证器中的最新验证码。"
		render(w, http.StatusUnauthorized, page)
		return
	}

	token := hex.EncodeToString(randomBytes(32))
	expires := now.Add(sessionAge)
	next := g.state
	next.LastStep = matched
	next.Secret = secret
	next.Sessions = make(map[string]int64, len(g.state.Sessions)+1)
	for id, expiration := range g.state.Sessions {
		if expiration > now.Unix() {
			next.Sessions[id] = expiration
		}
	}
	next.Sessions[sessionID(token)] = expires.Unix()
	if err := save(g.path, next); err != nil {
		log.Print(err)
		http.Error(w, "无法保存会话", http.StatusInternalServerError)
		return
	}
	g.state = next
	g.attempts = 0
	if page.Setup {
		http.SetCookie(w, &http.Cookie{
			Name: setupCookie, Path: "/", Secure: true, HttpOnly: true, MaxAge: -1,
		})
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionAge.Seconds()), Expires: expires,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	dataDir := os.Getenv("T3_GATE_DATA_DIR")
	if dataDir == "" {
		dataDir = "/data/t3-gate"
	}
	origin := os.Getenv("T3_GATE_ORIGIN")
	if origin == "" {
		origin = "https://t3.example.com"
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(dataDir, "state.json")
	data, err := load(path)
	if err != nil {
		log.Fatal(err)
	}
	g := gateway{path: path, origin: origin, state: data}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+loginPath, g.login)
	mux.HandleFunc("POST "+loginPath, g.login)
	mux.HandleFunc("GET /_gate/verify", g.verify)
	server := http.Server{
		Addr: "127.0.0.1:8787", Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 32 * 1024,
	}
	log.Fatal(server.ListenAndServe())
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>访问验证</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; color: #18231f; background: #edf1ee; }
body { margin: 0; min-height: 100svh; display: grid; place-items: center; }
main { box-sizing: border-box; width: min(28rem, calc(100% - 2rem)); padding: clamp(1.5rem, 6vw, 3rem); border: 1px solid #d9e1db; border-radius: 1.5rem; background: #fff; }
h1 { margin: 0 0 .75rem; font-size: 2rem; letter-spacing: -.035em; }
p, ol { margin: 0 0 1.25rem; line-height: 1.65; }
ol { padding-left: 1.3rem; }
label { display: grid; gap: .45rem; margin-bottom: 1rem; font-weight: 600; }
input, button { box-sizing: border-box; width: 100%; min-height: 3rem; font: inherit; border-radius: .65rem; }
input { padding: .65rem .75rem; border: 1px solid #8c9b91; background: transparent; color: inherit; }
input:focus-visible, button:focus-visible { outline: 2px solid #2f8f6b; outline-offset: 3px; }
button { border: 0; background: #15543f; color: #fff; font-weight: 650; cursor: pointer; }
code { display: block; padding: .75rem; margin-top: .5rem; background: #edf1ee; border-radius: .5rem; overflow-wrap: anywhere; user-select: all; }
.qr { display: block; width: min(100%, 14rem); height: auto; margin: 0 auto 1rem; border-radius: .65rem; }
details { margin-bottom: 1.25rem; }
summary { cursor: pointer; font-weight: 600; }
.error { color: #a32727; }
@media(prefers-color-scheme: dark) {
  :root { color: #e5eee8; background: #101713; }
  main { background: #1a241e; border-color: #35463b; }
  code { background: #101713; }
  .error { color: #ffa9a0; }
}
</style>
<main>
<h1>访问验证</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
{{if .Setup}}
  <p>在 Authy 或其他 TOTP 认证器里添加账户，扫描二维码，然后输入生成的六位验证码。</p>
  <img class="qr" src="{{.QRCode}}" width="256" height="256" alt="认证器绑定二维码">
  <details>
    <summary>手动添加</summary>
    <p>账户名填 Caddy Gate，类型选基于时间，并复制以下绑定密钥。<code>{{.Secret}}</code></p>
  </details>
{{else}}
  <p>输入认证器中的六位验证码。</p>
{{end}}
<form method="post" action="/_gate/login">
{{if .Setup}}<input type="hidden" name="setup" value="1">{{end}}
  <label>验证码<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>
  <button type="submit">{{if .Setup}}完成绑定{{else}}登录{{end}}</button>
</form>
</main>
</html>`))
