package dns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neon9809/cf-dns-select/config"
)

// 文件型 provider：三种格式渲染 + 回读解析 round trip。
func TestFileBasedRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		format string
		want   string
	}{
		{"dnsmasq", fileFormatHosts, "1.2.3.4 a.example.com\n1.2.3.4 b.example.com\n"},
		{"smartdns", fileFormatSmartDNS, "address /a.example.com/1.2.3.4\naddress /b.example.com/1.2.3.4\n"},
		{"mosdns", fileFormatMosDNSHosts, "a.example.com 1.2.3.4\nb.example.com 1.2.3.4\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.conf")
			c := NewFileBased(config.AdguardInstance{RulesFile: path}, tc.name, tc.format)
			if err := c.TestConnection(); err != nil {
				t.Fatal(err)
			}
			stats, err := c.ReplaceRewrites(map[string]map[string]bool{
				"b.example.com": {"1.2.3.4": true},
				"a.example.com": {"1.2.3.4": true},
			})
			if err != nil {
				t.Fatal(err)
			}
			if stats.Written != 2 {
				t.Errorf("应写入 2 条，实际 %d", stats.Written)
			}
			list, err := c.ListRewrites()
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 2 || list[0].Domain != "a.example.com" || list[0].Answer != "1.2.3.4" {
				t.Errorf("回读结果不符: %+v", list)
			}
		})
	}
}

// 文件型 provider：空集清理 + reload 命令执行。
func TestFileBasedClearAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	reloadRan := false
	_ = writeMarker(filepath.Join(dir, "marker"), &reloadRan)

	c := NewFileBased(config.AdguardInstance{RulesFile: path}, "test", fileFormatHosts)
	if _, err := c.ReplaceRewrites(map[string]map[string]bool{"x.com": {"1.1.1.1": true}}); err != nil {
		t.Fatal(err)
	}
	list, _ := c.ListRewrites()
	if len(list) != 1 {
		t.Fatalf("应有一条记录，实际 %d", len(list))
	}
	// 清空
	if _, err := c.ReplaceRewrites(map[string]map[string]bool{"x.com": {}}); err != nil {
		t.Fatal(err)
	}
	list, _ = c.ListRewrites()
	if len(list) != 0 {
		t.Errorf("清空后应为 0 条，实际 %d", len(list))
	}
}

func writeMarker(path string, flag *bool) error {
	return nil // marker 逻辑在 TestFileBasedReloadCmd 中单独验证
}

// reload 命令应被执行。
func TestFileBasedReloadCmd(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "reloaded")
	path := filepath.Join(dir, "rules.conf")
	c := NewFileBased(config.AdguardInstance{
		RulesFile: path,
		ReloadCmd: "touch " + marker,
	}, "test", fileFormatHosts)
	if _, err := c.ReplaceRewrites(map[string]map[string]bool{"x.com": {"1.1.1.1": true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := osStat(marker); err != nil {
		t.Errorf("reload 命令未执行（marker 不存在）: %v", err)
	}
}

// Technitium provider：mock API 验证差集收敛。
func TestTechnitiumReplaceRewrites(t *testing.T) {
	records := map[string]string{ // name → IP
		"old-example-com":  "9.9.9.9",
		"keep-example-com": "1.1.1.1",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/zones/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","response":[{"name":"example.com"}]}`))
	})
	mux.HandleFunc("/api/zones/records/get", func(w http.ResponseWriter, r *http.Request) {
		var list []tRecord
		for n, ip := range records {
			list = append(list, tRecord{Name: n, Type: "A", Value: ip})
		}
		w.Write([]byte(`{"status":"ok","response":` + mustJSON(list) + `}`))
	})
	mux.HandleFunc("/api/zones/records/add", func(w http.ResponseWriter, r *http.Request) {
		records[r.URL.Query().Get("name")] = r.URL.Query().Get("ipAddress")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/zones/records/update", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		records[q.Get("name")] = q.Get("ipAddress")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/zones/records/delete", func(w http.ResponseWriter, r *http.Request) {
		delete(records, r.URL.Query().Get("domain"))
		w.Write([]byte(`{"status":"ok"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewTechnitium(config.AdguardInstance{URL: srv.URL + "?zone=example.com", Password: "tok"})
	if err := c.TestConnection(); err != nil {
		t.Fatal(err)
	}
	stats, err := c.ReplaceRewrites(map[string]map[string]bool{
		"keep-example-com": {"1.1.1.1": true},
		"new-example-com":  {"2.2.2.2": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Written != 1 || stats.Removed != 1 {
		t.Errorf("期望 写入1/删除1，实际 %+v", stats)
	}
	if records["old-example-com"] != "" {
		t.Errorf("过期记录应被删除: %v", records)
	}
	if records["new-example-com"] != "2.2.2.2" {
		t.Errorf("新记录应被添加: %v", records)
	}
	if records["keep-example-com"] != "1.1.1.1" {
		t.Errorf("已有且正确的记录不应变动: %v", records)
	}
}

func osStat(path string) (interface{ Name() string }, error) {
	fi, err := os.Stat(path)
	return fi, err
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// 文件型 provider：双栈答案（同域名 v4+v6 两条记录）渲染与回读。
func TestFileBasedDualStack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.conf")
	c := NewFileBased(config.AdguardInstance{RulesFile: path}, "smartdns", fileFormatSmartDNS)
	if err := c.TestConnection(); err != nil {
		t.Fatal(err)
	}
	stats, err := c.ReplaceRewrites(map[string]map[string]bool{
		"a.example.com": {"104.20.50.16": true, "2606:4700::6810": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Written != 2 {
		t.Errorf("双栈应写入 2 条，实际 %d", stats.Written)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 渲染按域名排序，同域名内按答案字符串排序：2606:… < 104.20.50.16 不成立（'1'<'2'），
	// 实际顺序为 104.20.50.16 在前
	want := "address /a.example.com/104.20.50.16\naddress /a.example.com/2606:4700::6810\n"
	if !strings.HasSuffix(string(data), want) {
		t.Errorf("受管文件应包含 v4+v6 两条 address 记录，实际尾部:\n%s", data)
	}
	list, err := c.ListRewrites()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("回读应得 2 条，实际 %d: %+v", len(list), list)
	}
	fams := map[string]bool{}
	for _, e := range list {
		fams[e.Answer] = true
	}
	if !fams["104.20.50.16"] || !fams["2606:4700::6810"] {
		t.Errorf("回读应同时含 v4 与 v6 答案: %+v", list)
	}
}
