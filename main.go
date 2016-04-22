package main

import (
	"net/http"
	"encoding/json"
	"time"
	"encoding/base64"
	"strconv"
)

var (
	img []byte
	imgLen int
)

func init() {
	img, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQEAYAAABPYyMiAAAABmJLR0T///////8JWPfcAAAACXBIWXMAAABIAAAASABGyWs+AAAAF0lEQVRIx2NgGAWjYBSMglEwCkbBSAcACBAAAeaR9cIAAAAASUVORK5CYII=")
}

func main() {
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Content-Length", strconv.Itoa(imgLen))
		w.Write(img)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("Bad request"))
			return
		}
		var i VulnReqs
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&i); err != nil {
			w.WriteHeader(400)
			if serr, ok := err.(*json.SyntaxError); ok {
				w.Write([]byte("Error " + serr.Error() + " at offset " + strconv.Itoa(int(serr.Offset))))
			} else {
				w.Write([]byte("Error " + serr.Error()))
			}
			return
		}

		resChan := make(chan VulnRes)
		/** @var VulnReq vuln */
		for _, vuln := range i {
			switch vuln.Kind {
			case "wp":
				go func() {
					resChan <- scanWp(vuln.Version)
				}()
			case "plugin":
				go func() {
					resChan <- scanPlugin(vuln.Slug, vuln.Version)
				}()
			case "theme":
				go func() {
					resChan <- scanTheme(vuln.Slug, vuln.Version)
				}()
			default:
				go func() {
					resChan <- VulnRes{OK:true}
				}()
			}
		}

		s := VulnRess{}
		for range i {
			s = append(s, <-resChan)
		}
		encoder := json.NewEncoder(w)
		encoder.Encode(&s)
		w.Write([]byte("Hello, world!"))
	})
	err := http.ListenAndServe(":5555", nil)
	panic(err)
}

func downloadDatabase(db string) (t *WpVulns) {
	res, err := http.Get("https://wpvulndb.com/data/" + db + "_vulns.json")
	if err != nil {
		panic(err.Error())
	}
	decoder := json.NewDecoder(res.Body)
	decoder.Decode(&t)
	if err != nil {
		panic(err.Error())
	}
	res.Body.Close()
	return
}

type WpVulns []WpVuln
type WpVuln map[string]WpVersion
type WpVersion struct {
	Vulnerabilities []WpVu `json:"vulnerabilities"`
}
type WpVu struct {
	ID         int `json:"id"`
	Title      string `json:"title"`
	VulnType   string `json:"vuln_type"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	FixedIn    string `json:"fixed_in"`

	URL        []string `json:"url"`
	CVE        []string `json:"cve"`
	ExploitDB  []string `json:"exploitdb"`
	Metasploit []string `json:"metasploit"`
	OSVDB      []string `json:"osvdb"`
	Secunia    []string `json:"secunia"`
}

type VulnReqs []VulnReq
type VulnReq struct {
	Kind    string `json:"type"`
	Slug    string `json:"slug"`
	Version string `json:"version"`
}

type VulnRess []VulnRes
type VulnRes struct {
	OK bool `json:"ok"`
}
