package main

import (
	"fmt"
	"github.com/robfig/config"
	"flag"
	"io/ioutil"
	"github.com/Efruit/lg"
	"os"
	"strings"
	"net/url"
	mwapi "github.com/kracekumar/go-mwapi"
	"time"
	"bytes"
	"strconv"
	"html/template"
)

var dbgmode = flag.Bool("debug", false, "Log debug messages")

func init () {
	flag.Parse()
	lg.DebugMode = *dbgmode
}

func main () {
	lg.Log(lg.INFO, "Initiating parse job...")
	for _, v := range flag.Args() {
		parser(v)
		if !*dbgmode {
			err := os.Remove(v)
			if err != nil {
				lg.Log(lg.ERROR, "Failed to remove file")
			}
		}
	}
}

var USER string
var SQLMISC string
var PASSWD string
var DBHOST string

const (
	ERROR = -1
	REG_NONE = 0
	REG_SZ = 1
	REG_EXPAND_SZ = 2
	REG_BINARY = 3
	REG_DWORD = 4
	REG_DWORD_LITTLE_ENDIAN = 4
	REG_DWORD_BIG_ENDIAN = 5
	REG_LINK = 6 
	REG_MULTI_SZ = 7
	REG_RESOURCE_LIST = 8
	REG_FULL_RESOURCE_DESCRIPTOR = 9
	REG_RESOURCE_REQUIREMENTS_LIST = 10
	REG_QWORD = 11
	REG_QWORD_LITTLE_ENDIAN = 11
)

var names = []string{
	"REG_NONE",
	"REG_SZ",
	"REG_EXPAND_SZ",
	"REG_BINARY",
	"REG_DWORD",
	"REG_DWORD_BIG_ENDIAN",
	"REG_LINK",
	"REG_MULTI_SZ",
	"REG_RESOURCE_LIST",
	"REG_FULL_RESOURCE_DESCRIPTOR",
	"REG_RESOURCE_REQUIREMENTS_LIST",
	"REG_QWORD",
}

func GetName(t int) string {
	if REG_QWORD < t || t < REG_NONE {
		return "ERROR"
	} else {
		return names[t]
	}
}

// thing: it's an unfortunate fact of life that, because of the nature of the Windows Registry, some private data will slip through in ways we can't even begin to anticipate

type soft struct{
	Name string
	Versions []soft
	Major string
	Minor string
	Update string
}

var soft_unknown soft = soft{Name: "[Unknown]", Major:"", Minor:"", Update:""}

var COLOR = "ccccccff"

type swiki struct{
	Key string
	Type string
	Default string
	Soft string
	Values []swiki
}

var tmplfm = template.FuncMap {
	"hive": func(s string)string{return strings.Split(s, "\\")[0]},
}

func Render(s swiki) string{
	/* From the Go docs on text/template */
	tmpl, err := template.New("rendered").Funcs(tmplfm).Parse(WIKITEXT)
	if err != nil {
		lg.Log(lg.ERROR, err.Error())
	}

	var buffer = bytes.NewBufferString("")
	err = tmpl.Execute(buffer, s)
	if err != nil {
		lg.Log(lg.ERROR, err.Error())
	}

	buf := strings.Replace(buffer.String(), "{_", "{", -1)
	buf = strings.Replace(buf, "_}", "}", -1)

	return buf
}

const ADDTEXT=`{_{_rt|name={{.Key}}|type={{.Type}}|value={{.Default}}|usedby=(unknown)_}_}
<!-- BOT: ADDHERE -->`

const WIKITEXT=`
'''{{.Key}}''' is a key in [[{{hive .Key}}]].

{{ range .Values }}
=={{.Key}}==
{_{_value|{{.Type}}|(unknown)|<!-- {{.Default}} -->_}_}
{_{_unresearched_}_}
{{end}}

==References==
Sourced from a .reg dump file
`

func parser(s string) {
		var now = time.Now()
		var parses time.Time
		var parsee time.Time
		var ups time.Time
		var upe time.Time
		defer func(){
			naw := time.Now().Sub(now)
			nzw := parsee.Sub(parses)
			nkw := upe.Sub(ups)
			lg.Log(lg.TRACE, "Total:" + naw.String())
			lg.Log(lg.TRACE, "Parse:" + nzw.String())
			lg.Log(lg.TRACE, "Post:" + nkw.String())
		}()

		parses = time.Now()
		tmp, err := ioutil.ReadFile(s)
		if err != nil {
			lg.Log(lg.ERROR, err.Error())
			return
		}
	

		if *dbgmode {
			regfhd, err := ioutil.TempFile(os.TempDir(), "regp-raw-")
			if err != nil {
				lg.Log(lg.ERROR, "Failed to create debug raw file")
				lg.Log(lg.DEBUG,err.Error())
				return
			}
			lg.Log(lg.DEBUG, "Raw Dump File: " + regfhd.Name())
			lg.Log(lg.DEBUG, "Dumping body into raw file")
			fmt.Fprint(regfhd, tmp)
		}

		regfh, err := ioutil.TempFile(os.TempDir(), "regp-")
		if err != nil {
			lg.Log(lg.ERROR, "Failed to create temporary file")
			lg.Log(lg.DEBUG, err.Error())
			return
		}
		lg.Log(lg.DEBUG, "Temporary File: " + regfh.Name())
		defer func() {
			if regfh != nil && !*dbgmode {
				lg.Log(lg.DEBUG, "RMing temp file " + regfh.Name())
				os.Remove(regfh.Name())
				regfh = nil
			}
		}()

		/*tmpa, err := url.QueryUnescape(string(tmp))
		if err != nil {
			lg.Log(lg.DEBUG,err.Error())
			return
		}*/

		tmpb := strings.Replace(string(tmp), "\r", "", -1)

		if *dbgmode {
			regfhd, err := ioutil.TempFile(os.TempDir(), "regp-post-")
			if err != nil {
				lg.Log(lg.ERROR, "Failed to create debug post-processing dump file")
				lg.Log(lg.DEBUG,err.Error())
				return
			}
			lg.Log(lg.DEBUG, "Processed Dump File: " + regfhd.Name())
			lg.Log(lg.DEBUG, "Dumping tmpb into raw file")
			fmt.Fprint(regfhd, tmpb)
		}

		if strings.HasPrefix(string(tmpb), "REGEDIT4") {
			lg.Log(lg.DEBUG,"Found Windows Registry Editor string")
			fmt.Fprint(regfh, strings.Join(strings.Split(string(tmpb), "\n")[1:], "\n"))
		} else {
			lg.Log(lg.INFO, "Invalid .reg")
			lg.Log(lg.INFO, "Not a valid .reg file.")
			return
		}

		registry, err := config.Read(regfh.Name(), config.ALTERNATIVE_COMMENT,config.ALTERNATIVE_SEPARATOR,false, false)

		if err != nil {
			lg.Log(lg.DEBUG, "Not a valid .reg file.")
			lg.Log(lg.DEBUG, err.Error())
			return
		}

		lg.Log(lg.TRACE, "Entering print")
		n := 0
		if len(registry.Sections()) != 0 {
			n = 1
		}
		var aok bool = true
		var aok2 bool = true
		var buff = make(map[string]string)
		lg.Log(lg.TRACE, fmt.Sprint("n = ", n))
		for _, vv := range registry.Sections(){
			if vv == "DEFAULT" {
				continue
			}

			if strings.HasPrefix(vv, "-") { // Lol an actual .reg file
				lg.Log(lg.DEBUG, "- found")
				aok = false
				break
			} else if strings.Count(vv, "\"") > 2 {
				aok = false
				break
			}

			lg.Log(lg.DEBUG, vv)

			r, err := registry.Options(vv)
			if err != nil {
				lg.Log(lg.DEBUG,err.Error())
			}

			for _, vvv := range r {
				rr, err := registry.RawString(vv, vvv)
				if rr == "-" {
					lg.Log(lg.TRACE, "- found")
					aok = false // ya blew it
								// ya could'a had it all
								// but 'cha blew it
				}

				if err != nil {
					lg.Log(lg.DEBUG,err.Error())
				}

				lg.Log(lg.DEBUG, fmt.Sprintf("%v=%v\n", vvv, rr))
			}
			
			rs, _ := registry.RawString(vv, "@")
			var swiggy = swiki{Key:vv, Default: rs}
			for _, vvv := range r {
				rr, _ := registry.RawString(vv, vvv)
				var i = ParseType(rr)
				lg.Log(lg.DEBUG, i)
				swiggy.Values=append(swiggy.Values, swiki{Key:vvv, Type: GetName(i)})
			}
			buff[vv] = Render(swiggy)
		}

		if !aok {
			lg.Log(lg.DEBUG, "Not aok, terminating")
			return
		} else {
			lg.Log(lg.DEBUG, "aok = true, continuing")
		}
		parsee = time.Now()

		ups = time.Now()
		hkeywiki := url.URL{
			Scheme: "http",
			Host: "hkey.n0v4.com",
			Path: "/w/api.php",
		}
		api := mwapi.NewMWApi(hkeywiki)
		api.Login(USER, PASSWD)

		delete(buff, "DEFAULT")
		for k, v := range buff {
			lg.Log(lg.DEBUG, k)
			if aok2 {
				api.Login(USER, PASSWD)
				t := api.GetToken("edit")
				lg.Log(lg.TRACE, t.Tokens.Edittoken)
				params := url.Values{
					"action": {"edit"},
					"title": {k},
					"createonly": {"1"},
					"bot": {"1"},
					"text": {fmt.Sprintf("#REDIRECT [[%v]]", strings.Replace(k, "\\", "/", -1))},
					"token": {t.Tokens.Edittoken},
				}
				resp := api.PostForm(params)
				if resp.StatusCode != 200 {
					rbody, _ := ioutil.ReadAll(resp.Body)
					lg.Log(lg.DEBUG, string(rbody))
				}
			}
			api.Login(USER, PASSWD)
			t := api.GetToken("edit")
			lg.Log(lg.TRACE, t.Tokens.Edittoken)

			params := url.Values{
				"action": {"edit"},
				"title": {strings.Replace(k, "\\", "/", -1)},
				"createonly": {"1"},
				"bot": {"1"},
				"text": {v},
				"token": {t.Tokens.Edittoken},

			}
			resp := api.PostForm(params)
			if resp.StatusCode != 200 {
				rbody, _ := ioutil.ReadAll(resp.Body)
				lg.Log(lg.DEBUG, string(rbody))
			}
		}
		upe = time.Now()
}

func ParseType(s string) (int){
	switch {
		case strings.HasPrefix(s, "\""):
			lg.Log(lg.DEBUG, fmt.Sprintf("REG_SZ: %s", s))
			return REG_SZ
		case strings.HasPrefix(s, "dword:"):
			lg.Log(lg.DEBUG, fmt.Sprintf("REG_DWORD: %s", s))
			return REG_DWORD
		case strings.HasPrefix(s, "hex("):
			lg.Log(lg.DEBUG, "Parsing hex()")
			var g = string([]byte(s)[4])
			var ii int64
			var iii int
			var err error

			ii, err = strconv.ParseInt(g, 16, 0)
			if err != nil {
				lg.Log(lg.ERROR, "MALFUNCTION: Non-recognized byte (stage 2) in hex()")
				lg.Log(lg.ERROR, s)
				lg.Log(lg.ERROR, err.Error())
				return -1
			}
			
			iii = int(ii)

			if !(REG_NONE <= iii && iii <= REG_QWORD) {
				lg.Log(lg.ERROR, "Type invalid or absent")
				lg.Log(lg.TRACE, s)
				lg.Log(lg.TRACE, iii)
				lg.Log(lg.TRACE, "!(REG_NONE =< iii && iii =< REG_QWORD)")
				return -1
			}
			lg.Log(lg.DEBUG, fmt.Sprintf("hex(%s)(%v)(%v): %s", GetName(iii), iii, ii, s))
			return iii
		case strings.HasPrefix(s, "hex:"):
			lg.Log(lg.DEBUG, fmt.Sprintf("REG_BINARY: %s", s))
			return REG_BINARY
		default:
			lg.Log(lg.ERROR, "Type invalid or not found")
			lg.Log(lg.TRACE, s)
			return -1
	}
}
