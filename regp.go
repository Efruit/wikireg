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
		err := os.Remove(v)
		if err != nil {
			lg.Log(lg.ERROR, "Failed to remove file")
		}
	}
}

var USER string
var SQLMISC string
var PASSWD string
var DBHOST string

const (
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
{_{_rt-start|{_{_unresearched_}_}_}_}
{_{_rt|key|name={{.Key}}_}_}
{_{_rt|name={{.Key}}|type={{.Type}}|value={{.Default}}|usedby=(unknown)_}_}
<!-- BOT: ADDHERE -->
{_{_rt-end_}_}
'''{{.Key}}''' is a key in [[{{hive .Key}}]].

{{ range .Values }}
=={{.Key}}==
{_{_value|{{.Type}}|(unknown)|<!-- {{.Default}} -->_}_}
{_{_unresearched_}_}
{{end}}

==Raw export==
{_{_TODO|[[User:wowaname|wowaname]]: What do you want here?_}_}
{_{_raw|replace_}_}

==References==
Sourced from a .reg dump file
`

func parser(s string) {
		now := time.Now()
		defer func(){
			naw := time.Now().Sub(now)
			lg.Log(lg.TRACE, naw.String())
		}()

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
				if strings.HasPrefix(rr, "-") {
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
				swiggy.Values=append(swiggy.Values, swiki{Key:vvv, Type: names[i]})
			}
			buff[vv] = Render(swiggy)
		}

		if !aok {
			lg.Log(lg.DEBUG, "Not aok, terminating")
			return
		} else {
			lg.Log(lg.DEBUG, "aok = true, continuing")
		}

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
}

func ParseType(s string) (int){
	switch {
		case strings.HasPrefix(s, "\""):
			return REG_SZ
		case strings.HasPrefix(s, "dword:"):
			return REG_DWORD
		case strings.HasPrefix(s, "hex("):
			var flak string
			var i int
			n, err := fmt.Sscanf(s, "hex(%d):%s", i, flak)
			if n < 2 {
				lg.Log(lg.ERROR, err.Error())
				return -1
			}
			if !(REG_NONE < i && i < REG_QWORD) {
				lg.Log(lg.ERROR, "Type invalid or absent")
				lg.Log(lg.TRACE, s)
				return -1
			}
			return i
		case strings.HasPrefix(s, "hex:"):
			return REG_BINARY
		default:
			lg.Log(lg.ERROR, "Type invalid or not found")
			lg.Log(lg.TRACE, s)
			return -1
	}
}
