package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type OTXResult struct {
	HasNext    bool `json:"has_next"`
	ActualSize int  `json:"actual_size"`
	URLList    []struct {
		Domain   string `json:"domain"`
		URL      string `json:"url"`
		Hostname string `json:"hostname"`
		Httpcode int    `json:"httpcode"`
		PageNum  int    `json:"page_num"`
		FullSize int    `json:"full_size"`
		Paged    bool   `json:"paged"`
	} `json:"url_list"`
}
type CommonCrawlInfo []struct {
	CdxAPI string `json:"cdx-api"`
}

var IncludeSubs bool
var MaxRetries int
var HttpStatus bool
var client = &http.Client{
	Timeout: time.Second * 15,
}
var ResultData []Data

type Data struct {
	Host     string
	Path     string
	QueryKey []string
	Hash     string
}

type Url struct {
	Url string
}

func HandleUri(uri string) Data {
	u, err := url.Parse(uri)
	data := Data{}
	if err != nil {
		return data
	}
	data.Host = u.Host
	reg, _ := regexp.Compile(`(\d+)`)
	data.Path = reg.ReplaceAllString(u.Path, "1")
	hashString := data.Host + data.Path
	for _, param := range strings.Split(u.RawQuery, "&") {
		key := strings.Split(param, "=")[0]
		data.QueryKey = append(data.QueryKey, key)
		hashString += key
	}
	data.Hash = Md5(hashString)
	return data
}

func Md5(content string) string {
	h := md5.New()
	h.Write([]byte(content))
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func DeDuplication(uri string) bool {
	data := HandleUri(uri)
	for _, item := range ResultData {
		if item.Hash == data.Hash {
			return true
		}
	}
	ResultData = append(ResultData, data)
	return false
}

func main() {
	var domains []string
	flag.BoolVar(&IncludeSubs, "subs", false, "include subdomains of target domain")
	flag.IntVar(&MaxRetries, "retries", 5, "amount of retries for http client")
	flag.BoolVar(&HttpStatus, "httpcode", false, "get httpcode")
	flag.Parse()
	if flag.NArg() > 0 {
		domains = []string{flag.Arg(0)}
	} else {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			domains = append(domains, s.Text())
		}
	}
	for _, domain := range domains {
			Run(domain)
	}
}

type fetch func(string) ([]string, error)

func Run(domain string) {
	fetchers := []fetch{getWaybackUrls, getCommonCrawlURLs, getOtxUrls}
	for _, fn := range fetchers {
		found, err := fn(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			continue
		}
		for _, f := range found {
			if !HttpStatus  {
				if !DeDuplication(f) {
					if !UrlPath(f) {
						fmt.Println(f)
					}
				}
			} else {
				if !DeDuplication(f) {
					if !UrlPath(f) {
						fmt.Println(HttpCode(f))
					}
				}
			}
		}
	}
}
func getOtxUrls(hostname string) ([]string, error) {
	var urls []string
	page := 0
	retries := MaxRetries
	for {
		var o = &OTXResult{}
		for retries > 0 {
			r, err := client.Get(fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/hostname/%s/url_list?limit=50&page=%d", hostname, page))
			if err != nil {
				retries -= 1
				if retries == 0 {
					return nil, errors.New(fmt.Sprintf("http request to OTX failed: %s", err.Error()))
				}

			}
			defer r.Body.Close()
			bytes, err := ioutil.ReadAll(r.Body)
			if err != nil {
				retries -= 1
				if retries == 0 {
					return nil, errors.New(fmt.Sprintf("error reading body from alienvault: %s", err.Error()))
				}
			}
			err = json.Unmarshal(bytes, o)
			if err != nil {
				retries -= 1
				if retries == 0 {
					return nil, errors.New(fmt.Sprintf("error in parsing JSON from alienvault: %s", err.Error()))
				}
			} else {
				break
			}
		}
		for _, url := range o.URLList {
			urls = append(urls, url.URL)
		}
		if !o.HasNext {
			break
		}
		page++
	}
	return urls, nil
}
func getWaybackUrls(hostname string) ([]string, error) {
	wildcard := "*."
	var waybackresp [][]string
	if !IncludeSubs {
		wildcard = ""
	}
	retries := MaxRetries
	var found []string
	for retries > 0 {
		tg := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey&fl=original", wildcard, hostname)
		r, err := client.Get(tg)
		if err != nil {
			retries -= 1
			if retries == 0 {
				return nil, errors.New(fmt.Sprintf("http request to web.archive.org failed: %s", err.Error()))
			}
		}
		defer r.Body.Close()
		resp, err := ioutil.ReadAll(r.Body)
		if err != nil {
			retries -= 1
			if retries == 0 {
				return nil, errors.New(fmt.Sprintf("error reading body: %s", err.Error()))
			}
		}
		err = json.Unmarshal(resp, &waybackresp)
		if err != nil {
			retries -= 1
			if retries == 0 {
				return nil, errors.New(fmt.Sprintf("could not decoding response from wayback machine: %s", err.Error()))
			}
		} else {
			break
		}
	}
	first := true
	for _, result := range waybackresp {
		if first {
			// skip first result from wayback machine
			// always is "original"
			first = false
			continue
		}
		found = append(found, result[0])
	}
	return found, nil
}
func getCommonCrawlURLs(domain string) ([]string, error) {
	var found []string
	wildcard := "*."
	if !IncludeSubs {
		wildcard = ""
	}
	currentApi, err := getCurrentCC()
	if err != nil {
		return nil, fmt.Errorf("error getting current commoncrawl url: %v", err)
	}
	var res = &http.Response{}
	retries := MaxRetries
	for retries > 0 {
		res, err = http.Get(
			fmt.Sprintf("%s?url=%s%s/*&output=json", currentApi, wildcard, domain),
		)
		if err != nil {
			retries -= 1
			if retries == 0 {
				return nil, err
			}
		} else {
			break
		}
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	for sc.Scan() {
		wrapper := struct {
			URL string `json:"url"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)

		if err != nil {
			continue
		}

		found = append(found, wrapper.URL)
	}
	return found, nil
}
func getCurrentCC() (string, error) {
	r, err := client.Get("http://index.commoncrawl.org/collinfo.json")
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	resp, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	wrapper := []struct {
		API string `json:"cdx-api"`
	}{}
	err = json.Unmarshal(resp, &wrapper)
	if err != nil {
		return "", fmt.Errorf("could not unmarshal json from CC: %s", err.Error())
	}
	if len(wrapper) < 1 {
		return "", errors.New("unexpected response from commoncrawl.")
	}
	return wrapper[0].API, nil
}

func HttpCode(url string) (x string){
	baseHost := url
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 3 * time.Second,
	}
	res, err := client.Get(baseHost)
	if err != nil {
		return ""
	}
	if res.StatusCode != 301 && res.StatusCode != 302 && res.StatusCode != 303 && res.StatusCode != 304 {
		k :=fmt.Sprintf("%s %d len:%d",url,res.StatusCode,res.ContentLength)
		return k
	}
	g := fmt.Sprintf("%s %d  %s len:%d",url,res.StatusCode,res.Header.Get("Location"),res.ContentLength)
	return g
}

func UrlPath(x string) (w bool) {
	u, err := url.Parse(x)
	if err != nil {
		return false
	}
	if !(strings.HasSuffix(u.Path,".jpg")) && !(strings.HasSuffix(u.Path,".css")) && !(strings.HasSuffix(u.Path,".svg")) && !(strings.HasSuffix(u.Path,".png")) && !(strings.HasSuffix(u.Path,".gif")){
		return false
	}else {
		return true
	}
}
