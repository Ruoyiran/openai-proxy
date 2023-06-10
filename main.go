package main

import (
	"flag"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	"github.com/sevlyar/go-daemon"
	"io"
	"log"
	"os"
	"time"

	"github.com/Ruoyiran/endless"
	tlsclient "github.com/bogdanfinn/tls-client"

	"github.com/acheong08/OpenAIAuth/auth"
	"github.com/gin-gonic/gin"
)

type authStruct struct {
	OpenaiEmail    string `json:"openai_email"`
	OpenaiPassword string `json:"openai_password"`
}

var (
	jar     = tlsclient.NewCookieJar()
	options = []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(360),
		tlsclient.WithClientProfile(tlsclient.Safari_IOS_16_0),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithCookieJar(jar), // create cookieJar instance and pass it as argument
	}
	client, _      = tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	userAgent      = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
	httpProxy      = os.Getenv("http_proxy")
	authorizations authStruct
	damaen         = false
	port           = 8080
	host           = "0.0.0.0"
)

func admin(c *gin.Context) {
	if c.GetHeader("Authorization") != os.Getenv("PASSWORD") {
		c.String(401, "Unauthorized")
		c.Abort()
		return
	}
	c.Next()
}

func init() {
	flag.BoolVar(&damaen, "daemon", false, "running in daemon")
	flag.StringVar(&host, "host", "0.0.0.0", "server host")
	flag.IntVar(&port, "port", 8080, "server port")

	authorizations.OpenaiEmail = os.Getenv("OPENAI_EMAIL")
	authorizations.OpenaiPassword = os.Getenv("OPENAI_PASSWORD")
	if authorizations.OpenaiEmail != "" && authorizations.OpenaiPassword != "" {
		go func() {
			for {
				authenticator := auth.NewAuthenticator(authorizations.OpenaiEmail, authorizations.OpenaiPassword, httpProxy)
				err := authenticator.Begin()
				if err != nil {
					log.Println(err)
					break
				}
				puid, err := authenticator.GetPUID()
				if err != nil {
					break
				}
				_ = os.Setenv("OPENAI_PUID", puid)
				println(puid)
				time.Sleep(24 * time.Hour * 7)
			}
		}()
	}
}

func main() {
	flag.Parse()

	if httpProxy != "" {
		client.SetProxy(httpProxy)
		println("Proxy set:" + httpProxy)
	}

	handler := gin.Default()
	//handler.GET("/ping", func(c *gin.Context) {
	//	c.JSON(200, gin.H{"message": "pong"})
	//})
	//
	//handler.PATCH("/admin/puid", admin, func(c *gin.Context) {
	//	// Get the password from the request (json) and update the password
	//	type puidStruct struct {
	//		PUID string `json:"puid"`
	//	}
	//	var puid puidStruct
	//	err := c.BindJSON(&puid)
	//	if err != nil {
	//		c.String(400, "puid not provided")
	//		return
	//	}
	//	// Set environment variable
	//	_ = os.Setenv("OPENAI_PUID", puid.PUID)
	//	c.String(200, "puid updated")
	//})
	//handler.PATCH("/admin/password", admin, func(c *gin.Context) {
	//	// Get the password from the request (json) and update the password
	//	type password_struct struct {
	//		PASSWORD string `json:"password"`
	//	}
	//	var password password_struct
	//	err := c.BindJSON(&password)
	//	if err != nil {
	//		c.String(400, "password not provided")
	//		return
	//	}
	//	// Set environment variable
	//	_ = os.Setenv("PASSWORD", password.PASSWORD)
	//	c.String(200, "PASSWORD updated")
	//})
	//handler.PATCH("/admin/openai", admin, func(c *gin.Context) {
	//	err := c.BindJSON(&authorizations)
	//	if err != nil {
	//		c.JSON(400, gin.H{"error": "JSON invalid"})
	//	}
	//	_ = os.Setenv("OPENAI_EMAIL", authorizations.OpenaiEmail)
	//	_ = os.Setenv("OPENAI_PASSWORD", authorizations.OpenaiPassword)
	//})
	//
	//handler.Any("/api/*path", openAIProxy)
	handler.Any("/azure_openai/*path", azureOpenAIProxy)

	gin.SetMode(gin.ReleaseMode)

	log.Printf("[*] PID: %d PPID: %d ARG: %s\n", os.Getpid(), os.Getppid(), os.Args)
	if damaen {
		cntxt := &daemon.Context{
			PidFileName: "openai-proxy.pid",
			PidFilePerm: 0644,
			LogFileName: "openai-proxy.log",
			LogFilePerm: 0640,
			WorkDir:     "./",
			Umask:       027,
			Args:        flag.Args(),
		}

		d, err := cntxt.Reborn()
		if err != nil {
			log.Fatal("Unable to run: ", err)
		}
		if d != nil {
			return
		}
		defer cntxt.Release()

		log.Print("- - - - - - - - - - - - - - -")
		log.Print("daemon started")
	}
	log.Printf("[*] Forever running in PID: %d PPID: %d\n", os.Getpid(), os.Getppid())
	log.Printf("[*] Starting server at %s:%d\n", host, port)

	err := endless.ListenAndServe(fmt.Sprintf("%s:%d", host, port), handler)
	if err != nil {
		log.Fatal(err.Error())
	}
}

func openAIProxy(c *gin.Context) {
	// Remove _cfuvid cookie from session
	jar.SetCookies(c.Request.URL, []*http.Cookie{})

	var url string
	var err error
	var requestMethod string
	var request *http.Request
	var response *http.Response

	if c.Request.URL.RawQuery != "" {
		url = "https://chat.openai.com/backend-api" + c.Param("path") + "?" + c.Request.URL.RawQuery
	} else {
		url = "https://chat.openai.com/backend-api" + c.Param("path")
	}
	requestMethod = c.Request.Method

	request, err = http.NewRequest(requestMethod, url, c.Request.Body)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	request.Header.Set("Host", "chat.openai.com")
	request.Header.Set("Origin", "https://chat.openai.com/chat")
	request.Header.Set("Connection", "keep-alive")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Keep-Alive", "timeout=360")
	request.Header.Set("Authorization", c.Request.Header.Get("Authorization"))
	request.Header.Set("sec-ch-ua", "\"Chromium\";v=\"112\", \"Brave\";v=\"112\", \"Not:A-Brand\";v=\"99\"")
	request.Header.Set("sec-ch-ua-mobile", "?0")
	request.Header.Set("sec-ch-ua-platform", "\"Linux\"")
	request.Header.Set("sec-fetch-dest", "empty")
	request.Header.Set("sec-fetch-mode", "cors")
	request.Header.Set("sec-fetch-site", "same-origin")
	request.Header.Set("sec-gpc", "1")
	request.Header.Set("user-agent", userAgent)
	if os.Getenv("OPENAI_PUID") != "" {
		request.Header.Set("cookie", "_puid="+os.Getenv("OPENAI_PUID")+";")
	}

	response, err = client.Do(request)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer response.Body.Close()
	// Copy headers from response
	for k, v := range response.Header {
		c.Header(k, v[0])
	}
	// Get status code
	c.Status(response.StatusCode)

	buf := make([]byte, 4096)
	for {
		n, err := response.Body.Read(buf)
		if n > 0 {
			_, writeErr := c.Writer.Write(buf[:n])
			if writeErr != nil {
				log.Printf("Error writing to client: %v", writeErr)
				break
			}
			c.Writer.Flush() // flush buffer to make sure the data is sent to client in time.
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading from response body: %v", err)
			break
		}
	}
}

func azureOpenAIProxy(c *gin.Context) {
	// Remove _cfuvid cookie from session
	jar.SetCookies(c.Request.URL, []*http.Cookie{})

	var url string
	var err error
	var requestMethod string
	var request *http.Request
	var response *http.Response

	if c.Request.URL.RawQuery != "" {
		url = "https://ttgamestarkcontainerminiapkworker.openai.azure.com/openai" + c.Param("path") + "?" + c.Request.URL.RawQuery
	} else {
		url = "https://ttgamestarkcontainerminiapkworker.openai.azure.com/openai" + c.Param("path")
	}
	requestMethod = c.Request.Method

	request, err = http.NewRequest(requestMethod, url, c.Request.Body)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	request.Header.Set("Connection", "keep-alive")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Keep-Alive", "timeout=360")
	request.Header.Set("api-key", c.Request.Header.Get("api-key"))
	response, err = client.Do(request)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer response.Body.Close()
	// Copy headers from response
	for k, v := range response.Header {
		c.Header(k, v[0])
	}
	// Get status code
	c.Status(response.StatusCode)

	buf := make([]byte, 4096)
	for {
		n, err := response.Body.Read(buf)
		if n > 0 {
			_, writeErr := c.Writer.Write(buf[:n])
			if writeErr != nil {
				log.Printf("Error writing to client: %v", writeErr)
				break
			}
			c.Writer.Flush() // flush buffer to make sure the data is sent to client in time.
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading from response body: %v", err)
			break
		}
	}
}
