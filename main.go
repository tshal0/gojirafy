package main

import (
	"crypto/rsa"
	"crypto/x509"
	_ "database/sql"

	"app/db"
	"encoding/pem"
	"github.com/andygrunwald/go-jira"
	"github.com/dghubble/oauth1"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/net/context"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"net/http"
	"strings"
	// "time"
)

var (
	jiraURL = kingpin.Flag("jira-url", "JIRA Instance to use").Default("http://localhost:8080/").URL()
)

/*
	$ openssl genrsa -out jira.pem 1024
	$ openssl rsa -in jira.pem -pubout -out jira.pub
*/
const jiraPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC2A65MSSK2l21HSpN+8xslAcaXFV5WeB6UGyQGgF55CzciOJmu
12pozAQ99iQaTs7RsJIX+ZLKtjFFI0mq5P7CPtCCrSgvNKttKupFunoU1XoPMGWn
u+id6l/8vJc9WDijxA5SDgGLb2EOttuGcUTE/hcaOmHSVl8rpRRRRwpDTQIDAQAB
AoGBAJzG+uEWteHU+PnJUNaujBkKOIZ2j3WnrZ8g6Zz4AWf9sxW07xtczXlLEfRV
Ca/nZdnUX2JrRHd7C2FkDdY3vP8a01/7UXYvLPlX4ufXE7fdCNk8M0gM56E84bqt
YyMXcx6xK2aPYc6PnKQH1h1n4HO1m9399Qyr52obV+HwlzS5AkEA57Osvtj027L1
ooX43U6omtZ5lUXxw+AX0Qzm3URm/BzTS9+6Z1NcBzOv4e3y96WWu6NO593fKZQ8
vvEt0+BVowJBAMkaFXQvUBzShAuiGGBHMNXgn8TFViJ7cuU9iYS+GxI96GBowBKJ
824KQMyE/l+zUWMmyGu1A/7Vsv9Xv2DyMk8CQHBK4gO0ficj+mwD5fLLtmckXtR7
i4pUxvYn/JNsHUU+ayEwktSUz9slr64ddk2TURQrN4ikPQ2XrEEV/hHbfWUCQBs+
1G9ERbdR8h/dWy4YFw6y+xJepffP/9X9C1eXpfVHu+br6jHYzMk4zGSpFAmFMt6b
D4ZAJQVukGy1x7Drv1MCQAnOcXErk+xJlmgiiWcv6A2WjPpGqzwB3uAZ8qr3zEn4
bu2xqxGzZOzCCyT6DIma9ZQ9tZHnkmpc+wmpdRfK9B4=
-----END RSA PRIVATE KEY-----`

const jiraConsumerKey = "gojirakey"

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

var dbContext *db.DB

func handleJiraLogin(w http.ResponseWriter, r *http.Request) {
	requestToken, requestSecret, err := config.RequestToken()
	log.Println(requestSecret)
	authorizationURL, err := config.AuthorizationURL(requestToken)
	if err != nil {
		log.Fatalf("Unable to get authorization url. %v", err)
	}
	log.Println(authorizationURL.String())
	http.Redirect(w, r, authorizationURL.String(), http.StatusTemporaryRedirect)
}
func handleJiraCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// session, _ := store.Get(r, "cookie-name")

	_, requestSecret, err := config.RequestToken()
	if err != nil {
		log.Fatal(err)
	}
	oauthToken := r.URL.Query().Get("oauth_token")
	oauthVerifier := r.URL.Query().Get("oauth_verifier")

	accessToken, accessSecret, err := config.AccessToken(oauthToken, requestSecret, oauthVerifier)
	tok := oauth1.NewToken(accessToken, accessSecret)

	client := config.Client(ctx, tok)
	log.Println("DbContext:")
	log.Println(dbContext)
	env := &db.Env{Context: dbContext}

	env.Context.SetAccessToken(1, accessToken)
	// http.SetCookie(w, &http.Cookie{
	// 	Name:    "session_token",
	// 	Value:   tok,
	// 	Expires: time.Now().Add(120 * time.Second),
	// })

	jiraClient, err := jira.NewClient(client, "http://localhost:8080")

	i := jira.Issue{
		Fields: &jira.IssueFields{
			Description: "Test Issue",
			Type: jira.IssueType{
				Name: "Bug",
			},
			Project: jira.Project{
				Key: "VAL",
			},
			Summary: "Just a demo issue THREE",
		},
	}
	_, _, err = jiraClient.Issue.Create(&i)

	log.Println(err)

}
func privateKey() *rsa.PrivateKey {
	keyDERBlock, _ := pem.Decode([]byte(jiraPrivateKey))

	if keyDERBlock == nil {
		log.Fatal("unable to decode key PEM block")
	}
	if !(keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY")) {
		log.Fatalf("unexpected key DER block type: %s", keyDERBlock.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		log.Fatalf("unable to parse PKCS1 private key. %v", err)
	}
	return privateKey
}

var (
	config = oauth1.Config{
		ConsumerKey: jiraConsumerKey,
		CallbackURL: "http://localhost:9090/JiraCallback", /* for command line usage */
		Endpoint: oauth1.Endpoint{
			RequestTokenURL: "http://localhost:8080/plugins/servlet/oauth/request-token",
			AuthorizeURL:    "http://localhost:8080/plugins/servlet/oauth/authorize",
			AccessTokenURL:  "http://localhost:8080/plugins/servlet/oauth/access-token",
		},
		Signer: &oauth1.RSASigner{
			PrivateKey: privateKey(),
		},
	}
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// c, err := r.Cookie("session_token")
	// if err != nil {
	// 	if err == http.ErrNoCookie {
	// 		w.WriteHeader(http.StatusUnauthorized)
	// 		return
	// 	}
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }
	// sessionToken := c.Value

}

func main() {

	var err error
	dbContext, err = db.InitDB("")
	if err != nil {
		log.Println(err.Error())
	}
	env := &db.Env{Context: dbContext}
	log.Println("Get Users")
	users, err := env.Context.Users()

	for _, usr := range users {
		log.Printf("%d | %s | \n", usr.UserID, usr.AccessToken)
	}
	r := mux.NewRouter()

	r.HandleFunc("/", handleJiraLogin)
	r.HandleFunc("/JiraLogin", handleJiraLogin)
	r.HandleFunc("/JiraCallback", handleJiraCallback)
	if err := http.ListenAndServe(":9090", r); err != nil {
		panic(err)
	}

}
