package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

type datadogTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

type datadogAPIKeyAttributes struct {
	CreatedAt  string `json:"created_at"`
	Key        string `json:"key"`
	Last4      string `json:"last4"`
	ModifiedAt string `json:"modified_at"`
	Name       string `json:"name"`
}

type datadogAPIKeyData struct {
	Type       string                  `json:"type"`
	Attributes datadogAPIKeyAttributes `json:"attributes"`
}

type datadogAPIKeyRespone struct {
	Data datadogAPIKeyData `json:"data"`
}

const (
	redirectURI = "http://localhost:8084/datadog_callback"

	datadogAuthorizeEndpoint = "https://app.datadoghq.com/oauth2/v1/authorize"
	datadogTokenEndpoint     = "https://api.datadoghq.com/oauth2/v1/token"
	datadogAPIKeyEndpoint    = "https://api.datadoghq.com/api/v2/api_keys/marketplace"
)

var (
	ddClientID          = os.Getenv("DD_CLIENT_ID")
	ddClientSecret      = os.Getenv("DD_CLIENT_SECRET")
	challenge, verifier = challengeAndVerifier()
)

func main() {
	if ddClientID == "" || ddClientSecret == "" {
		log.Fatal("DD_CLIENT_ID and DD_CLIENT_SECRET must be set")
	}

	router := &httprouter.Router{}
	router.GET("/datadog_callback", handleDatadogCallback)

	server := &http.Server{
		Addr:    ":8084",
		Handler: router,
	}

	fmt.Println("Open this URL in your browser:")
	fmt.Printf("  %s\n", datadogAuthorizeURI())

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err.Error())
	}

}

func handleDatadogCallback(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	fmt.Println("\nReceived request at /datadog_callback")
	fmt.Printf("  %s\n", req.URL)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/text")

	code := req.URL.Query().Get("code")
	if code == "" {
		log.Fatal("missing datadog code param")
	}
	clientID := req.URL.Query().Get("client_id")
	if clientID == "" {
		log.Fatal("missing datadog client_id param")
	}
	site := req.URL.Query().Get("site")
	if site == "" {
		log.Fatal("missing datadog site param")
	}

	// TODO: Is dd_oid a unique (and durable) identifier for the OAuth user's org?
	ddOrgID := req.URL.Query().Get("dd_oid")
	if ddOrgID == "" {
		log.Fatal("missing datadog dd_oid param")
	}
	ddOrgName := req.URL.Query().Get("dd_org_name")
	if ddOrgName == "" {
		log.Fatal("missing datadog dd_org_name param")
	}

	fmt.Println("\nReceived Datadog callback")
	fmt.Printf("  dd_org_name: %s\n", ddOrgName)
	fmt.Printf("  dd_oid:      %s\n", ddOrgID)
	fmt.Printf("  site:        %s\n", site)

	fmt.Fprintf(w, "Received Datadog callback\n")
	fmt.Fprintf(w, "  dd_org_name: %s\n", ddOrgName)
	fmt.Fprintf(w, "  dd_oid:      %s\n", ddOrgID)
	fmt.Fprintf(w, "  site:        %s\n", site)

	// exchange the code for an access token

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", ddClientID)
	data.Set("client_secret", ddClientSecret)
	data.Set("redirect_uri", redirectURI)
	data.Set("code_verifier", verifier)
	data.Set("code", code)

	req, err := http.NewRequest(
		http.MethodPost, datadogTokenEndpoint, strings.NewReader(data.Encode()),
	)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	rsp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			log.Fatal(err)
		}

		err = fmt.Errorf("datadog token endpoint returned %d: %s", rsp.StatusCode, string(body))
		log.Fatal(err)
	}

	var ddTokenRsp datadogTokenResponse
	err = json.NewDecoder(rsp.Body).Decode(&ddTokenRsp)
	if err != nil {
		log.Fatal(err)
	}

	req, err = http.NewRequest(http.MethodPost, datadogAPIKeyEndpoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", ddTokenRsp.AccessToken))

	rsp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			log.Fatal(err)
		}

		err = fmt.Errorf("datadog api key endpoint returned %d: %s", rsp.StatusCode, string(body))
		log.Fatal(err)
	}

	var ddAPIKeyRsp datadogAPIKeyRespone
	err = json.NewDecoder(rsp.Body).Decode(&ddAPIKeyRsp)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: How to programmatically delete this API key later on?
	//
	// This always creates a key with a name format as:
	// [OAuth Client Name] OAuth Client API Key XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	//
	// This causes a 409 "An API key with this name already exists" error if the
	// user goes through this flow again.
	//
	// The only way we can see to delete the API key is for the user to manually
	// delete it at:
	// https://app.datadoghq.com/organization-settings/api-keys
	//
	// I can only see how to validate it programmatically via:
	// https://docs.datadoghq.com/api/latest/authentication
	apiKey := ddAPIKeyRsp.Data.Attributes.Key
	if apiKey == "" {
		log.Fatal(err)
	}
	refreshToken := ddTokenRsp.RefreshToken
	if refreshToken == "" {
		log.Fatal(err)
	}

	fmt.Printf("\nSuccessful call to %s\n", datadogAPIKeyEndpoint)
	fmt.Printf("  apiKey:       %s\n", apiKey)
	fmt.Printf("  refreshToken: %s\n", refreshToken)

	fmt.Fprintf(w, "\nSuccessful call to %s\n", datadogAPIKeyEndpoint)
	fmt.Fprintf(w, "  apiKey:       %s\n", apiKey)
	fmt.Fprintf(w, "  refreshToken: %s\n", refreshToken)

	// create Datadog API clients
	configuration := datadog.NewConfiguration()
	apiClient := datadog.NewAPIClient(configuration)

	events := datadogV1.NewEventsApi(apiClient)
	monitors := datadogV1.NewMonitorsApi(apiClient)

	// events were not always showing up in the Datadog UI without this sleep
	fmt.Println("\nSleeping for 5 seconds before creating event...")
	time.Sleep(5 * time.Second)

	// create a test event and test monitor

	ctx := ddCtx(context.Background(), site, apiKey)

	err = createEvent(ddCtx(ctx, site, apiKey), events)
	if err != nil {
		log.Fatal(err)
	}

	ctx = ddCtx(context.Background(), site, apiKey)
	err = createMonitor(ctx, monitors)
	if err != nil {
		log.Fatal(err)
	}
}

func ddCtx(ctx context.Context, site, apiKey string) context.Context {
	// TODO: Is it correct/advisable to map the site string returned by
	// /datadog_callback to the ContextServerVariables site param in this way?
	siteMap := map[string]string{
		"https://app.datadoghq.com": "datadoghq.com",
		"https://us3.datadoghq.com": "us3.datadoghq.com",
		"https://us5.datadoghq.com": "us5.datadoghq.com",
		"https://app.datadoghq.eu":  "datadoghq.eu",
		"https://app.ddog-gov.com":  "ddog-gov.com",
	}

	siteParam := siteMap[site]

	ctx = context.WithValue(
		ctx,
		datadog.ContextServerVariables,
		map[string]string{"site": siteParam},
	)

	return context.WithValue(
		ctx,
		datadog.ContextAPIKeys,
		map[string]datadog.APIKey{
			"apiKeyAuth": {
				Key: apiKey,
			},
		},
	)
}

func createEvent(ctx context.Context, events *datadogV1.EventsApi) error {
	alertType := datadogV1.EVENTALERTTYPE_INFO
	t := time.Now().Unix()
	deviceName := "ddtest_device"
	pri := datadogV1.EVENTPRIORITY_NORMAL
	host := "ddtest_host"
	sourceTypeName := "kubernetes"

	body := datadogV1.EventCreateRequest{
		AlertType:      &alertType,
		DateHappened:   &t,
		DeviceName:     &deviceName,
		Host:           &host,
		Priority:       *datadogV1.NewNullableEventPriority(&pri),
		SourceTypeName: &sourceTypeName,
		Text:           "ddtest event text",
		Title:          "ddtest event title",
	}

	resp, _, err := events.CreateEvent(ctx, body)
	if err != nil {
		return err
	}

	responseContent, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println("\nResponse from `EventsApi.CreateEvent`")
	fmt.Printf("  %s\n", responseContent)

	return nil
}

func createMonitor(ctx context.Context, monitors *datadogV1.MonitorsApi) error {
	created := time.Now()
	message := "ddtest monitor message"
	name := "ddtest monitor name"
	overallState := datadogV1.MONITOROVERALLSTATES_ALERT
	priority := int64(3)

	creatorEmail := "ddtest@example.com"
	creatorHandle := "ddtest handle"
	creatorName := "dd creator name"
	creator := &datadogV1.Creator{
		Email:  &creatorEmail,
		Handle: &creatorHandle,
		Name:   *datadog.NewNullableString(&creatorName),
	}

	monitorBody := datadogV1.Monitor{
		Created:         &created,
		Creator:         creator,
		Message:         &message,
		Name:            &name,
		Options:         &datadogV1.MonitorOptions{},
		OverallState:    &overallState,
		Priority:        *datadog.NewNullableInt64(&priority),
		Query:           "test-monitor-query",
		RestrictedRoles: []string{},
		State:           datadogV1.NewMonitorState(),
		Type:            datadogV1.MONITORTYPE_EVENT_ALERT,
	}
	monitorResp, r, err := monitors.CreateMonitor(ctx, monitorBody)
	if err != nil {
		// TODO: Why does creating monitors always fail with a 403, while event
		// creation works?
		fmt.Printf("\nError when calling `MonitorsApi.CreateMonitor`: %s\n", err)
		fmt.Printf("Full HTTP response: %+v\n", r)
		return err
	}
	fmt.Printf("Response from `MonitorsApi.CreateMonitor`: %v", monitorResp)

	return nil
}

func challengeAndVerifier() (string, string) {
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		log.Fatal(err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(secretBytes)
	b := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(b[:])

	return challenge, verifier
}

func datadogAuthorizeURI() string {
	u, _ := url.Parse(datadogAuthorizeEndpoint)
	params := url.Values{
		"redirect_uri":          {redirectURI},
		"client_id":             {ddClientID},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	u.RawQuery = params.Encode()
	return u.String()
}
