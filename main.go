package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bwmarrin/discordgo"
	"golang.org/x/exp/slices"
)

const endpointAccessToken = "https://discord.com/api/oauth2/token"

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type verifier struct {
	clientID     string
	clientSecret string
	redirectURI  string
	guildID      string
	roles        []string
}

func main() {
	clientID := os.Getenv("DISCORD_CLIENT_ID")
	if clientID == "" {
		log.Fatal("DISCORD_CLIENT_ID must be set")
	}

	clientSecret := os.Getenv("DISCORD_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("DISCORD_CLIENT_SECRET must be set")
	}

	redirectURI := os.Getenv("DISCORD_REDIRECT_URI")
	if redirectURI == "" {
		log.Fatal("DISCORD_REDIRECT_URI must be set")
	}

	guildID := os.Getenv("DISCORD_GUILD_ID")
	if guildID == "" {
		log.Fatal("DISCORD_GUILD_ID must be set")
	}

	roleList := os.Getenv("DISCORD_ROLE_LIST")
	if roleList == "" {
		log.Fatal("DISCORD_ROLE_LIST must be set")
	}

	v := &verifier{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		guildID:      guildID,
		roles:        strings.Split(roleList, ","),
	}

	log.Println("starting http server")
	if err := http.ListenAndServe(":8080", v); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func (v *verifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	oauthCode := r.URL.Query().Get("code")
	if oauthCode == "" {
		http.Error(w, "no oauth code found", http.StatusBadRequest)
		return
	}

	// state := r.URL.Query().Get("state")
	// if state == "" {
	// 	http.Error(w, "no state found", http.StatusBadRequest)
	// 	return
	// }
	// TODO: state validation

	resp, err := http.PostForm(endpointAccessToken, url.Values{
		"client_id":     {v.clientID},
		"client_secret": {v.clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {oauthCode},
		"redirect_uri":  {v.redirectURI},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := &tokenResponse{}
	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if data.AccessToken == "" {
		log.Printf("did not receive access token from discord: %s", data.ErrorDescription)
		http.Error(w, fmt.Sprintf("did not receive access token from discord: %s", data.ErrorDescription), http.StatusInternalServerError)
		return
	}

	client, err := discordgo.New(fmt.Sprintf("Bearer %s", data.AccessToken))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to initialize discord client: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	member, err := guildMember(client, v.guildID)
	if err != nil {
		log.Printf("failed to get user guilds: %s", err.Error())
		http.Error(w, fmt.Sprintf("failed to get user guilds: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/text")
	for _, r := range v.roles {
		if slices.Contains(member.Roles, r) {
			log.Printf("has %s", r)
			w.Write([]byte(r))
			return
		}
	}
}

func guildMember(s *discordgo.Session, guildID string) (*discordgo.Member, error) {
	result := &discordgo.Member{}
	url := fmt.Sprintf("%s/member", discordgo.EndpointUserGuild("@me", guildID))
	body, err := s.Request("GET", url, nil)
	if err != nil {
		return result, fmt.Errorf("failed to query discord: %w", err)
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	return result, nil
}
