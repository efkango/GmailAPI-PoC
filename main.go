package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

const (
	credentials   = "environments/credentials.json"
	tokenFile     = "token.json"
	targetKeyword = "makromusic"
)

func getOAuthConfig() *oauth2.Config {
	credentialsFile := os.Getenv(credentials)
	if credentialsFile == "" {
		credentialsFile = "environments/credentials.json"
	}

	creds, err := os.ReadFile(credentialsFile)
	if err != nil {
		log.Fatalf("Credentials file not readable err %v", err)
	}

	config, err := google.ConfigFromJSON(
		creds,
		gmail.GmailReadonlyScope,
		gmail.GmailModifyScope,
		gmail.GmailSendScope,
	)
	if err != nil {
		log.Fatalf("OAuth config not created err%v", err)
	}
	return config
}

func getToken(config *oauth2.Config) *oauth2.Token {
	if _, err := os.Stat(tokenFile); err == nil {
		token, err := loadToken(tokenFile)
		if err == nil {
			return token
		}
	}

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Open this URL and give the access code \n%v\n", authURL)

	var authCode string
	fmt.Print("Access Code: ")
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Code not readable %v", err)
	}

	token, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Token err %v", err)
	}

	saveToken(tokenFile, token)
	return token
}

func loadToken(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func saveToken(file string, token *oauth2.Token) {
	f, err := os.Create(file)
	if err != nil {
		log.Fatalf("Token file not created %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func processEmails(service *gmail.Service) error {
	messages, err := service.Users.Messages.List("me").Q("is:unread").Do()
	if err != nil {
		return fmt.Errorf("messages are not readable %v", err)
	}

	if len(messages.Messages) == 0 {
		log.Println("no any mails")
		return nil
	}

	for _, msg := range messages.Messages {
		email, err := service.Users.Messages.Get("me", msg.Id).Format("full").Do()
		if err != nil {
			log.Printf("%s Id message not get %v", msg.Id, err)
			continue
		}

		if shouldReply(email) {
			log.Printf("'%s'keyword founded sending...", targetKeyword)
			if err := sendReply(service, email); err != nil {
				log.Printf("%s Id of message not posted %v", msg.Id, err)
				continue
			}
			log.Printf("%s Id of message sended message", msg.Id)
			markAsRead(service, msg.Id)
		}
	}
	return nil
}

func shouldReply(email *gmail.Message) bool {
	body := decodeEmail(email)
	return strings.Contains(strings.ToLower(body), strings.ToLower(targetKeyword))
}

func decodeEmail(email *gmail.Message) string {
	var body string

	if email.Payload.Body != nil && email.Payload.Body.Data != "" {
		data, err := base64.URLEncoding.DecodeString(email.Payload.Body.Data)
		if err == nil {
			return string(data)
		}
	}

	if email.Payload.Parts != nil {
		for _, part := range email.Payload.Parts {
			if part.MimeType == "text/plain" && part.Body != nil {
				data, err := base64.URLEncoding.DecodeString(part.Body.Data)
				if err != nil {
					log.Printf("Body decode err %v", err)
					continue
				}
				body += string(data)
			}
		}
	}

	return body
}

func sendReply(service *gmail.Service, email *gmail.Message) error {
	var from string
	var subject string

	for _, header := range email.Payload.Headers {
		if header.Name == "From" {
			from = header.Value
		}
		if header.Name == "Subject" {
			subject = header.Value
		}
	}

	// mail format
	messageStr := fmt.Sprintf(
		"From: me\r\n"+
			"To: %s\r\n"+
			"Subject: Re: %s\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n\r\n"+
			"Merhaba,\n\n"+
			"Mesajınızı aldık. 'makromusic' ile ilgili talebiniz en kısa sürede incelenecektir.\n\n"+
			"Teşekkürler,\n"+
			"makromusic ekibi",
		from, // Gönderenin mail adresi direkt kullanılıyor
		subject,
	)

	message := &gmail.Message{
		Raw:      base64.URLEncoding.EncodeToString([]byte(messageStr)),
		ThreadId: email.ThreadId,
	}

	_, err := service.Users.Messages.Send("me", message).Do()
	return err
}

func markAsRead(service *gmail.Service, messageID string) {
	_, err := service.Users.Messages.Modify("me", messageID, &gmail.ModifyMessageRequest{
		RemoveLabelIds: []string{"UNREAD"},
	}).Do()
	if err != nil {
		fmt.Println("err")
	}
}

func main() {
	ctx := context.Background()
	config := getOAuthConfig()

	fmt.Println("Gmail OAuth process...")
	token := getToken(config)

	fmt.Println("Gmail service...")
	service, err := gmail.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
	if err != nil {
		log.Fatalf("Gmail service error %v", err)
	}

	fmt.Println("Email process starts")
	if err := processEmails(service); err != nil {
		log.Fatalf("Email process err %v", err)
	}

	fmt.Println("Email processing completed successfully")
}
