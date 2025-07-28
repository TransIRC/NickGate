package nickserv

import (
        "bytes"
        "encoding/json"
        "fmt"
        "net/http"
        "time"
)

// AuthClient handles authentication with the Ergo API
type AuthClient struct {
        apiURL      string
        registerURL string // new field for registration endpoint
        token       string
        client      *http.Client
        userAgent   string
}

// NewAuthClient creates a new NickServ authentication client
func NewAuthClient(apiURL, registerURL, token string) *AuthClient {
        return &AuthClient{
                apiURL:      apiURL,
                registerURL: registerURL,
                token:       token,
                client: &http.Client{
                        Timeout: 10 * time.Second,
                },
                userAgent: "NickGate/1.0",
        }
}

// AuthRequest represents the authentication request payload
type AuthRequest struct {
        AccountName string `json:"accountName"`
        Passphrase  string `json:"passphrase"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
        Success bool   `json:"success"`
        Message string `json:"message,omitempty"`
}

// SARegisterRequest represents the registration request payload
type SARegisterRequest struct {
        AccountName string `json:"accountName"`
        Passphrase  string `json:"passphrase"`
}

// SARegisterResponse represents the registration response
type SARegisterResponse struct {
        Success   bool   `json:"success"`
        ErrorCode string `json:"errorCode,omitempty"`
        Error     string `json:"error,omitempty"`
}

// Authenticate verifies credentials with Ergo API
func (a *AuthClient) Authenticate(accountName, passphrase string) (bool, error) {
        reqBody := AuthRequest{
                AccountName: accountName,
                Passphrase:  passphrase,
        }

        jsonData, err := json.Marshal(reqBody)
        if err != nil {
                return false, fmt.Errorf("failed to marshal request: %w", err)
        }

        req, err := http.NewRequest("POST", a.apiURL, bytes.NewBuffer(jsonData))
        if err != nil {
                return false, fmt.Errorf("failed to create request: %w", err)
        }

        req.Header.Set("Authorization", "Bearer "+a.token)
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("User-Agent", a.userAgent)

        resp, err := a.client.Do(req)
        if err != nil {
                return false, fmt.Errorf("request to NickServ API failed: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                // If auth fails because the account doesn't exist, this is not an error condition for us
                if resp.StatusCode == http.StatusNotFound {
                        return false, nil
                }
                return false, fmt.Errorf("NickServ API returned status %d", resp.StatusCode)
        }

        var authResp AuthResponse
        if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
                return false, fmt.Errorf("failed to decode NickServ response: %w", err)
        }

        return authResp.Success, nil
}

// Register creates a new account via the Ergo API
func (a *AuthClient) Register(accountName, passphrase string) (bool, error) {
        if a.registerURL == "" {
                return false, fmt.Errorf("registration endpoint not configured")
        }

        reqBody := SARegisterRequest{
                AccountName: accountName,
                Passphrase:  passphrase,
        }

        jsonData, err := json.Marshal(reqBody)
        if err != nil {
                return false, fmt.Errorf("failed to marshal registration request: %w", err)
        }

        req, err := http.NewRequest("POST", a.registerURL, bytes.NewBuffer(jsonData))
        if err != nil {
                return false, fmt.Errorf("failed to create registration request: %w", err)
        }

        req.Header.Set("Authorization", "Bearer "+a.token)
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("User-Agent", a.userAgent)

        resp, err := a.client.Do(req)
        if err != nil {
                return false, fmt.Errorf("request to registration API failed: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                return false, fmt.Errorf("registration API returned status %d", resp.StatusCode)
        }

        var regResp SARegisterResponse
        if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
                return false, fmt.Errorf("failed to decode registration response: %w", err)
        }

        if !regResp.Success {
                return false, fmt.Errorf("registration failed: %s (code: %s)", regResp.Error, regResp.ErrorCode)
        }

        return regResp.Success, nil
}

// Ping checks if the Ergo API is reachable
func (a *AuthClient) Ping() error {
        req, err := http.NewRequest("HEAD", a.apiURL, nil)
        if err != nil {
                return fmt.Errorf("failed to create ping request: %w", err)
        }

        req.Header.Set("Authorization", "Bearer "+a.token)
        req.Header.Set("User-Agent", a.userAgent)

        resp, err := a.client.Do(req)
        if err != nil {
                return fmt.Errorf("ping to NickServ API failed: %w", err)
        }
        resp.Body.Close()

        if resp.StatusCode >= 400 {
                return fmt.Errorf("NickServ API returned status %d", resp.StatusCode)
        }

        return nil
}