package faroe

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Returns true if the password is sufficiently strong.
func verifyUserPasswordStrength(password string) (bool, error) {
	passwordHashBytes := sha1.Sum([]byte(password))
	passwordHash := hex.EncodeToString(passwordHashBytes[:])
	hashPrefix := passwordHash[0:5]
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", hashPrefix)
	res, err := http.DefaultClient.Get(url)
	if err != nil {
		return false, fmt.Errorf("failed to send post request to %s: %s", url, err.Error())
	}
	if res.StatusCode != 200 {
		return false, fmt.Errorf("received status code %d from %s", res.StatusCode, url)
	}
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		hashSuffix := strings.ToLower(scanner.Text()[:35])
		if passwordHash == hashPrefix+hashSuffix {
			return false, nil
		}
	}
	return true, nil
}

func verifyUserPasswordPattern(password string) bool {
	length := len([]rune(password))
	return length >= 10 && length <= 100
}
