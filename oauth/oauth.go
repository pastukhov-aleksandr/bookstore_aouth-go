package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/pastukhov-aleksandr/bookstore_utils-go/rest_errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

type AccessDetails struct {
	AccessUuid string
	UserId     uint64
}

type SicretCode struct {
	ACCESS_SECRET  string
	REFRESH_SECRET string
}

func GetSicretAccess() (*SicretCode, rest_errors.RestErr) {
	if err := godotenv.Load(); err != nil {
		log.Println(".env file not found")
		return nil, rest_errors.NewBadRequestError("invalid access token")
	}

	return &SicretCode{
		ACCESS_SECRET: getEnv(ACCESS_SECRET, ""),
		REFRESH_SECRET: getEnv(REFRESH_SECRET, "")
	}, nil
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) (int64, rest_errors.RestErr) {
	if request == nil {
		return 0, rest_errors.NewUnauthorizedError("unauthorized")
	}

	tokenAuth, err := extractTokenMetadata(request)
	if err != nil {
		return 0, rest_errors.NewUnauthorizedError("unauthorized")
	}

	// accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	// if accessTokenId == "" {
	// 	return nil
	// }

	// at, err := getAccessToken(accessTokenId)
	// if err != nil {
	// 	if err.Status() == http.StatusNotFound {
	// 		return nil
	// 	}
	// 	return err
	// }
	// request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	// request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	// return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid restclient response when trying to get access token",
			errors.New("network timeout"))
	}

	if response.StatusCode > 299 {
		restErr, err := rest_errors.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response",
			errors.New("error processing json"))
	}
	return &at, nil
}

func extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func verifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := extractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func tokenValid(r *http.Request) error {
	token, err := verifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func extractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := verifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, err
}
