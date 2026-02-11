package saml2aws

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

// AWSAccount holds the AWS account name and roles
type AWSAccount struct {
	Name  string
	Roles []*AWSRole
}

// ParseAWSAccounts extract the aws accounts from the saml assertion
func ParseAWSAccounts(audience string, samlAssertion string) ([]*AWSAccount, error) {
	// log.Println("=== DEBUG ParseAWSAccounts ===")
	// log.Printf("Posting to audience: %s", audience)
	// log.Printf("SAML assertion length: %d", len(samlAssertion))

	res, err := http.PostForm(audience, url.Values{"SAMLResponse": {samlAssertion}})
	if err != nil {
		log.Printf("ERROR: http.PostForm failed: %v", err)
		return nil, errors.Wrap(err, "error retrieving AWS login form")
	}
	defer res.Body.Close()

	log.Printf("Response status: %s", res.Status)
	log.Printf("Response headers: %v", res.Header)

	data, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("ERROR: reading response body failed: %v", err)
		return nil, errors.Wrap(err, "error retrieving AWS login body")
	}

	// log.Printf("Response body length: %d bytes", len(data))
	// log.Println(string(data))
	// log.Println("First 500 chars of response:")
	// if len(data) > 500 {
	// 	log.Println(string(data[:500]))
	// } else {
	// 	log.Println(string(data))
	// }
	log.Println("=== END DEBUG ParseAWSAccounts ===")

	return ExtractAWSAccounts(data)
}

// ExtractAWSAccounts extract the accounts from the AWS html page
func ExtractAWSAccounts(data []byte) ([]*AWSAccount, error) {
	log.Println("=== DEBUG ExtractAWSAccounts ===")
	accounts := []*AWSAccount{}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		log.Printf("ERROR: failed to build document: %v", err)
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	log.Println("Searching for fieldset > div.saml-account elements...")
	foundCount := 0
	doc.Find("fieldset > div.saml-account").Each(func(i int, s *goquery.Selection) {
		foundCount++
		account := new(AWSAccount)
		account.Name = s.Find("div.saml-account-name").Text()
		log.Printf("Found account %d: %s", i, account.Name)

		roleCount := 0
		s.Find("label").Each(func(i int, s *goquery.Selection) {
			role := new(AWSRole)
			role.Name = s.Text()
			role.RoleARN, _ = s.Attr("for")
			log.Printf("  Role %d: %s (ARN: %s)", i, role.Name, role.RoleARN)
			account.Roles = append(account.Roles, role)
			roleCount++
		})
		log.Printf("Account has %d roles", roleCount)
		accounts = append(accounts, account)
	})

	log.Printf("Found %d total accounts with saml-account class", foundCount)
	log.Println("=== END DEBUG ExtractAWSAccounts ===")

	return accounts, nil
}

// AssignPrincipals assign principal from roles
func AssignPrincipals(awsRoles []*AWSRole, awsAccounts []*AWSAccount) {

	awsPrincipalARNs := make(map[string]string)
	for _, awsRole := range awsRoles {
		awsPrincipalARNs[awsRole.RoleARN] = awsRole.PrincipalARN
	}

	for _, awsAccount := range awsAccounts {
		for _, awsRole := range awsAccount.Roles {
			awsRole.PrincipalARN = awsPrincipalARNs[awsRole.RoleARN]
		}
	}

}

// LocateRole locate role by name
func LocateRole(awsRoles []*AWSRole, roleName string) (*AWSRole, error) {
	for _, awsRole := range awsRoles {
		if awsRole.RoleARN == roleName {
			return awsRole, nil
		}
	}

	return nil, fmt.Errorf("Supplied RoleArn not found in saml assertion: %s", roleName)
}
