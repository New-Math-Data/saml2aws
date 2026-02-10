package commands

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/samlcache"
)

// Login login to ADFS
func Login(loginFlags *flags.LoginExecFlags) error {
	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "Error building login details.")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile, account.CredentialsFile)
	// creates a cacheProvider, only used when --cache is set
	cacheProvider := &samlcache.SAMLCacheProvider{
		Account:  account.Name,
		Filename: account.SAMLCacheFile,
	}

	logger.Debug("Check if creds exist.")

	// this checks if the credentials file has been created yet
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "Error loading credentials.")
	}
	if !exist {
		log.Println("Unable to load credentials. Login required to create them.")
		return nil
	}

	if !sharedCreds.Expired() && !loginFlags.Force {
		logger.Debug("Credentials are not expired. Skipping.")
		previousCreds, err := sharedCreds.Load()
		if err != nil {
			log.Println("Unable to load cached credentials.")
		} else {
			logger.Debug("Credentials will expire at ", previousCreds.Expires)
		}
		if loginFlags.CredentialProcess {
			err = PrintCredentialProcess(previousCreds)
			if err != nil {
				return err
			}
		}
		return nil
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	logger.WithField("idpAccount", account).Debug("building provider")

	provider, err := saml2aws.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "Error building IdP client.")
	}

	err = provider.Validate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "Error validating login details.")
	}

	var samlAssertion string
	if account.SAMLCache {
		if cacheProvider.IsValid() {
			samlAssertion, err = cacheProvider.ReadRaw()
			if err != nil {
				return errors.Wrap(err, "Could not read SAML cache.")
			}
		} else {
			logger.Debug("Cache is invalid")
			log.Printf("Authenticating as %s ...", loginDetails.Username)
		}
	} else {
		log.Printf("Authenticating as %s ...", loginDetails.Username)
	}

	if samlAssertion == "" {
		// samlAssertion was not cached
		samlAssertion, err = provider.Authenticate(loginDetails)
		if err != nil {
			return errors.Wrap(err, "Error authenticating to IdP.")
		}
		if account.SAMLCache {
			err = cacheProvider.WriteRaw(samlAssertion)
			if err != nil {
				return errors.Wrap(err, "Could not write SAML cache.")
			}
		}
	}

	if samlAssertion == "" {
		log.Println("Response did not contain a valid SAML assertion.")
		log.Println("Please check that your username and password is correct.")
		log.Println("To see the output follow the instructions in https://github.com/versent/saml2aws#debugging-issues-with-idps")
		os.Exit(1)
	}

	// DEBUG: Print SAML assertion
	log.Println("=== SAML ASSERTION (base64) ===")
	log.Println(samlAssertion)
	log.Println("=== END SAML ASSERTION ===")

	// DEBUG: Print decoded SAML assertion
	if decoded, err := b64.StdEncoding.DecodeString(samlAssertion); err == nil {
		log.Println("=== SAML ASSERTION (decoded XML) ===")
		log.Println(string(decoded))
		log.Println("=== END DECODED SAML ASSERTION ===")
	}

	// Fix role/provider order in SAML assertion
	samlAssertion, err = fixRoleProviderOrder(samlAssertion)
	if err != nil {
		return errors.Wrap(err, "Error fixing role/provider order in SAML assertion.")
	}

	// Verify the fixed assertion is still valid base64
	log.Println("=== VERIFYING FIXED SAML ===")
	testDecode, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		log.Printf("ERROR: Fixed SAML is not valid base64: %v", err)
		return errors.Wrap(err, "Fixed SAML assertion is not valid base64")
	}
	log.Printf("Fixed SAML is valid base64, decoded length: %d bytes", len(testDecode))
	log.Println("First 200 chars of fixed XML:")
	if len(testDecode) > 200 {
		log.Println(string(testDecode[:200]))
	} else {
		log.Println(string(testDecode))
	}
	log.Println("=== END VERIFICATION ===")

	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
		if err != nil {
			return errors.Wrap(err, "Error storing password in keychain.")
		}
	}

	role, err := selectAwsRole(samlAssertion, account)
	if err != nil {
		return errors.Wrap(err, "Failed to assume role. Please check whether you are permitted to assume the given role for the AWS service.")
	}

	log.Println("Selected role:", role.RoleARN)

	awsCreds, err := loginToStsUsingRole(account, role, samlAssertion)
	if err != nil {
		return errors.Wrap(err, "Error logging into AWS role using SAML assertion.")
	}

	// print credential process if needed
	if loginFlags.CredentialProcess {
		err = PrintCredentialProcess(awsCreds)
		if err != nil {
			return err
		}
		// Check if a custom credential file is used
		customCredentialsFile, err := CustomCredentialsFile(sharedCreds.Filename)
		if err != nil {
			return err
		}
		// If a custom credential file is used then save credentials. This allows for autorefreshing of credentials, which is not supported with the default credential file. See https://github.com/Versent/saml2aws/issues/895
		if customCredentialsFile {
			err = saveCredentials(awsCreds, sharedCreds)
			if err != nil {
				return err
			}
		}
	} else {
		err = saveCredentials(awsCreds, sharedCreds)
		if err != nil {
			return err
		}

		log.Println("Logged in as:", awsCreds.PrincipalARN)
		log.Println("")
		log.Println("Your new access key pair has been stored in the AWS configuration.")
		log.Printf("Note that it will expire at %v", awsCreds.Expires)
		if sharedCreds.Profile != "default" {
			log.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", sharedCreds.Profile, "ec2 describe-instances).")
		}
	}

	return nil
}

func buildIdpAccount(loginFlags *flags.LoginExecFlags) (*cfg.IDPAccount, error) {
	cfgm, err := cfg.NewConfigManager(loginFlags.CommonFlags.ConfigFile)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load configuration.")
	}

	account, err := cfgm.LoadIDPAccount(loginFlags.CommonFlags.IdpAccount)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load IdP account.")
	}

	// update username and hostname if supplied
	flags.ApplyFlagOverrides(loginFlags.CommonFlags, account)

	err = account.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to validate account.")
	}

	return account, nil
}

func resolveLoginDetails(account *cfg.IDPAccount, loginFlags *flags.LoginExecFlags) (*creds.LoginDetails, error) {

	// log.Printf("loginFlags %+v", loginFlags)

	loginDetails := &creds.LoginDetails{URL: account.URL, Username: account.Username, MFAToken: loginFlags.CommonFlags.MFAToken, DuoMFAOption: loginFlags.DuoMFAOption}

	log.Printf("Using IdP Account %s to access %s %s", loginFlags.CommonFlags.IdpAccount, account.Provider, account.URL)

	var err error
	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.LookupCredentials(loginDetails, account.Provider)
		if err != nil {
			if !credentials.IsErrCredentialsNotFound(err) {
				return nil, errors.Wrap(err, "Error loading saved password.")
			}
		}
	} else { // if user disabled keychain, dont use Okta sessions & dont remember Okta MFA device
		if strings.ToLower(account.Provider) == "okta" {
			account.DisableSessions = true
			account.DisableRememberDevice = true
		}
	}

	// log.Printf("%s %s", savedUsername, savedPassword)

	// if you supply a username in a flag it takes precedence
	if loginFlags.CommonFlags.Username != "" {
		loginDetails.Username = loginFlags.CommonFlags.Username
	}

	// if you supply a password in a flag it takes precedence
	if loginFlags.CommonFlags.Password != "" {
		loginDetails.Password = loginFlags.CommonFlags.Password
	}

	// if you supply a cleint_id in a flag it takes precedence
	if loginFlags.CommonFlags.ClientID != "" {
		loginDetails.ClientID = loginFlags.CommonFlags.ClientID
	}

	// if you supply a client_secret in a flag it takes precedence
	if loginFlags.CommonFlags.ClientSecret != "" {
		loginDetails.ClientSecret = loginFlags.CommonFlags.ClientSecret
	}

	// if you supply an mfa_ip_address in a flag or an IDP account it takes precedence
	if account.MFAIPAddress != "" {
		loginDetails.MFAIPAddress = account.MFAIPAddress
	} else if loginFlags.CommonFlags.MFAIPAddress != "" {
		loginDetails.MFAIPAddress = loginFlags.CommonFlags.MFAIPAddress
	}

	if loginFlags.DownloadBrowser {
		loginDetails.DownloadBrowser = loginFlags.DownloadBrowser
	} else if account.DownloadBrowser {
		loginDetails.DownloadBrowser = account.DownloadBrowser
	}

	// parse KCBroker if set
	if account.KCBroker != "" {
		loginDetails.KCBroker = account.KCBroker
	}

	// log.Printf("loginDetails %+v", loginDetails)

	// if skip prompt was passed just pass back the flag values
	if loginFlags.CommonFlags.SkipPrompt || loginFlags.CredentialProcess {
		return loginDetails, nil
	}

	if loginFlags.TryNoPrompt && loginDetails.Username != "" && loginDetails.Password != "" {
		return loginDetails, nil
	}

	if account.Provider != "Shell" {
		err = saml2aws.PromptForLoginDetails(loginDetails, account.Provider)
		if err != nil {
			return nil, errors.Wrap(err, "Error occurred accepting input.")
		}
	}

	return loginDetails, nil
}

func selectAwsRole(samlAssertion string, account *cfg.IDPAccount) (*saml2aws.AWSRole, error) {
	data, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding SAML assertion.")
	}

	log.Println("=== DEBUG selectAwsRole ===")
	log.Printf("Decoded SAML length: %d bytes", len(data))

	roles, err := saml2aws.ExtractAwsRoles(data)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing AWS roles.")
	}

	log.Printf("Extracted %d role strings", len(roles))
	for i, role := range roles {
		log.Printf("Role %d: %s", i, role)
	}

	if len(roles) == 0 {
		log.Println("No roles to assume.")
		log.Println("Please check you are permitted to assume roles for the AWS service.")
		os.Exit(1)
	}

	awsRoles, err := saml2aws.ParseAWSRoles(roles)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing AWS roles.")
	}

	log.Printf("Parsed %d AWS roles", len(awsRoles))
	for i, role := range awsRoles {
		log.Printf("AWS Role %d: RoleARN=%s, PrincipalARN=%s", i, role.RoleARN, role.PrincipalARN)
	}
	log.Println("=== END DEBUG ===")

	return resolveRole(awsRoles, samlAssertion, account)
}

func resolveRole(awsRoles []*saml2aws.AWSRole, samlAssertion string, account *cfg.IDPAccount) (*saml2aws.AWSRole, error) {
	var role = new(saml2aws.AWSRole)

	if len(awsRoles) == 0 {
		return nil, errors.New("No roles available.")
	}

	// If a role ARN is specified, locate and return it directly without calling AWS UI
	if account.RoleARN != "" {
		return saml2aws.LocateRole(awsRoles, account.RoleARN)
	}

	// If there's only one role, return it directly
	if len(awsRoles) == 1 {
		return awsRoles[0], nil
	}

	// Multiple roles - try to get account info from AWS for better display
	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding SAML assertion.")
	}

	log.Println("=== DEBUG resolveRole ===")
	log.Printf("Decoding SAML for ParseAWSAccounts, length: %d", len(samlAssertionData))

	aud, err := saml2aws.ExtractDestinationURL(samlAssertionData)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing destination URL.")
	}

	log.Printf("Destination URL: %s", aud)

	awsAccounts, err := saml2aws.ParseAWSAccounts(aud, samlAssertion)
	if err != nil {
		log.Printf("Warning: Could not parse AWS accounts: %v", err)
		log.Println("Falling back to role-only selection")
		awsAccounts = nil
	}

	log.Printf("Parsed %d AWS accounts", len(awsAccounts))
	log.Println("=== END DEBUG ===")

	// If ParseAWSAccounts failed or returned no accounts, create simple accounts from roles
	if len(awsAccounts) == 0 {
		log.Println("Creating account list from roles directly")
		accountMap := make(map[string]*saml2aws.AWSAccount)

		for _, awsRole := range awsRoles {
			// Extract account ID from role ARN (arn:aws:iam::ACCOUNT:role/NAME)
			accountID := "Unknown"
			parts := strings.Split(awsRole.RoleARN, ":")
			if len(parts) >= 5 {
				accountID = parts[4]
			}

			if accountMap[accountID] == nil {
				accountMap[accountID] = &saml2aws.AWSAccount{
					Name:  accountID,
					Roles: []*saml2aws.AWSRole{},
				}
			}
			accountMap[accountID].Roles = append(accountMap[accountID].Roles, awsRole)
		}

		// Convert map to slice
		for _, acc := range accountMap {
			awsAccounts = append(awsAccounts, acc)
		}

		log.Printf("Created %d accounts from roles", len(awsAccounts))
	}

	saml2aws.AssignPrincipals(awsRoles, awsAccounts)

	for {
		role, err = saml2aws.PromptForAWSRoleSelection(awsAccounts)
		if err == nil {
			break
		}
		log.Println("Error selecting role. Try again.")
	}

	return role, nil
}

func loginToStsUsingRole(account *cfg.IDPAccount, role *saml2aws.AWSRole, samlAssertion string) (*awsconfig.AWSCredentials, error) {

	sess, err := session.NewSession(&aws.Config{
		Region: &account.Region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create session.")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlAssertion),     // Required
		DurationSeconds: aws.Int64(int64(account.SessionDuration)),
	}

	if account.PolicyFile != "" {
		policy, err := os.ReadFile(account.PolicyFile)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("Failed to load supplimental policy file: %s", account.PolicyFile))
		}
		params.Policy = aws.String(string(policy))
	}

	if account.PolicyARNs != "" {
		var arns []*sts.PolicyDescriptorType
		for _, arn := range strings.Split(account.PolicyARNs, ",") {
			arns = append(arns, &sts.PolicyDescriptorType{Arn: aws.String(arn)})
		}
		params.PolicyArns = arns
	}

	log.Println("Requesting AWS credentials using SAML assertion.")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving STS credentials using SAML.")
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
		Region:           account.Region,
	}, nil
}

func saveCredentials(awsCreds *awsconfig.AWSCredentials, sharedCreds *awsconfig.CredentialsProvider) error {
	err := sharedCreds.Save(awsCreds)
	if err != nil {
		return errors.Wrap(err, "Error saving credentials.")
	}

	return nil
}

// CredentialsToCredentialProcess
// Returns a Json output that is compatible with the AWS credential_process
// https://github.com/awslabs/awsprocesscreds
func CredentialsToCredentialProcess(awsCreds *awsconfig.AWSCredentials) (string, error) {

	type AWSCredentialProcess struct {
		Version         int
		AccessKeyId     string
		SecretAccessKey string
		SessionToken    string
		Expiration      string
	}

	cred_process := AWSCredentialProcess{
		Version:         1,
		AccessKeyId:     awsCreds.AWSAccessKey,
		SecretAccessKey: awsCreds.AWSSecretKey,
		SessionToken:    awsCreds.AWSSessionToken,
		Expiration:      awsCreds.Expires.Format(time.RFC3339),
	}

	p, err := json.Marshal(cred_process)
	if err != nil {
		return "", errors.Wrap(err, "Error while marshalling the credential process.")
	}
	return string(p), nil

}

func CustomCredentialsFile(credentialsFile string) (bool, error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}
	defaultCredentialsFile := fmt.Sprintf("%s/.aws/credentials", homeDir)
	if defaultCredentialsFile == credentialsFile {
		return false, nil
	}
	return true, nil

}

// PrintCredentialProcess Prints a Json output that is compatible with the AWS credential_process
// https://github.com/awslabs/awsprocesscreds
func PrintCredentialProcess(awsCreds *awsconfig.AWSCredentials) error {
	jsonData, err := CredentialsToCredentialProcess(awsCreds)
	if err == nil {
		fmt.Println(jsonData)
	}
	return err
}

// fixRoleProviderOrder ensures that role/provider pairs in the SAML assertion
// are in the correct order: role ARN first, provider ARN second.
// The provider ARN contains "saml-provider" in its path.
func fixRoleProviderOrder(samlAssertion string) (string, error) {
	// Decode the base64 SAML assertion
	decoded, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return "", errors.Wrap(err, "Error decoding SAML assertion")
	}

	samlXML := string(decoded)
	log.Println("=== FIXING ROLE/PROVIDER ORDER ===")

	fixedCount := 0

	// Pattern: find provider ARN followed by comma and role ARN
	// We need to swap these to role,provider
	// Look for: arn:aws:iam::ACCOUNT:saml-provider/NAME,arn:aws:iam::ACCOUNT:role/NAME

	result := samlXML
	offset := 0

	for {
		// Find next occurrence of saml-provider
		providerStart := strings.Index(result[offset:], "arn:aws:iam::")
		if providerStart == -1 {
			break
		}
		providerStart += offset

		// Check if this is a saml-provider ARN
		providerEnd := -1
		for i := providerStart; i < len(result); i++ {
			if result[i] == ',' || result[i] == '<' {
				providerEnd = i
				break
			}
		}

		if providerEnd == -1 {
			break
		}

		providerARN := result[providerStart:providerEnd]

		// Check if this is a provider ARN
		if !strings.Contains(providerARN, "saml-provider") {
			offset = providerStart + 13
			continue
		}

		// Check if followed by comma
		if providerEnd >= len(result) || result[providerEnd] != ',' {
			offset = providerStart + 13
			continue
		}

		// Find the role ARN after the comma
		roleStart := providerEnd + 1
		roleEnd := -1
		for i := roleStart; i < len(result); i++ {
			if result[i] == '<' || result[i] == ',' {
				roleEnd = i
				break
			}
		}

		if roleEnd == -1 {
			offset = providerStart + 13
			continue
		}

		roleARN := result[roleStart:roleEnd]

		// Check if this is a role ARN
		if !strings.Contains(roleARN, ":role/") {
			offset = providerStart + 13
			continue
		}

		// Found provider,role - swap to role,provider
		original := providerARN + "," + roleARN
		swapped := roleARN + "," + providerARN

		result = result[:providerStart] + swapped + result[roleEnd:]

		log.Printf("Fixed: %s -> %s", original, swapped)
		fixedCount++

		// Move offset past this fix
		offset = providerStart + len(swapped)
	}

	if fixedCount > 0 {
		log.Printf("Fixed %d role/provider pairs to role,provider order", fixedCount)
	} else {
		log.Println("All role/provider pairs already in correct order")
	}

	log.Println("=== END FIXING ===")

	// Re-encode to base64
	return b64.StdEncoding.EncodeToString([]byte(result)), nil
}
