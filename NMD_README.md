## Instructions for NMD users

1. Ensure go is installed on your machine
    - `brew install go`

2. Ensure you have pulled the latest from the `master`

3. Open the terminal in the root of this repo and run the following command
    - `go build -o saml2aws ./cmd/saml2aws`

4. You may then use it as normal `saml2aws`, ensure you preface with 
    `./saml2aws login`

### Legacy Instructions
5. Find the AWS role and account you want cli creds for.
    - Go into console and find account number and role name (IAM should have the arn)
    - It will look like this `arn:aws:iam::xxxxxxxxx:role/NMD-Admin-NewMath`
    - NOTE the actual name `NMD-Admin-NewMath` might be different

6. Open the ~/.saml2aws file with an editor
    - in the role_arn field put the role arn from 4 in there

7. In the terminal run the following
    - `./nmd-saml2aws login --disable-keychain --profile <whatever you want>`

8. Authenticate and you should see the creds refresh in `~/.aws/credentials`