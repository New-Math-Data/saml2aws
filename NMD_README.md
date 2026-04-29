## Instructions for NMD users

1. Ensure go is installed on your machine
    - `brew install go`

2. Ensure you have pulled the latest from the `master`

3. Open the terminal in the root of this repo and run the following command
    - `go build -o saml2aws ./cmd/saml2aws`

4. You may then use it as normal `saml2aws`, ensure you preface with 
    `./saml2aws login`

### Debugging login issues

If authentication fails unexpectedly, use the `--verbose` and `--debug-idp` flags together to diagnose the problem:

```bash
./saml2aws --verbose login --debug-idp
```

- `--verbose` enables debug-level logging, showing HTTP requests/responses, page headings, and form actions from the IDP.
- `--debug-idp` writes the full IDP response HTML to a temp file (path printed in the output) so you can open it in a browser and see exactly what page the IDP returned.

This is especially useful when Google introduces intermediate pages (password resets, account recovery, new terms of service) that saml2aws doesn't handle automatically.

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