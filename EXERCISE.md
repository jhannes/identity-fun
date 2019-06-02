# OpenID Connect self paced exercise

## Overview

Open-ID Connect consists of three main technologies:

* [The Oauth2](https://tools.ietf.org/html/rfc6749) authentication flow
* Json Web Tokens (JWT) with information about the end user
* The discovery document with information about the Identity Provider

To execute an Open ID Connect authorization code flow, the client, application and identity provider goes through the following steps (copy and paste the following into http://plantuml.com)

```
actor endUser
participant application
participant IDP

note over application: Developer has registered app with client_id, client_secret and redirect_uri
endUser -> application: Tries to access function\n which requires authorization
endUser <-- application: Redirect to Identity Provider (IDP)
endUser -> IDP: Authorization request
note left of IDP: http request with client_id, redirect_uri, etc
endUser <-- IDP: Login page
endUser -> IDP: Credentials
endUser <-- IDP: Autentisering-code
note left of IDP: Redirects to redirect_uri with a `code`
endUser -> application: code
application -> IDP: Request token with code, client_secret
application <-- IDP: access_token, id_token
```

At then end of the flow, the client receives a ID Token (identity token) with information about the end user. The ID token consists of three parts: `base64(header) + "." + base64(payload) + "." + signature(base64(header) + "." + base64(body)`.

The contents of the Header and Payload are defined in the [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html).

Here's an example of a JWT. Try to cut and paste it into [JWT.io](https://jwt.io):

```
eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwY2QzNzcxYzExMjVjOWY3N2U4MmUzOTk3NGUxNjNhOGM3M2IzYzQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiNTM3NjM3MTYzMTk2LWRydG9mYjBpdHM3ZGxwcmFncDNiY3A3YWQzcjlnazF1LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiNTM3NjM3MTYzMTk2LWRydG9mYjBpdHM3ZGxwcmFncDNiY3A3YWQzcjlnazF1LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE0ODgyNDkzOTU0Njg1MjkwODU5IiwiYXRfaGFzaCI6IjEwRDZjOUg0NUI4RzRuUmFBcXdiYlEiLCJpYXQiOjE1NDI4MzEzNTMsImV4cCI6MTU0MjgzNDk1M30.R9szAvAy9FkZlcCREC7K8Ms39QJwqjffY93nrZEag5hdp0pOZ0AV4K7mLpxL4bqok4vQr0X8B7IUFfLMy2GDJhux_mi05jepzIIKy0z0lVYTe3rvmye5opj0Pz_IwjRNY00dy8osVE1hDqNlObrui8UTcuQ0UV_Zd0uiHw1f7lIo57kB1VHB2HVM4OSWqSWBOa0_gIYiYpcTyTdPtKJanrwew1T9uhB8aODS2R57vHB-RHXfRBiLBHZDU_9V3z6LxS-gzTEVk8YNS0kfP20U9Mjhd_CJjIWkOmruJ1bQMZAU45ZGlnMd-zYwxMAMU8tFmpKHcobMQlfPf5J9Dp1q2w
```

Decoding will yield the following header:

```json
{
  "alg": "RS256",
  "kid": "60cd3771c1125c9f77e82e39974e163a8c73b3c4",
  "typ": "JWT"
}
```

... and the following payload:

```json
{
  "iss": "accounts.google.com",
  "azp": "537637163196-drtofb0its7dlpragp3bcp7ad3r9gk1u.apps.googleusercontent.com",
  "aud": "537637163196-drtofb0its7dlpragp3bcp7ad3r9gk1u.apps.googleusercontent.com",
  "sub": "114882493954685290859",
  "at_hash": "10D6c9H45B8G4nRaAqwbbQ",
  "iat": 1542831353,
  "exp": 1542834953
}
```

The most used values here signify:

* `iss` (issuer): This is a token issued by Google
* `aud` (audience): The token was issued to my app (that I registered with Google)
* `sub` (subject): This is a unique id for the end user in the context of my app
* `iat` (issued at): It was issued on November 21st
* "exp" (expires): It expires one hour after the issue time


## Exercise

The exercise consists of registering an application with various identity providers and using the web browser and cURL to authenticate.

We will explore the following Identity Providers:

* Google
* Microsoft Active Directory
* (Only for Norwegian workshops) ID-porten - the Norwegian Identity Provider for public sector services

### Prerequisites

In order to follow this tutorial, you need a computer with a Bash shell and cUrl. On Windows, you can use Windows Subsystem for Linux (WSL), Git bash or Cygwin. If you don't want to install cUrl, you can use Httpie or Postman


### Google

1. Go to [Google API Console](https://console.developers.google.com/apis/credentials)
2. You will be prompted to create an application if you haven't done so before
3. [Create credentials](https://console.developers.google.com/apis/credentials/oauthclient)
4. Select Web Application. Enter the following values:
   * Authenticated origins: `https://my.example.com` (for example)
   * Authorized redirect URI: `https://my.example.com/oauth2callback` (for example)
   * Google will prompt you to add `example.com` as an authorized domain.
5. Google will provide you with a *`client_id`* and *`client_secret`*. Copy these to a text file as you will need them both
6. Edit and paste the following URL into your web browser: `https://accounts.google.com/o/oauth2/v2/auth?scope=profile+email+openid&response_type=code&redirect_uri=https://my.example.com/oauth2callback&client_id=:client_id` (replace redirect_uri and client_id with your own values). Using _Bash_ you can do the following:
   * `export REDIRECT_URI=https://my.example.com/oauth2callback` # Or your own value
   * `export CLIENT_ID=<value from Google API Console>`
   * `echo "https://accounts.google.com/o/oauth2/v2/auth?scope=profile+email+openid&response_type=code&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID"`
   * Open the resulting URL in a browser
7. *Don't panick*: Complete the login sequence in the browser. You will be redirected to https://my.example.com _which is an invalid web site_. That's fine!
8. Copy the `code` query parameter from your browser. You need to do execute an HTTP POST request to Google, for example using cUrl:
   * `export REDIRECT_URI=https://my.example.com/oauth2callback` # Or your own value
   * `export CLIENT_ID=<value from Google API Console>`
   * `export CLIENT_SECRET=<value from Google API Console>`
   * `export CODE=<value from browser query parameter>`
   * `TOKEN_RESPONSE=$(curl -X POST --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode client_secret=$CLIENT_SECRET --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI" https://oauth2.googleapis.com/token)`
   * `echo $TOKEN_RESPONSE`
9. The token response contains an `id_token`. You can copy and paste this into [https://jwt.io](https://jwt.io)
10. Alternatively, you can parse the id_token with shell commands (requires [jq](https://stedolan.github.io/jq/) the be installed):
   * `ID_TOKEN=$(echo $TOKEN_RESPONSE | jq ".id_token")`
   * `ID_TOKEN_PAYLOAD=$(echo $ID_TOKEN | cut -d. -f2 | base64 -d)`
   * `echo $ID_TOKEN_PAYLOAD`
   * `echo $ID_TOKEN_PAYLOAD | jq "[ .sub, .name, .email, .iss, .aud ]"`

Here is an example JWT:

```
eyJhbGciOiJSUzI1NiIsImtpZCI6IjYwY2QzNzcxYzExMjVjOWY3N2U4MmUzOTk3NGUxNjNhOGM3M2IzYzQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiNTM3NjM3MTYzMTk2LWRydG9mYjBpdHM3ZGxwcmFncDNiY3A3YWQzcjlnazF1LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiNTM3NjM3MTYzMTk2LWRydG9mYjBpdHM3ZGxwcmFncDNiY3A3YWQzcjlnazF1LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE0ODgyNDkzOTU0Njg1MjkwODU5IiwiZW1haWwiOiJqaGFubmVzQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoidW9aNjdZYTRlVVJhcWZrUmJpMzhtZyIsImlhdCI6MTU0MjgzMTgzMiwiZXhwIjoxNTQyODM1NDMyfQ.unUEjxOVjjmZL8piyCXxfncYThYBZqU3OCrkjpmp66cosKChR4nEgaSCHyWbqPFpnizsJ-JgVdIW483QM4bv3sg4eA2PMfFoDU8t-ZhDupacPvxEMsFlMZx0GNbfnz6bL7TsuECUEEQD992Mw6RT5c906j-Q0oRiC8JdU1hDSrWufFCUiS1MOOk99ekyBvsYN-fQ0po7yoe33RqqPDc7STzO_NhdOpb5Yu9nqlDjDSZl7Z3VsgygfgyBanvneWvDuVWOADpPf6EQX_CnraDjOhYWGvbU3KMXxJeGeO-4cKklhqAz1_gdL5Bo3Lml6vAb1RXiL3tEzeg-ALyYQ2dNWg
```

To understand where the URLs and scopes come from, you can see the [Discovery document](https://accounts.google.com/.well-known/openid-configuration), which contains the `authorization_endpoint`, `token_endpoint`, `scopes_supported` and more.

### ID-porten

1. Request a test client_id and client_secret from Difi for your required `redirect_uri`, or ask the workshop instructor for a `client_id` and `client_secret`. This example uses `http://localhost:8080/idporten/oauth2callback` as the `redirect_uri`. If you have an organization certificate that's registered with Difi, you can [issue clients](https://difi.github.io/idporten-oidc-dokumentasjon/oidc_api_admin.html) yourself.
2. Edit and paste the following URL into your web browser: `https://oidc-ver1.difi.no/idporten-oidc-provider/authorize?scope=profile+openid&response_type=code&redirect_uri=http://localhost:8080/idporten/oauth2callback&client_id=:client_id` (replace redirect_uri and client_id with your own values). Using _Bash_ you can do the following:
   * `export REDIRECT_URI=http://localhost:8080/idporten/oauth2callback` # Or your own value
   * `export CLIENT_ID=<value from Difi>`
   * `echo "https://oidc-ver1.difi.no/idporten-oidc-provider/authorize?scope=profile+openid&response_type=code&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID"`
   * Open the resulting URL in a browser
3. Log on with MinID, test users always have the password "password01" and one time code "12345". Here are some example test users:
   * 48099902453
   * 48106400663
   * 48126800293
4. *Don't panick*: Complete the login sequence in the browser. You will be redirected to `http://localhost:8080` _where you probably will get a 404 or other error_. That's fine!
5. Copy the `code` query parameter from your browser. You need to do execute an HTTP POST request to Difi, for example using cUrl:
   * `export REDIRECT_URI=http://localhost:8080/idporten/oauth2callback` # Or your own value
   * `export CLIENT_ID=<value from Difi>`
   * `export CLIENT_SECRET=<value from Difi>`
   * `export CODE=<value from browser query parameter>`
   * `TOKEN_RESPONSE=$(curl -X POST --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode client_secret=$CLIENT_SECRET --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI" https://oidc-ver1.difi.no/idporten-oidc-provider/token)`
   * `echo $TOKEN_RESPONSE`
6. The token response contains an `id_token`. You can copy and paste this into [https://jwt.io](https://jwt.io)
7. Alternatively, you can parse the id_token with shell commands (requires [jq](https://stedolan.github.io/jq/) the be installed):
   * `ID_TOKEN=$(echo $TOKEN_RESPONSE | jq ".id_token")`
   * `ID_TOKEN_PAYLOAD=$(echo $ID_TOKEN | cut -d. -f2 | base64 -d)`
   * `echo $ID_TOKEN_PAYLOAD`
   * `echo $ID_TOKEN_PAYLOAD | jq "[ .sub, .pid, .acr, .iss, .aud ]"`

Here is an example JWT:

```
eyJraWQiOiJtcVQ1QTNMT1NJSGJwS3JzY2IzRUhHcnItV0lGUmZMZGFxWl81SjlHUjlzIiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoidzdHUWxneERGYjRnamdyRTZoQ0MzUSIsInN1YiI6ImhfOGxpNi01bmZ4V09nWVU5VExqTTl3MU5Db2I4MjRhcWZyRGRQVVE2UVE9IiwiYW1yIjpbIk1pbmlkLVBJTiJdLCJpc3MiOiJodHRwczpcL1wvb2lkYy12ZXIxLmRpZmkubm9cL2lkcG9ydGVuLW9pZGMtcHJvdmlkZXJcLyIsInBpZCI6IjQ4MTI2ODAwMjkzIiwibG9jYWxlIjoibmIiLCJzaWQiOiJuREVSRHF0Um5xMExDV1RmZjZrTF9nQXZiNjZEbjJLQl9YejU4X1ZGOVdVPSIsImF1ZCI6Im9pZGNfc29wcmFfc3RlcmlhIiwiYWNyIjoiTGV2ZWwzIiwiYXV0aF90aW1lIjoxNTQyODMzMzI5LCJleHAiOjE1NDI4MzM0NzYsImlhdCI6MTU0MjgzMzM1NiwianRpIjoidEF1V29YaF9iSS1uaXZvQXV6Y1hPU0FOWkM1eGplRXo0eHZiVldyUUVTQT0ifQ.GD_RM1v4doIuuRQXEV3j9R6sFkcfFtP5-afHfBwL81dV14fRU1XRPGRgc8QDiNO5xlVbc3fDjyfzTm0tfQe9XpLgXOQFBCWbldpVPoZnHMNk8i99hTdPY__7q_LZQVHXTWNZy_DWU-is6oRYR5YN6EeUEWya23YCrmYhlpVpD8JQNxPlIf-POD_AKOIBfBqOp7kv9zceL93FOzSvy1GvId7P5MZJ0h2B_jiszqaTyvXtCMv_pDSybCujUiWNFGuTLRb6DUqjgjVg-fqRpraWkIp65Uct9EZnkSIKsaCWJoCYgDhXyrFPmDHAOMqZ6F_w4cLMrPVHNsbVY1S6UekuJw
```

To understand where the URLs and scopes come from, you can see the [Discovery document](https://oidc-ver1.difi.no/idporten-oidc-provider/.well-known/openid-configuration), which contains the `authorization_endpoint`, `token_endpoint`, `scopes_supported` and more.

### Azure Active Directory (multi-tenant)

If you have an account in any Active Directory, you can create your own free Active Directory where you can create application registrations. By creating a "**multi-tenant**" app, you can allow uses from any Active Directory to authorize with your app using their organization credentials.

1. Log into [Azure Portal](https://portal.azure.com/) and [create a new Active Directory](https://portal.azure.com/#create/Microsoft.AzureActiveDirectory)
2. Make sure you are switched to your new Active Directory by clicking on your account info in the top right corner and select Switch directory
3. In your new Active Directory, [Create a new App Registration](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredAppsPreview). Make sure that under *Supported Account Types* you select "Accounts in any organizational directory" (this is what is referred to as "multi-tenant"). Enter your `redirect_uri` (e.g. `https://my.example.com/oauth2callback`).
4. Setup your `response_uri` and get your `client_secret` and `client_secret`:
   * `export REDIRECT_URI=https://my.example.com/oauth2callback` # Or your own value under Authentication
   * `export CLIENT_ID=<value of Application ID on Overview>`
   * `export CLIENT_SECRET=<find under Certificates & secrets>` # Notice that Azure likes to use special characters in client secrets, so quote it, like so `CLIENT_SECRET='abc>&123$pqr'
   * `export SCOPE=openid+profile+email`
5. Generate an authorization URL and paste into your web browser (find under Overview > Endpoints):
   * `echo "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?scope=$SCOPE&response_type=code&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID"`
6. Authorize with *any organization you have access to*. You can authorize with your work account, your account at your client site or any organization that uses Active Directory. Since the organization has no relationship with your personal Active Directory, the user will be prompted for consent before Active Directory gives their information to your app. **Don't panick when the browser redirects you to your currently inactive redirect_uri**
7. Copy the `code` from the resulting URL (example)
   * `export CODE=<value from browser query parameter>`
8. Request the authorization token:
   * `TOKEN_RESPONSE=$(curl -X POST --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode client_secret=$CLIENT_SECRET --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI" https://login.microsoftonline.com/organizations/oauth2/v2.0/token)`
9. Examine the token response:
   * `ID_TOKEN=$(echo $TOKEN_RESPONSE | jq ".id_token")`
   * `ID_TOKEN_PAYLOAD=$(echo $ID_TOKEN | cut -d. -f2 | base64 -d)`
   * `echo $ID_TOKEN_PAYLOAD | jq`
   * `echo $ID_TOKEN_PAYLOAD | jq "[ .name, .iss, .tid, .email ]"`

Notice that the `tid` (tenant ID) and `iss` (issuer) claims in the ID token tells you which organization the user was authorized for. This is extremely useful when you create applications that are to be used by several organizations.


### Azure Active Directory (B2B)

If you have an account in any Active Directory, you can create your own free Active Directory where you can create application registrations. By inviting guest users from other organizations, you can create a **B2B application** which lets users from other Active Directory to authenticate with their organization credentials while you can control what features of your applications they are authorized for.

1. Log into [Azure Portal](https://portal.azure.com/) and [create a new Active Directory](https://portal.azure.com/#create/Microsoft.AzureActiveDirectory)
2. Make sure you are switched to your new Active Directory by clicking on your account info in the top right corner and select Switch directory
3. In your new Active Directory, [Manage users](https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/AllUsers) to invite guest users from other organizations. This can be your work organization, clients or third parties. You can also create users that belong directly to your own Active Directory
4. [Create a new App Registration](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredAppsPreview). Make sure that under *Supported Account Types* you select "Accounts in this organizational directory only". Enter your `redirect_uri` (e.g. `https://my.example.com/oauth2callback`).
5. Setup your `response_uri` and get your `client_secret` and `client_secret`:
   * `export REDIRECT_URI=https://my.example.com/oauth2callback` # Or your own value under Authentication
   * `export CLIENT_ID=<value of Application ID on Overview>`
   * `export CLIENT_SECRET=<create under Certificates & secrets>` # Notice that Azure likes to use special characters in client secrets, so quote it, like so `CLIENT_SECRET='abc>&123$pqr'
   * `export SCOPE=openid+profile+email`
   * `export AUTHORIZATION_ENDPOINT=https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/v2.0/authorize` # Find under Overview > Endpoints)
   * `export TOKEN_ENDPOINT=https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/v2.0/token` # Find under Overview > Endpoints)
6. Generate an authorization URL and paste into your web browser:
   * `echo "$AUTHORIZATION_ENDPOINT?scope=$SCOPE&response_type=code&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID"`
7. Authorize a user that is a member of your Active Directory. This can be a full user of the Active Directory or it can be a guest user that you have invited from another organization. Since their organization has no relationship with your personal Active Directory, a guest user will be prompted for consent before Active Directory gives their information to your app. **Don't panick when the browser redirects you to your currently inactive redirect_uri**
8. Copy the `code` from the resulting URL (example)
   * `export CODE=<value from browser query parameter>`
9. Request the authorization token:
   * `TOKEN_RESPONSE=$(curl -X POST --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode client_secret=$CLIENT_SECRET --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI" $TOKEN_ENDPOINT)`
9. Examine the token response:
   * `ID_TOKEN=$(echo $TOKEN_RESPONSE | jq ".id_token")`
   * `ID_TOKEN_PAYLOAD=$(echo $ID_TOKEN | cut -d. -f2 | base64 -d)`
   * `echo $ID_TOKEN_PAYLOAD | jq`
   * `echo $ID_TOKEN_PAYLOAD | jq "[ .iss, .idp, .email ]"`

Notice that the `tid` (tenant ID) and `iss` (issuer) claims in the ID token contains the identification of the Active Directory where the application lives, while the `idp` (Identity Provider) claim contains the organization where the user account lives. For a guest user, this is the account that authorized the user's credentials.

Only guest users that you have explicitly invited to your Active Directory will be able to authenticate with your apps.

You can [configure the app in you Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/AllApps/menuId/) only allow specific users or users in specific groups to access the app. Select your app and under Properties, select "User Assignement Required". (You need Active Directory Premium to enable Group assignment)


Here is an example JWT:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkhCeGw5bUFlNmd4YXZDa2NvT1UyVEhzRE5hMCJ9.eyJhdWQiOiIyZmU0ZTA5Ny00NzQ0LTRlMjYtODY0NS05N2IxZTM5ZmQ5YjYiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vYjgxMjgyNGMtOTdhOS00NWNlLWIwMWMtNmU5MjlkNmI3ODUyL3YyLjAiLCJpYXQiOjE1NTkzODY1MzQsIm5iZiI6MTU1OTM4NjUzNCwiZXhwIjoxNTU5MzkwNDM0LCJhaW8iOiJBVVFBdS84TEFBQUFjQ2hjcjRad2Q3czU3UGFJYk14NWgwUXVydlZaZnYxSGg4dGhtMC9xcDJIcU12SHErRjdLV0NUQkJ0ZjBmWkdtSTFQb2h5WDhNaEdTc1pYOVdWbW9oZz09IiwiZW1haWwiOiJqb2hhbm5lcy5icm9kd2FsbEBzb3ByYXN0ZXJpYS5jb20iLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC84Yjg3YWY3ZC04NjQ3LTRkYzctOGRmNC01ZjY5YTIwMTFiYjUvIiwibmFtZSI6ImpvaGFubmVzLmJyb2R3YWxsQHNvcHJhc3RlcmlhLmNvbSBCUk9EV0FMTCIsIm5vbmNlIjoiMTQ5NjciLCJvaWQiOiJmNTIwODhkYy04YzQ0LTQwNzItYWU1Yy03MDAzMTkyZmZiYmMiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb2hhbm5lcy5icm9kd2FsbEBzb3ByYXN0ZXJpYS5jb20iLCJzdWIiOiJicERkQWt6NzlJM3NGUktaSEpVUkEya0NRVjJqcXg0SDdpdlRaTWVESHJrIiwidGlkIjoiYjgxMjgyNGMtOTdhOS00NWNlLWIwMWMtNmU5MjlkNmI3ODUyIiwidXRpIjoiUnF6SXhqY2U2MGlldDRQc3E2NHdBQSIsInZlciI6IjIuMCJ9.sl0q__wL_B71hA60U6bvsNwNfiTi3qS-FAowEAgz3nwqszy-vrulHCLfhlHaawHvgtV9sd4OoQ2QEZql6TLMeYlHaJR1jp5i1oAZ5oCMnj6v6CLyWTSe66ZHaL5vP0NiIN_uv3Oe5W8NAEy0zh_ctlUOulLKn5b-_FNvDyj8F5CNV_Axg9mG3NjsLlx5due9Spvza0hBPyLL0moQHNYiZose2BeeZXmRJ8_pkelajwmqFJtAbXlU8DNgJa2jlW6QFwDuknk8a_ZhAt382Fk2XDuH3OiWtxW1O8x-U69RW9wTcgK8xC1LVMc2MQNyb7FdakhPHE-yqkNYP_4nK0JibA
```


### Slack (NB: Not OpenID Connect, only Oauth2)

Many smaller organizations and workgroups use Slack as their preferred communication tool. This means that Slack is a good source of identity information for these organization. Slack only supports Oauth2 and not the full OpenID Connect protocol, so you cannot find the authorization and token endpoints in a discovery document and there is no ID token. But you can instead use API calls to verify the user identity.

In particular, use can use user membership of specific private channels double as authorization information.

This guide assumes you are member of a Slack community already, but you don't need to be administrator. For more information, see [Slack API doc](https://api.slack.com/docs/oauth).

1. [Create a new Slack app](https://api.slack.com/apps). Make sure you use the correct Slack workspace (in this example, I will use `javaBin-test.slack.com`)
2. Under "OAuth & Permissions", add your `response_uri` (e.g. `https://my.example.com/oauth2callback`) and add some scopes. For this demo, I use `groups:read`, `channels:read`, `identity.email` and `users.profile:read`.
3. Setup your `response_uri` and get your `client_secret` and `client_secret` under "Basic information):
   * `export REDIRECT_URI=https://my.example.com/oauth2callback` # Or your own value under OAuth & Permissions
   * `export CLIENT_ID=<value of Client ID under Basic Information / App credentials>`
   * `export CLIENT_SECRET=<value of Client ID under Basic Information / App credentials>`
   * `export SCOPE=groups:read+channels:read+users.profile:read` # Or your own values under OAuth2 & Permissions
   * `export AUTHORIZATION_ENDPOINT=https://<workspace>.slack.com/oauth/authorize` # E.g. `https://javaBin-test.slack.com/oauth/authorize`
   * `export TOKEN_ENDPOINT=https://slack.com/api/oauth.access`
4. Generate an authorization URL and paste into your web browser:
   * `echo "$AUTHORIZATION_ENDPOINT?scope=$SCOPE&response_type=code&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID"`
5. Authorize with a user that is a member of your Slack community and consent to the app getting your details. **Don't panick when the browser redirects you to your currently inactive redirect_uri**
6. Copy the `code` from the resulting URL (example)
   * `export CODE=<value from browser query parameter>`
7. Request the authorization token:
   * `TOKEN_RESPONSE=$(curl -X POST --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode client_secret=$CLIENT_SECRET --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI" $TOKEN_ENDPOINT)`
8. Retrieve the access token:
   * `ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq ".access_token")`
9. Get information about the user:
   * [Get basic user info](https://api.slack.com/methods/users.profile.get): `curl --header "Authorization: Bearer $ACCESS_TOKEN" https://slack.com/api/users.profile.get | jq`
   * [Get a list of private channels](https://api.slack.com/methods/conversations.list) that the user is member of: `curl --header "Authorization: Bearer $ACCESS_TOKEN" https://slack.com/api/conversations.list?types=private_channel | jq ".channels[] | [ .id, .name, .is_private ]"`


## Summary

*Uses Bash shell, cUrl and [jq](https://stedolan.github.io/jq/)*

1. Get the `authorization_endpoint` and `token_endpoint` for your ID provider ([Google Accounts](https://accounts.google.com/.well-known/openid-configuration), [ID porten test](https://oidc-ver1.difi.no/idporten-oidc-provider/.well-known/openid-configuration), [Azure multi-tenant](https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration)):
   * Google: `export AUTHORIZATION_ENDPOINT=https://accounts.google.com/o/oauth2/v2/auth ; export TOKEN_ENDPOINT=https://oauth2.googleapis.com/token `
   * ID-porten: `export AUTHORIZATION_ENDPOINT=https://oidc-ver1.difi.no/idporten-oidc-provider/authorize ; export TOKEN_ENDPOINT=https://oidc-ver1.difi.no/idporten-oidc-provider/token `
   * Azure multi-tenant: `export AUTHORIZATION_ENDPOINT=https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize; export TOKEN_ENDPOINT=https://login.microsoftonline.com/organizations/oauth2/v2.0/token`
2. Setup your `response_uri` and get your `client_secret` and `client_secret` from the OpenID Connect provider ([Google API Console](), [Azure Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredAppsPreview)):
   * `export REDIRECT_URI=https://my.example.com/oauth2callback` # Or your own value
   * `export CLIENT_ID=<value from ID provider>`
   * `export CLIENT_SECRET=<value from ID provider>`
   * `export SCOPE=openid+profile+email`
3. Generate an authorization URL and paste into your web browser:
   * `echo "$AUTHORIZATION_ENDPOINT?scope=$SCOPE&response_type=code&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID"`
4. Authorize with the ID provider. **Don't panick when the browser redirects you to your currently inactive redirect_uri**
5. Copy the `code` from the resulting URL (example)
   * `export CODE=<value from browser query parameter>`
6. Request the authorization token:
   * `TOKEN_RESPONSE=$(curl -X POST --data-urlencode "grant_type=authorization_code" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "client_secret=$CLIENT_SECRET" --data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI" $TOKEN_ENDPOINT)`
7. Examine the token response:
   * `ID_TOKEN=$(echo $TOKEN_RESPONSE | jq ".id_token")`
   * `ID_TOKEN_PAYLOAD=$(echo $ID_TOKEN | cut -d. -f2 | base64 -d)`
   * `echo $ID_TOKEN_PAYLOAD | jq`
   * `echo $ID_TOKEN_PAYLOAD | jq "[ .sub, .iss, .aud ]"`

Alternatively, if you have set up your client as a PUBLIC client (one that cannot protect it's client_secret), you can use `response_mode=fragment` to deliver the ID token directly to the browser as a URL fragment parameter:

1. Generate an authorization URL and paste into your web browser:
   * `echo "$AUTHORIZATION_ENDPOINT?redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&scope=$SCOPE&nonce=$RANDOM&response_type=id_token&response_mode=fragment"`
2. Authorize with the ID provider. **Don't panick when the browser redirects you to your currently inactive redirect_uri**
3. Copy the `id_token` from the resulting URL fragment (example)
   * `export ID_TOKEN=<value from browser id_token fragment>`
7. Examine the token response:
   * `ID_TOKEN_PAYLOAD=$(echo $ID_TOKEN | cut -d. -f2 | base64 -d)`
   * `echo $ID_TOKEN_PAYLOAD | jq`
