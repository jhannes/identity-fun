# Identity fun

Demonstration application to further understanding of OpenID Connect and Oauth2.

## Setup

1. Create Google credentials at [Google Developer Console](https://console.developers.google.com/apis/credentials) and put `google.client_id`, `google.client_secret` and `google.redirect_uri` into `oauth2-providers.properties`
2. Create Active Directory crentials in [Azure Portal](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal) - [App Registration Blade](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) and put `azure.client_id`, `azure.client_secret` and `azure.redirect_uri` into `oauth2-providers.properties`.
3. [Request credentials](https://difi.github.io/idporten-oidc-dokumentasjon/) for ID-porten and put `idporten.client_id`, `idporten.client_secret` and `idporten.redirect_id` in `oauth2-providers.properties`.
4. [Create a Slack application](https://api.slack.com/apps) and find your crentials under Basic Information > App Credentials. Put `slack.client_id` and`slack.client_secret` in `oauth2-providers.properties`. Select "OAuth & Permissions" in the menu and add your Redirect URL here. Put `slack.redirect_id` in `oauth2-providers.properties`. See [Slack documentation](https://api.slack.com/docs/sign-in-with-slack) for details



## Why should you care about OpenID Connect?

The advantage of OpenID Connect is the fact that it's standardized and widely adopted. This means that a library or tool designed to work with, e.g. Google accounts, can easily be adopted to work with e.g. Microsoft's Active Directory  or the Norwegian national ID provider ID-porten.

Different Identity providers can support different levels of trust between you and your users.

The protocol is perceived with an air of mystery by many developers, but it's surprisingly simple to master. As a developer, you owe yourself and your users to play with OpenID Connect before you ever implement a username+password.


## TODO

* [x] Write Linkedin post about ID-porten
* [x] Write Linkedin post about AD
* [x] Configuration for client ids and secrets
* [x] Make the debugging pages more debuggable and improve logging
* [x] Make API profile call for each provider
* [x] Active Directory admin
    * [x] Create reasonable sample directory
    * [x] Create some company branding
    * [x] Only grant access to certain groups
    * [x] Give application roles
    * [x] Require MFA (requires paid AD)
* [x] Error handling on authenticate
* [x] Refresh tokens
* [x] Logout
    * [x] Show end-session endpoint
    * [ ] front-channel logout (not available on http://localhost on Azure)
* [x] Deployment
* [ ] Oauth2Servlet is superclass of OpenIdConnectServlet?
* [ ] Demo of public clients (response_mode=fragment, pkce)
* [ ] Style login buttons
