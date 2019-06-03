# Identity fun

Training application to further understanding of OpenID Connect and Oauth2. Live demo at [https://javabin-openid-demo.azurewebsites.net/](https://javabin-openid-demo.azurewebsites.net/).

## Setup

1. Create Google credentials at [Google Developer Console](https://console.developers.google.com/apis/credentials) and put `google.client_id`, `google.client_secret` and `google.redirect_uri` into `oauth2-providers.properties`
2. Create Active Directory crentials in [Azure Portal](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal) - [App Registration Blade](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) and put `azure.client_id`, `azure.client_secret` and `azure.redirect_uri` into `oauth2-providers.properties`.
3. [Request credentials](https://difi.github.io/idporten-oidc-dokumentasjon/) for ID-porten and put `idporten.client_id`, `idporten.client_secret` and `idporten.redirect_id` in `oauth2-providers.properties`.
4. [Create a Slack application](https://api.slack.com/apps) and find your crentials under Basic Information > App Credentials. Put `slack.client_id` and`slack.client_secret` in `oauth2-providers.properties`. Select "OAuth & Permissions" in the menu and add your Redirect URL here. Put `slack.redirect_id` in `oauth2-providers.properties`. See [Slack documentation](https://api.slack.com/docs/sign-in-with-slack) for details



## Why should you care about OpenID Connect?

The advantage of OpenID Connect is the fact that it's standardized and widely adopted. This means that a library or tool designed to work with, e.g. Google accounts, can easily be adopted to work with e.g. Microsoft's Active Directory  or the Norwegian national ID provider ID-porten.

Different Identity providers can support different levels of trust between you and your users.

The protocol is perceived with an air of mystery by many developers, but it's surprisingly simple to master. As a developer, you owe yourself and your users to play with OpenID Connect before you ever implement a username+password.


## More about ID-porten

With the new [ID-porten API](https://difi.github.io/idporten-oidc-dokumentasjon/oidc_api_admin.html), you are able to manage client ids yourself. You need to purchase an organization certificate for your organization (at this moment, only Commfides provides this) and get this registered with Difi. Commfides will send you a .p12-file with the secret key and certificate (yes, this is not very good security!).

You have to go through the following steps:

1. Generate a JWT with your organization as the _issuer_ (`"iss"`) and ID-porten (`https://oidc.difi.no/idporten-oidc-provider/token`) as the _audience_ (`"aud"`) and sign it with the your organization's authentication certificate
2. Make a POST request to `https://oidc.difi.no/idporten-oidc-provider/token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and `assertion` as the JWT created in step 2.
3. You will receive a token response with an `access_token` as a JWT with the issuer and audience reversed from step 2
4. Use this access_token in the `Authorization` header to API calls to [Difi's Integration API](https://integrasjon.difi.no/swagger-ui.html). Try GET [https://integrasjon.difi.no/clients](https://integrasjon-ver2.difi.no/clients) to list clients and POST [https://integrasjon.difi.no/clients](https://integrasjon.difi.no/clients) to create a new client

See the `IdPortenApiClient` client for an example.

## Deployment

1. `mvn clean package azure-webapp:deploy`
2. Go to [Azure app service cmd](https://javabin-openid-demo.scm.azurewebsites.net/DebugConsole) to check logs and update configuration file
3. Go to [Azure Portal](https://portal.azure.com) to restart server


## Revoking application consent

* [Active Directory](https://account.activedirectory.windowsazure.com)
* [Google](https://myaccount.google.com/permissions)
