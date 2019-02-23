# Identity fun

Demonstration application to further understanding of OpenID Connect and Oauth2.

## Why should you care about OpenID Connect?

The advantage of OpenID Connect is the fact that it's standardized and widely adopted. This means that a library or tool designed to work with, e.g. Google accounts, can easily be adopted to work with e.g. Microsoft's Active Directory  or the Norwegian national ID provider ID-porten.

Different Identity providers can support different levels of trust between you and your users.

The protocol is perceived with an air of mystery by many developers, but it's surprisingly simple to master. As a developer, you owe yourself and your users to play with OpenID Connect before you ever implement a username+password.


## TODO

* [ ] Configuration for client ids and secrets
* [ ] Active Directory admin
    * [ ] Only grant access to certain groups
    * [ ] Give application roles
    * [ ] Require MFA (requires paid AD)
* [ ] Make API profile call for each provider
* [ ] Write Linkedin post about ID-porten
* [ ] Write Linkedin post about AD
* [ ] Make the debugging pages more debuggable and improve logging
* [ ] Style login buttons
* [ ] Oauth2Servlet is superclass of OpenIdConnectServlet
* [ ] Demo of public clients (response_mode=fragment, pkce)
