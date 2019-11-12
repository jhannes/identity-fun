package com.johannesbrodwall.identity;

import org.actioncontroller.HttpActionException;
import org.actioncontroller.meta.ApiHttpExchange;

import java.io.IOException;
import java.util.Optional;

public class HttpConfigurationException extends HttpActionException {
    private final String providerName;
    private final Optional<String> consoleUrl;
    private final String redirectUri;

    public HttpConfigurationException(String providerName, Optional<String> consoleUrl, String redirectUri, Exception e) {
        super(500, e);
        this.providerName = providerName;
        this.consoleUrl = consoleUrl;
        this.redirectUri = redirectUri;
    }

    @Override
    public void sendError(ApiHttpExchange exchange) throws IOException {
        String message = "<!DOCTYPE html>\n"
                + "<html>"
                + "<head>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                + "</head>"
                + "<body>"
                + "<h2>Setup error with provider <code>" + providerName + "</code></h2>"
                + "<div><code>" + getCause().getMessage() + "</code></div>"
                +  consoleUrl
                .map(url ->
                        "<h2><a target='_blank' href='"  + url + "'>Setup " + providerName + "</a></h2>"
                                + "<div>Use " +
                                "<code>" + redirectUri + "</code>" +
                                " as redirect_uri " +
                                "<button onclick='navigator.clipboard.writeText(\"" + redirectUri + "\")'>clipboard</button>" +
                                "</div>")
                .orElse("")
                + "<div><a href='/'>Front page</a></div>"
                + "</body>"
                + "</html>";
        exchange.write("text/html", writer -> writer.write(message));
    }
}
