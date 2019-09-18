package com.johannesbrodwall.identity;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class URLBuilder {
    private URL url;

    private List<String> parameters = new ArrayList<>();

    public URLBuilder(URL url) {
        this.url = url;
    }

    public URLBuilder query(String parameterName, String value) {
        return query(parameterName + "=" + value.toString());
    }

    public URLBuilder query(String parameterName, Optional<String> value) {
        value.ifPresent(v -> query(parameterName, v));
        return this;
    }

    public URLBuilder query(String parameterAssignment) {
        if (parameterAssignment != null && !parameterAssignment.isBlank()) {
            parameters.add(parameterAssignment);
        }
        return this;
    }

    @Override
    public String toString() {
        return url + (parameters.isEmpty()
                ? ""
                : ("?" + String.join("&", parameters))
        );
    }
}
