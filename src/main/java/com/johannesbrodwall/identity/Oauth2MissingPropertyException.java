package com.johannesbrodwall.identity;

import java.io.File;

public class Oauth2MissingPropertyException extends Oauth2ConfigurationException {
    public Oauth2MissingPropertyException(String propertyName, File file) {
        super("Missing property [" + propertyName + "] in " + file.getAbsolutePath());
    }
}
