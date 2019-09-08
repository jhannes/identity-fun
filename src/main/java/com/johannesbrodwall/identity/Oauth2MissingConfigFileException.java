package com.johannesbrodwall.identity;

import java.io.File;

public class Oauth2MissingConfigFileException extends Oauth2ConfigurationException {
    public Oauth2MissingConfigFileException(File file) {
        super("Missing " + file.getAbsolutePath() + " (try copying from " + file + ".template)");
    }
}
