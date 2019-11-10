package com.johannesbrodwall.identity.config;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Optional;
import java.util.Properties;

public class Configuration {
    private final Properties properties;
    private File file;

    public Configuration(File file) throws IOException {
        this.file = file;
        properties = new Properties();
        try (FileReader reader = new FileReader(file)) {
            properties.load(reader);
        } catch (FileNotFoundException e) {
            throw new Oauth2MissingConfigFileException(file);
        }
    }

    public String getRequiredProperty(String key) {
        return getProperty(key).orElseThrow(() -> new Oauth2MissingPropertyException(key, file));
    }

    public Optional<String> getProperty(String key) {
        return Optional.ofNullable(properties.getProperty(key)).filter(s -> !s.isBlank());
    }
}
