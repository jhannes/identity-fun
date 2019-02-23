package com.johannesbrodwall.identity.util;

import java.net.HttpURLConnection;

public interface HttpAuthorization {
    void authorize(HttpURLConnection connection);
}
