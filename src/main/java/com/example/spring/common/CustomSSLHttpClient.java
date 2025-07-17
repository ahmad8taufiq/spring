package com.example.spring.common;

import java.io.InputStream;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class CustomSSLHttpClient {
    public static HttpClient createHttpClientWithSSLFromClasspath(String trustStoreResourcePath, String trustStorePassword) throws Exception {
        // Load truststore from resources
        KeyStore trustStore = KeyStore.getInstance("PKCS12");

        try (InputStream trustStream = CustomSSLHttpClient.class.getClassLoader()
                .getResourceAsStream(trustStoreResourcePath)) {

            if (trustStream == null) {
                throw new RuntimeException("Truststore not found in classpath: " + trustStoreResourcePath);
            }

            trustStore.load(trustStream, trustStorePassword.toCharArray());
        }

        // Initialize TrustManager
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        TrustManager[] trustManagers = trustFactory.getTrustManagers();

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, new SecureRandom());

        // Return custom HttpClient
        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .build();
    }
}
