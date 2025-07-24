package com.example.spring.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;

import com.example.spring.dto.PaymentRequestDTO;
import com.example.spring.common.CustomSSLHttpClient;
import com.fasterxml.jackson.databind.ObjectMapper;

public class PaymentApiService {
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    public PaymentApiService() {
        try {
            this.httpClient = CustomSSLHttpClient.createHttpClientWithSSLFromClasspath(
                "truststore.keystore",     // truststore file in resources
                "Coin10c10000"            // truststore password
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize custom SSL HttpClient", e);
        }

        this.objectMapper = new ObjectMapper();
    }

    public String sendPaymentRequest(PaymentRequestDTO paymentRequest) throws Exception {
        // Generate random UUID for the endpoint
        String randomUuid = UUID.randomUUID().toString();
        String url = "https://138.2.101.253:23432/input/" + randomUuid;
        
        // Convert request object to JSON
        String jsonBody = objectMapper.writeValueAsString(paymentRequest);
        
        // Build HTTP request
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer eyJ4NXQjUzI1NiI6IjZmN1ZvUHhCaVl5dFBNN1lmZmc2TUlEWmFaX1ZtdGRlLWZGQlhfWGJiM2MiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJLSVJVQk5CQkZOUlQiLCJhc3J2X3R5cGUiOiJhY2Nlc3MiLCJleHAiOjQ4NzUwNjI2MjIsImlhdCI6MTc1Mjk5ODYyMiwianRpIjoiM1BUOUEtYlFUZUdyY291aFN1aUM5USJ9.dt46wB64RasoSzPV9tDLRxAZ1_4DlWoc31fL2FuqbCuzA_oOv5CcS_NnOIx2rEjFg20JaNov7T33X6qtbFhJVDLSNw46njZsZ76u6DE2HX6RDem4XOKrSNZyqU6UNHnDvbyIcIw8AYdFSN5i3V47FYCniC_Atue-FCV2OICi-7rMB9GBivJl6vyMnohSrgSPDUptoSSkMQJfK911ExQCdzbDG0JYDcerXi4AtGO-zYFgcjzAWC-jSwRdLQmLRS2atjAz803Q2ZYzBJM5TxNIVHYoAollrRV_myRbDhHS8qW8w4irgQzmQ5LVrzWWus7Lf0yaKqijtypdHRRYXA8JGQ")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .timeout(Duration.ofSeconds(30))
            .build();
        
        // Send request and get response
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
        
        // Handle response
        if (response.statusCode() == 200) {
            return response.body();
        } else {
            throw new RuntimeException("API call failed with status: " + response.statusCode() + 
                ", body: " + response.body());
        }
    }
}
