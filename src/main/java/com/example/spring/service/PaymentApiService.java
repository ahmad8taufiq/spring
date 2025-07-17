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
            .header("Authorization", "Bearer eyJ4NXQjUzI1NiI6IjZmN1ZvUHhCaVl5dFBNN1lmZmc2TUlEWmFaX1ZtdGRlLWZGQlhfWGJiM2MiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJLSVJVQk5CQkZOUlQiLCJhc3J2X3R5cGUiOiJhY2Nlc3MiLCJleHAiOjQ4NzQ3MzA5NjUsImlhdCI6MTc1MjY2Njk2NSwianRpIjoidjhhb3hUdWNTV3FNdmNIckJwaDJhZyJ9.d6R1yHizkN47rjIEw49GsrUsx03-iJWxsxbZVoF59e5LebjzsqU9CG_vRRi0imkYw9p6uVAAgd2WSL4tMbMST4ImuTD23nynx6w3u2vqRJoPBSWH3OrEt1kba92TZB_qYZFZWsO-d2Tlmm0_P3rx61qJ4lz9YMOlwJ-Q-Sq1Sn6qkLusbwl6qNBibimT83f81x0O7_BoTUVVPP2msuAT9AjE_gT2EdqUdMDua0B9m4TY_yxPDYtMYmHAo89tNCcpWi26gLDGikO_LkBZUr-Ku0OctFlNLodSCkbnMGMJGeEYLRqBORDuM9luGoOaPZafxBW0UMv6Gkm4h4IzOnX-Xg")
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
