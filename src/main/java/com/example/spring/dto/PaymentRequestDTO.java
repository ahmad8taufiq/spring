package com.example.spring.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class PaymentRequestDTO {
    @JsonProperty("traceReference")
    private String traceReference;
    
    @JsonProperty("service")
    private String service;
    
    @JsonProperty("type")
    private String type;
    
    @JsonProperty("sender")
    private String sender;
    
    @JsonProperty("receiver")
    private String receiver;
    
    @JsonProperty("document")
    private String document;
    
    // Getters and Setters
    public String getTraceReference() { return traceReference; }
    public void setTraceReference(String traceReference) { this.traceReference = traceReference; }
    
    public String getService() { return service; }
    public void setService(String service) { this.service = service; }
    
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public String getSender() { return sender; }
    public void setSender(String sender) { this.sender = sender; }
    
    public String getReceiver() { return receiver; }
    public void setReceiver(String receiver) { this.receiver = receiver; }
    
    public String getDocument() { return document; }
    public void setDocument(String document) { this.document = document; }
}
