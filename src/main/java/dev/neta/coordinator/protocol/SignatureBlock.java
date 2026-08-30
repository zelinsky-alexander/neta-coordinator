package dev.neta.coordinator.protocol;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SignatureBlock(String algorithm, @JsonProperty("key_id") String keyId, String value) {}
