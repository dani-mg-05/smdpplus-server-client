package Peticiones;

import com.google.gson.Gson;

public class AuthenticateClient {
    private String transactionId;
    private String authenticateServerResponse;

    public AuthenticateClient(String transactionId, String authenticateServerResponse) {
        this.transactionId = transactionId;
        this.authenticateServerResponse = authenticateServerResponse;
    }

    public String toJsonString() {
        return new Gson().toJson(this);
    }
}
