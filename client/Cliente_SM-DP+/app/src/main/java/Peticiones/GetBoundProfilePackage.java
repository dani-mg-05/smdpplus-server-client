package Peticiones;

import com.google.gson.Gson;

public class GetBoundProfilePackage {
    private String transactionId;
    private String prepareDownloadResponse;

    public GetBoundProfilePackage(String transactionId, String prepareDownloadResponse) {
        this.transactionId = transactionId;
        this.prepareDownloadResponse = prepareDownloadResponse;
    }

    public String toJsonString() {
        return new Gson().toJson(this);
    }
}
