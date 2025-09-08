package Peticiones;

import com.google.gson.Gson;

public class InitiateAuthentication {
    private String euiccChallenge;
    private String euiccInfo1;
    private String smdpAddress;

    public InitiateAuthentication(String euiccChallenge, String euiccInfo1, String smdpAddress) {
        this.euiccChallenge = euiccChallenge;
        this.euiccInfo1 = euiccInfo1;
        this.smdpAddress = smdpAddress;
    }

    public String toJsonString() {
        return new Gson().toJson(this);
    }
}
