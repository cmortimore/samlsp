package com.salesforce.saml;

public class SAMLException extends Exception{

    public SAMLException() {
        super();
    }

    public SAMLException(String s) {
        super(s);
    }

    public SAMLException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public SAMLException(Throwable throwable) {
        super(throwable);
    }

}
