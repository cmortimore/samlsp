package com.salesforce.saml;

import com.salesforce.util.Bag;

public class Identity {

    private String subject;
    public Bag attributes;

    public Identity(String subject) {
        this.subject = subject;
        this.attributes = new Bag();
    }

    public String getSubject() {
        return subject;
    }

}
