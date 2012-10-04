<%@ page import="com.salesforce.saml.Identity" %>

<h2>SAML SP</h2>

<%
    Identity identity = (Identity) req.getSession().getAttribute("IDENTITY");

    if (identity != null) {
        out.println(identity);
        out.println(identity.attributes.toString());
    }

%>