<%@ page import="com.salesforce.saml.Identity" %>

<h2>You are logged in as: </h2>

<%
    Identity identity = (Identity) session.getAttribute("IDENTITY");
    if (identity != null) {
        out.println(identity.getSubject());
        out.println(identity.attributes.toString());
    }

%>

<p><a href="/logout.jsp">logout</a></p>