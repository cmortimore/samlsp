<%@ page import="com.salesforce.saml.Identity,java.util.Iterator,java.util.Map" %>
<style> body{font-family: Helvetica} </style>
<body>


<%

Identity identity = (Identity) session.getAttribute("IDENTITY");
if (identity != null) {
	
%>
<h2>You are logged in as: <%= identity.getSubject() %></h2>

<%
	
    Iterator it = identity.entrySet().iterator();
    while (it.hasNext()) {
        Map.Entry pairs = (Map.Entry)it.next();
		%><b><%= pairs.getKey() %>:</b><%= pairs.getValue() %><br/><%
        it.remove(); 
    }

}
%>

<p><a href="/logout.jsp">logout</a></p>
</body>