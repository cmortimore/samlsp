<%@ page import="com.salesforce.saml.Identity,com.salesforce.util.Bag,java.util.Set,java.util.Iterator,java.util.ArrayList" %>
<style> body{font-family: Helvetica} </style>
<body>


<%

Identity identity = (Identity) session.getAttribute("IDENTITY");
if (identity != null) {
	
%>
<h2>You are logged in as: <%= identity.getSubject() %></h2>
<table border="1" cellpadding="5">
<%
	Bag attributes = identity.attributes;
	Set keySet = attributes.keySet();
	Iterator iterator = keySet.iterator(); 
	while (iterator.hasNext()){
		String key = (String)iterator.next();
		%><tr><td><b><%= key %>:</b></td><td><%
		ArrayList<String> values = (ArrayList<String>)attributes.getValues(key);
		for (String value : values) {
			%><%= value %><br/><%
		}
		%></td></tr><%
		
	}

}
%>
</table>

<p><a href="/logout.jsp">logout</a></p>
</body>