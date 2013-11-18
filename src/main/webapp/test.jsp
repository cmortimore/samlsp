<%@ page import="com.salesforce.saml.Identity,com.salesforce.util.Bag,java.util.Set,java.util.Iterator,java.util.ArrayList" %>
<style> body{font-family: Helvetica} </style>
<body>


<%

Identity identity = (Identity) session.getAttribute("IDENTITY");
if (identity != null) {
	
%>
<h2>You are logged in as: <%= identity.getSubject() %></h2>

<%
	Bag attributes = identity.attributes;
	Set keySet = attributes.keySet();
	Iterator iterator = keySet.iterator(); 
	while (iterator.hasNext()){
		String key = (String)iterator.next();
		%><b><%= key %>:</b><%
		ArrayList<String> values = (ArrayList<String>)attributes.get(key);
		for (String value : values) {
			%><%= value %>&nbsp;&nbsp;&nbsp;&nbsp;<%
		}
		%><br/><%
		
	}

}
%>

<p><a href="/logout.jsp">logout</a></p>
</body>