<%
session.invalidate(); 
response.sendRedirect("https://" + request.getServerName());
%>
