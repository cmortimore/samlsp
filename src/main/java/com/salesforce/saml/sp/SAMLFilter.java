package com.salesforce.saml.sp;

import com.salesforce.saml.Identity;
import com.salesforce.util.RandomGUID;
import com.salesforce.util.XSDDateTime;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.text.MessageFormat;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;


public class SAMLFilter implements Filter {

    private FilterConfig config = null;

    private static final String IDENTITY = "IDENTITY";

    private static final String requestTemplate = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"{0}\" Destination=\"{1}\" ID=\"_{2}\" IssueInstant=\"{3}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{4}</saml:Issuer></samlp:AuthnRequest>";


    private static String cert;

    public void init(FilterConfig filterConfig) throws ServletException {
        config = filterConfig;
        cert = config.getInitParameter("cert");


    }

    public void destroy() {
    }


    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest)request;
        HttpServletResponse httpResponse = (HttpServletResponse)response;
        HttpSession session = httpRequest.getSession(true);
        Identity identity = (Identity)session.getAttribute(IDENTITY);
        if (identity == null) {

            if (httpRequest.getRequestURI().equals("/_saml")) {

                String encodedResponse = httpRequest.getParameter("SAMLResponse");
                String relayState = request.getParameter("RelayState");
                if ((relayState == null) || ( relayState.equals(""))) relayState = "/";

                SAMLValidator sv = new SAMLValidator();
                try {
                    identity = sv.validate(encodedResponse, cert, "https://identity.prerelna1.pre.my.salesforce.com", "https://samlsp.herokuapp.com/_saml", "https://samlsp.herokuapp.com/");
                    session.setAttribute(IDENTITY, identity);
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new ServletException(e);
                }
                httpResponse.sendRedirect(relayState);
                return;

            }  else {
                //we need to send the user to login

                String[] args = new String[5];
                args[0] = "https://samlsp.herokuapp.com/_saml";
                args[1] = "https://identity.prerelna1.pre.my.salesforce.com/idp/endpoint/HttpRedirect";
                args[2] = new RandomGUID().toString();
                args[3] = new XSDDateTime().getDateTime();
                args[4] = "https://samlsp.herokuapp.com/";
                MessageFormat html;
                html = new MessageFormat(requestTemplate);
                String requestXml = html.format(args);
                byte[] input = requestXml.getBytes("UTF-8");
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                Deflater d = new Deflater(Deflater.DEFLATED, true);
                DeflaterOutputStream dout = new DeflaterOutputStream(baos, d);
                dout.write(input);
                dout.close();
                String encodedRequest = Base64.encodeBase64String(baos.toByteArray());
                String SAMLRequest = URLEncoder.encode(encodedRequest,"UTF-8");
                httpResponse.sendRedirect("https://identity.prerelna1.pre.my.salesforce.com/idp/endpoint/HttpRedirect?SAMLRequest=" + SAMLRequest + "&RelayState=" + httpRequest.getRequestURI());
                return;
            }


        }

        chain.doFilter (request, response);

    }

}
