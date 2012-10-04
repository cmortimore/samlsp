package com.salesforce.saml.sp;

import com.salesforce.saml.Identity;
import com.salesforce.util.RandomGUID;
import com.salesforce.util.XSDDateTime;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.text.MessageFormat;
import java.util.zip.Deflater;


public class SAMLFilter implements Filter {

    private FilterConfig config = null;

    private static final String IDENTITY = "IDENTITY";

    private static final String requestTemplate = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"{0}\" Destination=\"{1}\" ID=\"_{2}\" IssueInstant=\"{3}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{4}</saml:Issuer></samlp:AuthnRequest>";


    private static String cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEZzCCA0+gAwIBAgIOATmUyEXBAAAAAHD3/AswDQYJKoZIhvcNAQEFBQAwezET\n" +
            "MBEGA1UEAwwKTXkgQ29tcGFueTEYMBYGA1UECwwPMDBEeDAwMDAwMDA5VlFtMRcw\n" +
            "FQYDVQQKDA5TYWxlc2ZvcmNlLmNvbTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEL\n" +
            "MAkGA1UECAwCQ0ExDDAKBgNVBAYTA1VTQTAeFw0xMjA5MDUwNDU1MTZaFw0xNDA5\n" +
            "MDUwNDU1MTZaMHsxEzARBgNVBAMMCk15IENvbXBhbnkxGDAWBgNVBAsMDzAwRHgw\n" +
            "MDAwMDAwOVZRbTEXMBUGA1UECgwOU2FsZXNmb3JjZS5jb20xFjAUBgNVBAcMDVNh\n" +
            "biBGcmFuY2lzY28xCzAJBgNVBAgMAkNBMQwwCgYDVQQGEwNVU0EwggEiMA0GCSqG\n" +
            "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXwDWO73cu3rHisGl3aQ60ZyGBQRkw5NDT\n" +
            "D8b73fqb0oA16tfF7YrDYZsUXC31rE6AmPHHPLPaNTShVF9ZpQ8w2dO9QM0W0ZD1\n" +
            "JWLYPITtmWIRs9/nvUhjoirwvJt3eypvcC31OFIjylH/7HFEprOUD3BjW9qT/yp8\n" +
            "SamPGx2YpgWni6S8cIoAqr+uPUtEK2F6VX/Aye/WsgEo2x6y93hUy53gflFL+Xl3\n" +
            "9uGssCUAjcwtiMreZS2Ph4ZknGnWMWjPsPAXOdoQ0Yi0c6FUXwqfTqBADLwRRUxr\n" +
            "X9hMcWYO/eo2SWGdS+T2/7CtN1u4sSXEjUroup50gp0/784fh+AbAgMBAAGjgegw\n" +
            "geUwHQYDVR0OBBYEFI4QaUhc99/m46kEW0E8ZyykSjSSMIGyBgNVHSMEgaowgaeA\n" +
            "FI4QaUhc99/m46kEW0E8ZyykSjSSoX+kfTB7MRMwEQYDVQQDDApNeSBDb21wYW55\n" +
            "MRgwFgYDVQQLDA8wMER4MDAwMDAwMDlWUW0xFzAVBgNVBAoMDlNhbGVzZm9yY2Uu\n" +
            "Y29tMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQswCQYDVQQIDAJDQTEMMAoGA1UE\n" +
            "BhMDVVNBgg4BOZTIRcMAAAAAcPf8CzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n" +
            "DQEBBQUAA4IBAQA0JS456PwGdIKakhcVuL4xARwRLuonAvcdPdyL6NjkxrouZW7e\n" +
            "Qss1LdqKGUyv6zJxJWqWrHG/TE8FlR3KJRuled/WEVAXFfjpFTO40yiNDs4U6ih9\n" +
            "PTeS6ke/rVvM6QUO6Tvdjdn6HIMb+EIb3ByuAknaoEDwxzy+6fEshMRtiPg8mP+X\n" +
            "rnjrAZkH0DF65WTLMcnU6pFBmaNOweTVoJ2GGrZ7yL3Ss3D7gSLDdPbEoID1xZ42\n" +
            "3EJaxSr96di3EZqSIGZITS90izrLd66lcoStMiE0zF/wTe5qVSZb4AK+aGCZ9u5q\n" +
            "HUOfjYRru3Gqm5M4QFnRZRto5lLDWz6nfGMQ\n" +
            "-----END CERTIFICATE-----";


    public void init(FilterConfig filterConfig) throws ServletException {
        config = filterConfig;
        //clientId = config.getInitParameter("client_id");


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
                byte[] output = new byte[10000];
                Deflater compresser = new Deflater();
                compresser.setInput(input);
                compresser.finish();
                int compressedDataLength = compresser.deflate(output);
                System.out.println("LENGHT OF OUTPUT ------> " + compressedDataLength);
                String encodedRequest = Base64.encodeBase64String(output);
                String SAMLRequest = URLEncoder.encode(encodedRequest,"UTF-8");

                httpResponse.sendRedirect("https://identity.prerelna1.pre.my.salesforce.com/idp/endpoint/HttpRedirect?SAMLRequest=" + SAMLRequest + "&RelayState=" + httpRequest.getRequestURI());
                return;
            }


        }

        chain.doFilter (request, response);

    }

}
