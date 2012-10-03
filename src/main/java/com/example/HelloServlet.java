package com.example;

import com.salesforce.saml.sp.Identity;
import com.salesforce.saml.sp.SAMLValidator;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HelloServlet extends HttpServlet {


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


	@Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        ServletOutputStream out = resp.getOutputStream();
        String encodedResponse = req.getParameter("SAMLResponse");

        SAMLValidator sv = new SAMLValidator();
        try {
            Identity identity = sv.validate(encodedResponse, cert, "https://identity.prerelna1.pre.my.salesforce.com", "https://samlsp.herokuapp.com/hello", "https://samlsp.herokuapp.com/hello");
            if (identity != null) out.write(identity.getSubject().getBytes("UTF-8"));
        } catch (Exception e) {
            out.write(e.getMessage().getBytes());
        }
        out.flush();
        out.close();

    }
    
}
