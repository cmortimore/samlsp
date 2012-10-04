package com.example;

import com.salesforce.saml.Identity;
import com.salesforce.saml.SAMLException;
import com.salesforce.saml.sp.SAMLValidator;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HelloServlet extends HttpServlet {

	@Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        ServletOutputStream out = resp.getOutputStream();

        Identity identity = req.getSession().getAttribute("IDENTITY")

        if (identity != null) {
            out.write(identity.getSubject().getBytes("UTF-8"));
            out.write(identity.attributes.toString().getBytes("UTF-8"));
        }

        out.flush();
        out.close();

    }
    
}
