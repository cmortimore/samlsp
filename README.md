# Simple SAML 2 Java SP

A simple filter that allows a java app to act as a SAML Service Provider.   Implements SAML Redirect Binding for SAML Requests and SAML POST Binding for Responses.   

Grab the code, and then add the filter in your web.xml.   You can see an example of configuration here:  https://github.com/cmortimore/samlsp/blob/master/src/main/webapp/WEB-INF/web.xml

If you'd like a simple library to use, run ant in the 'packager' directory, and it'll build you a Jar.

