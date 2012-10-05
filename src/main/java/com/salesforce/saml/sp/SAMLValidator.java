package com.salesforce.saml.sp;

import com.salesforce.saml.Identity;
import com.salesforce.saml.SAMLException;
import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.*;
import java.io.*;

import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;


public class SAMLValidator {

    public Identity validate(String encodedResponse, String cert, String issuer, String recipient, String audience) throws Exception {

        Identity identity = null;
        boolean isValid = false;

        //Build the document
        String response = new String(Base64.decodeBase64(encodedResponse.getBytes("UTF-8")),"UTF-8");
        System.out.println("Processing Assertion: " + response);
        DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
        domFactory.setNamespaceAware(true);
        DocumentBuilder builder = domFactory.newDocumentBuilder();
        Document responseDocument = builder.parse(new InputSource(new ByteArrayInputStream(response.getBytes("UTF-8"))));

        //Setup XPath
        NamespaceContext namespaceContext = new SAMLNamespaceResolver();
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(namespaceContext);
        XPathExpression responseXPath = xpath.compile("/samlp:Response");
        XPathExpression responseSignatureXPath = xpath.compile("/samlp:Response/ds:Signature");
        XPathExpression assertionXPath = xpath.compile("/samlp:Response/saml:Assertion");
        XPathExpression assertionSignatureXPath = xpath.compile("/samlp:Response/saml:Assertion/ds:Signature");
        XPathExpression issuerXPath = xpath.compile("saml:Issuer");
        XPathExpression nameIDXPath = xpath.compile("saml:Subject/saml:NameID");
        XPathExpression subjectConfirmationDataXPath = xpath.compile("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData");
        XPathExpression conditionsXPath = xpath.compile("saml:Conditions");
        XPathExpression audienceXPath = xpath.compile("saml:Conditions/saml:AudienceRestriction/saml:Audience");
        XPathExpression attributeXPath = xpath.compile("/samlp:Response/saml:Assertion/saml:AttributeStatement");


        //Get the Response node and fail if more than one
        NodeList responseXPathResult = (NodeList) responseXPath.evaluate(responseDocument, XPathConstants.NODESET);
        if (responseXPathResult.getLength() != 1) throw new SAMLException("More than 1 Response");
        Node responseNode = responseXPathResult.item(0);

        //Get the Assertion node and fail if more than one
        NodeList assertionXPathResult = (NodeList) assertionXPath.evaluate(responseDocument, XPathConstants.NODESET);
        if (assertionXPathResult.getLength() != 1) throw new SAMLException("More than 1 Assertion");
        Node assertionNode = assertionXPathResult.item(0);

        //See if the response is signed
        NodeList responseXPathSignatureResult = (NodeList) responseSignatureXPath.evaluate(responseDocument, XPathConstants.NODESET);

        if (responseXPathSignatureResult.getLength() > 1) {

            throw new SAMLException("More than 1 Response Signature");

        } else if (responseXPathSignatureResult.getLength() == 1) {

            //Check the response signature
            String responseId = responseNode.getAttributes().getNamedItem("ID").getTextContent();
            Node signature = responseXPathSignatureResult.item(0);
            isValid = validateSignature(signature, responseId, cert);

        } else {

            //No response signature.  Check the assertion signature
            NodeList assertionSignatureXPathResult = (NodeList) assertionSignatureXPath.evaluate(responseDocument, XPathConstants.NODESET);
            if (assertionSignatureXPathResult.getLength() > 1) {
                throw new SAMLException("More than 1 Assertion Signature");
            } else if (assertionSignatureXPathResult.getLength() ==1 ) {
                String assertionId = assertionNode.getAttributes().getNamedItem("ID").getTextContent();
                Node signature = assertionSignatureXPathResult.item(0);
                isValid = validateSignature(signature, assertionId, cert);
            } else throw new SAMLException("No Signature");

        }

        if (isValid) {

            //check the issuer
            Node issuerNode = (Node) issuerXPath.evaluate(assertionNode, XPathConstants.NODE);
            String assertedIssuer = issuerNode.getTextContent();
            if (!issuer.equals(assertedIssuer)) throw new SAMLException("Invalid Issuer");

            //check the recipient
            Node subjectConfirmationDataNode = (Node) subjectConfirmationDataXPath.evaluate(assertionNode, XPathConstants.NODE);
            String assertedRecipient = subjectConfirmationDataNode.getAttributes().getNamedItem("Recipient").getTextContent();
            if (!recipient.equals(assertedRecipient)) throw new SAMLException("Invalid Recipient");

            //check the audience
            Node audienceNode = (Node) audienceXPath.evaluate(assertionNode, XPathConstants.NODE);
            String assertedAudience = audienceNode.getTextContent();
            if (!audience.equals(assertedAudience)) throw new SAMLException("Invalid Audience");

            //Check the validity
            Node conditionsNode = (Node) conditionsXPath.evaluate(assertionNode, XPathConstants.NODE);
            String notOnOrAfter = conditionsNode.getAttributes().getNamedItem("NotOnOrAfter").getTextContent();
            String notBefore = conditionsNode.getAttributes().getNamedItem("NotBefore").getTextContent();
            Calendar start = DatatypeConverter.parseDateTime(notBefore);
            Calendar end = DatatypeConverter.parseDateTime(notOnOrAfter);
            if ( System.currentTimeMillis() <= start.getTimeInMillis() ) throw new SAMLException("Assertion appears to have arrived early");
            if ( System.currentTimeMillis() > end.getTimeInMillis() ) throw new SAMLException("Assertion Expired");

            //get the subject
            Node nameIdNode = (Node) nameIDXPath.evaluate(assertionNode, XPathConstants.NODE);
            identity = new Identity(nameIdNode.getTextContent());

            NodeList attributeXPathResult = (NodeList) attributeXPath.evaluate(responseDocument, XPathConstants.NODESET);
            for(int i = 0; i < attributeXPathResult.getLength(); i++) {
                Node attributeStatement = attributeXPathResult.item(i);
                NodeList attributes = attributeStatement.getChildNodes();
                for(int j = 0; j < attributes.getLength(); j++) {
                    Node attribute = attributes.item(j);
                    String name = attribute.getAttributes().getNamedItem("Name").getTextContent();
                    String value = attribute.getFirstChild().getTextContent();
                    identity.attributes.put(name,value);
                }
            }

        } else {

            throw new SAMLException("Invalid Signature");

        }

        return identity;
        
    }

    private boolean validateSignature(Node signature, String id, String cert) throws Exception {

        //parse PEM
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cert.getBytes("UTF-8")));


        DOMValidateContext valContext = new DOMValidateContext (certificate.getPublicKey(), signature);
        XMLSignatureFactory xsf = XMLSignatureFactory.getInstance("DOM");
        XMLSignature xs = xsf.unmarshalXMLSignature(valContext);

        List<Reference> references = xs.getSignedInfo().getReferences();
        if (references.size() != 1) throw new SAMLException("1 and Only 1 Reference is allowed");
        Reference ref = references.get(0);
        String refURI = ref.getURI();
        if ((refURI != null) && (!refURI.equals(""))) {
            String refURIStripped = refURI.substring(1);
            if (!id.equals(refURIStripped)) throw new SAMLException("Signature Reference is NOT targeting enveloping node: " + id + "|" + refURIStripped);
        }

        return xs.validate(valContext);

    }


    class SAMLNamespaceResolver implements NamespaceContext {

        public String getNamespaceURI(String prefix) {
            if (prefix == null) {
                throw new IllegalArgumentException("No prefix provided!");
            } else if (prefix.equals("samlp")) {
                return "urn:oasis:names:tc:SAML:2.0:protocol";
            } else if (prefix.equals("saml")) {
                return "urn:oasis:names:tc:SAML:2.0:assertion";
            } else if (prefix.equals("ds")) {
                return "http://www.w3.org/2000/09/xmldsig#";
            } else return null;

        }

        public String getPrefix(String namespaceURI) {
            return null;
        }

        public Iterator getPrefixes(String namespaceURI) {
            return null;
        }

    }

}