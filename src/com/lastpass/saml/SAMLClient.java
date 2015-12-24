/*
 * SAMLClient - Main interface module for service providers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Copyright (c) 2014-2015 LastPass, Inc.
 */
package com.lastpass.saml;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.InputSource;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.zip.Deflater;


/**
 * A SAMLClient acts as on behalf of a SAML Service
 * Provider to generate requests and process responses.
 *
 * To integrate a service, one must generally do the
 * following:
 *
 *  1. Change the login process to call
 *     generateAuthnRequest() to get a request and link,
 *     and then GET/POST that to the IdP login URL.
 *
 *  2. Create a new URL that acts as the
 *     AssertionConsumerService -- it will call
 *     validateResponse on the response body to
 *     verify the assertion; on success it will
 *     use the subject as the authenticated user for
 *     the web application.
 *
 * The specific changes needed to the application are
 * outside the scope of this SDK.
 */
public class SAMLClient
{
    private SPConfig spConfig;
    private IdPConfig idpConfig;
    private SignatureValidator sigValidator;
    private BasicParserPool parsers;
    private PrivateKey privateKey;

    /* do date comparisons +/- this many seconds */
    private static final int slack = 300;

    /**
     * Create a new SAMLClient, using the IdPConfig for
     * endpoints and validation.
     */
    public SAMLClient(SPConfig spConfig, IdPConfig idpConfig) throws SAMLException
    {
        this.spConfig = spConfig;
        this.idpConfig = idpConfig;

        BasicCredential cred = new BasicCredential();
        cred.setEntityId(idpConfig.getEntityId());
        cred.setPublicKey(idpConfig.getCert().getPublicKey());

        sigValidator = new SignatureValidator(cred);

        // create xml parsers
        parsers = new BasicParserPool();
        parsers.setNamespaceAware(true);
    }

    /**
     * Create a new SAMLClient, using the IdPConfig for
     * endpoints and validation. SP's private key is passed
     * in so encrypted assertions can be decrypted.
     */
    public SAMLClient(SPConfig spConfig, IdPConfig idpConfig, PrivateKey privateKey) throws SAMLException
    {
        this(spConfig, idpConfig);
        this.privateKey = privateKey;

    }

    /**
     * Get the configured IdpConfig.
     *
     * @return the IdPConfig associated with this client
     */
    public IdPConfig getIdPConfig()
    {
        return idpConfig;
    }

    /**
     * Get the configured SPConfig.
     *
     * @return the SPConfig associated with this client
     */
    public SPConfig getSPConfig()
    {
        return spConfig;
    }

    private Response parseResponse(String authnResponse)
        throws SAMLException
    {
        BasicParserPool parsers = new BasicParserPool();
        parsers.setNamespaceAware(true);
        try {
            Document doc = parsers.getBuilder()
                .parse(new InputSource(new StringReader(authnResponse)));

            Element root = doc.getDocumentElement();

            // this fixes the "Cannot resolve element with ID" exception.
            root.setIdAttribute("ID", true);

            return (Response) Configuration.getUnmarshallerFactory()
                .getUnmarshaller(root)
                .unmarshall(root);
        }
        catch (org.opensaml.xml.parse.XMLParserException e) {
            throw new SAMLException(e);
        }
        catch (org.opensaml.xml.io.UnmarshallingException e) {
            throw new SAMLException(e);
        }
        catch (org.xml.sax.SAXException e) {
            throw new SAMLException(e);
        }
        catch (java.io.IOException e) {
            throw new SAMLException(e);
        }
    }

    private Assertion decryptEncryptedAssertion(EncryptedAssertion encryptedAssertion, BasicCredential spPrivateKeyCredential) throws DecryptionException
    {
        StaticKeyInfoCredentialResolver staticKeyResolver = new StaticKeyInfoCredentialResolver(spPrivateKeyCredential);
        InlineEncryptedKeyResolver inlineEncryptedKeyResolver = new InlineEncryptedKeyResolver();

        Decrypter decrypter = new Decrypter(null, staticKeyResolver, inlineEncryptedKeyResolver);
        decrypter.setRootInNewDocument(true);

        return decrypter.decrypt(encryptedAssertion);
    }

    private void validate(Response response)
        throws ValidationException
    {
        // response signature must match IdP's key, if present
        Signature sig = response.getSignature();
        if (sig != null)
            sigValidator.validate(sig);

        // response must be successful
        if (response.getStatus() == null ||
            response.getStatus().getStatusCode() == null ||
            !(StatusCode.SUCCESS_URI
                .equals(response.getStatus().getStatusCode().getValue()))) {
            throw new ValidationException(
                "Response has an unsuccessful status code");
        }

        // response destination must match ACS
        if (!spConfig.getAcs().equals(response.getDestination()))
            throw new ValidationException(
                "Response is destined for a different endpoint");

        DateTime now = DateTime.now();

        // issue instant must be within a day
        DateTime issueInstant = response.getIssueInstant();

        if (issueInstant != null) {
            if (issueInstant.isBefore(now.minusDays(1).minusSeconds(slack)))
                throw new ValidationException(
                    "Response IssueInstant is in the past");

            if (issueInstant.isAfter(now.plusDays(1).plusSeconds(slack)))
                throw new ValidationException(
                    "Response IssueInstant is in the future");
        }

        List<Assertion> assertions;
        try {
            assertions = parseAllAssertions(response);
        } catch(SAMLException ex) {
            throw new ValidationException("no assertions found.");
        }

        for (Assertion assertion: assertions) {
            // Assertion must be signed correctly
            if (!assertion.isSigned())
                throw new ValidationException(
                    "Assertion must be signed");

            sig = assertion.getSignature();
            sigValidator.validate(sig);

            // Assertion must contain an authnstatement
            // with an unexpired session
            if (assertion.getAuthnStatements().isEmpty()) {
                throw new ValidationException(
                    "Assertion should contain an AuthnStatement");
            }
            for (AuthnStatement as: assertion.getAuthnStatements()) {
                DateTime sessionTime = as.getSessionNotOnOrAfter();
                if (sessionTime != null) {
                    DateTime exp = sessionTime.plusSeconds(slack);
                    if (exp != null &&
                            (now.isEqual(exp) || now.isAfter(exp)))
                        throw new ValidationException(
                                "AuthnStatement has expired");
                }
            }

            if (assertion.getConditions() == null) {
                throw new ValidationException(
                    "Assertion should contain conditions");
            }

            // Assertion IssueInstant must be within a day
            DateTime instant = assertion.getIssueInstant();
            if (instant != null) {
                if (instant.isBefore(now.minusDays(1).minusSeconds(slack)))
                    throw new ValidationException(
                        "Response IssueInstant is in the past");

                if (instant.isAfter(now.plusDays(1).plusSeconds(slack)))
                    throw new ValidationException(
                        "Response IssueInstant is in the future");
            }

            // Conditions must be met by current time
            Conditions conditions = assertion.getConditions();
            DateTime notBefore = conditions.getNotBefore();
            DateTime notOnOrAfter = conditions.getNotOnOrAfter();

            if (notBefore == null || notOnOrAfter == null)
                throw new ValidationException(
                    "Assertion conditions must have limits");

            notBefore = notBefore.minusSeconds(slack);
            notOnOrAfter = notOnOrAfter.plusSeconds(slack);

            if (now.isBefore(notBefore))
                throw new ValidationException(
                    "Assertion conditions is in the future");

            if (now.isEqual(notOnOrAfter) || now.isAfter(notOnOrAfter))
                throw new ValidationException(
                    "Assertion conditions is in the past");

            // If subjectConfirmationData is included, it must
            // have a recipient that matches ACS, with a valid
            // NotOnOrAfter
            Subject subject = assertion.getSubject();
            if (subject != null &&
                !subject.getSubjectConfirmations().isEmpty()) {
                boolean foundRecipient = false;
                for (SubjectConfirmation sc: subject.getSubjectConfirmations()) {
                    if (sc.getSubjectConfirmationData() == null)
                        continue;

                    SubjectConfirmationData scd = sc.getSubjectConfirmationData();
                    if (scd.getNotOnOrAfter() != null) {
                        DateTime chkdate = scd.getNotOnOrAfter().plusSeconds(slack);
                        if (now.isEqual(chkdate) || now.isAfter(chkdate)) {
                            throw new ValidationException(
                                "SubjectConfirmationData is in the past");
                        }
                    }

                    if (spConfig.getAcs().equals(scd.getRecipient()))
                        foundRecipient = true;
                }

                if (!foundRecipient)
                    throw new ValidationException(
                        "No SubjectConfirmationData found for ACS");
            }

            // audience must include intended SP issuer
            if (conditions.getAudienceRestrictions().isEmpty())
                throw new ValidationException(
                    "Assertion conditions must have audience restrictions");

            // only one audience restriction supported: we can only
            // check against the single SP.
            if (conditions.getAudienceRestrictions().size() > 1)
                throw new ValidationException(
                    "Assertion contains multiple audience restrictions");

            AudienceRestriction ar = conditions.getAudienceRestrictions()
                .get(0);

            // at least one of the audiences must match our SP
            boolean foundSP = false;
            for (Audience a: ar.getAudiences()) {
                if (spConfig.getEntityId().equals(a.getAudienceURI()))
                    foundSP = true;
            }
            if (!foundSP)
                throw new ValidationException(
                    "Assertion audience does not include issuer");
        }
    }

    @SuppressWarnings("unchecked")
    private String createAuthnRequest(String requestId)
        throws SAMLException
    {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        SAMLObjectBuilder<AuthnRequest> builder =
            (SAMLObjectBuilder<AuthnRequest>) builderFactory
            .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);

        SAMLObjectBuilder<Issuer> issuerBuilder =
            (SAMLObjectBuilder<Issuer>) builderFactory
            .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        AuthnRequest request = builder.buildObject();
        request.setAssertionConsumerServiceURL(spConfig.getAcs().toString());
        request.setDestination(idpConfig.getLoginUrl().toString());
        request.setIssueInstant(new DateTime());
        request.setID(requestId);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(spConfig.getEntityId());
        request.setIssuer(issuer);

        try {
            // samlobject to xml dom object
            Element elem = Configuration.getMarshallerFactory()
                .getMarshaller(request)
                .marshall(request);

            // and to a string...
            Document document = elem.getOwnerDocument();
            DOMImplementationLS domImplLS = (DOMImplementationLS) document
                .getImplementation();
            LSSerializer serializer = domImplLS.createLSSerializer();
            serializer.getDomConfig().setParameter("xml-declaration", false);
            return serializer.writeToString(elem);
        }
        catch (MarshallingException e) {
            throw new SAMLException(e);
        }
    }

    private byte[] deflate(byte[] input)
        throws IOException
    {
        // deflate and base-64 encode it
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(input);
        deflater.finish();

        byte[] tmp = new byte[8192];
        int count;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            count = deflater.deflate(tmp);
            bos.write(tmp, 0, count);
        }
        bos.close();
        deflater.end();

        return bos.toByteArray();
    }

    /**
     * Create a new AuthnRequest suitable for sending to an HTTPRedirect
     * binding endpoint on the IdP.  The SPConfig will be used to fill
     * in the ACS and issuer, and the IdP will be used to set the
     * destination.
     *
     * @return a deflated, base64-encoded AuthnRequest
     */
    public String generateAuthnRequest(String requestId)
        throws SAMLException
    {
        String request = createAuthnRequest(requestId);

        try {
            byte[] compressed = deflate(request.getBytes("UTF-8"));
            return DatatypeConverter.printBase64Binary(compressed);
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException(
                "Apparently your platform lacks UTF-8.  That's too bad.", e);
        } catch (IOException e) {
            throw new SAMLException("Unable to compress the AuthnRequest", e);
        }
    }

    protected List<Assertion> parseAllAssertions(Response response) throws SAMLException
    {
        List<Assertion> actualAssertions = new ArrayList<>();

        if (response.getAssertions().size() > 0) {
            actualAssertions = response.getAssertions();
        }

        if (response.getEncryptedAssertions().size() > 0) {
            BasicCredential cred = new BasicCredential();
            if (privateKey == null) {
                throw new SAMLException("Encrypted assertions found but no privateKey passed in.");
            }
            cred.setPrivateKey(privateKey);

            try {
                for (EncryptedAssertion eAssertion : response.getEncryptedAssertions()) {
                    actualAssertions.add(decryptEncryptedAssertion(eAssertion, cred));
                }
            } catch (DecryptionException ex) {
                throw new SAMLException("failed to decrypt assertions", ex);
            }
        }

        return actualAssertions;
    }

    /**
     * Check an authnResponse and return the subject if validation
     * succeeds.  The NameID from the subject in the first valid
     * assertion is returned along with the attributes.
     *
     * @param authnResponse a base64-encoded AuthnResponse from the SP
     * @throws SAMLException if validation failed.
     * @return the authenticated subject/attributes as an AttributeSet
     */
    public AttributeSet validateResponse(String authnResponse)
        throws SAMLException
    {
        byte[] decoded = DatatypeConverter.parseBase64Binary(authnResponse);
        try {
            authnResponse = new String(decoded, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException("UTF-8 is missing, oh well.", e);
        }

        Response response = parseResponse(authnResponse);

        try {
            validate(response);
        } catch (ValidationException e) {
            throw new SAMLException(e);
        }

        List<Assertion> assertions = parseAllAssertions(response);
        // we only look at first assertion
        if (assertions.size() != 1) {
            throw new SAMLException(
                "Response should have a single assertion. There were " + assertions.size() + ".");
        }
        Assertion assertion = assertions.get(0);

        Subject subject = assertion.getSubject();
        if (subject == null) {
            throw new SAMLException(
                "No subject contained in the assertion.");
        }
        if (subject.getNameID() == null) {
            throw new SAMLException("No NameID found in the subject.");
        }

        String nameId = subject.getNameID().getValue();

        HashMap<String, List<String>> attributes =
            new HashMap<String, List<String>>();

        for (AttributeStatement atbs : assertion.getAttributeStatements()) {
            for (Attribute atb: atbs.getAttributes()) {
                String name = atb.getName();
                List<String> values = new ArrayList<String>();
                for (XMLObject obj : atb.getAttributeValues()) {
                    values.add(obj.getDOM().getTextContent());
                }
                attributes.put(name, values);
            }
        }
        return new AttributeSet(nameId, attributes);
    }
}
