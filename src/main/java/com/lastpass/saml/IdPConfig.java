/*
 * IdpConfig - configuration settings for an identity provider.
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
 * Copyright (c) 2014 LastPass, Inc.
 */
package com.lastpass.saml;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;

import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.bind.DatatypeConverter;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.config.SAMLConfiguration;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;



/**
 * IdpConfig contains information about the SAML 2.0 Identity Provider
 * that authenticates users for a service.  Generally, it will be
 * initialized by loading the metadata file from disk.
 */
public class IdPConfig
{
    /**
     * Default constructor.  Applications may use this if the
     * configuration information comes from some outside source.
     */
    public IdPConfig()
    {
    }

    /**
     * Construct a new IdpConfig from a metadata XML file.
     *
     * @param metadataFile File where the metadata lives
     *
     * @throws SAMLException if an error condition occurs while trying to parse and process
     *              the metadata
     */
    public IdPConfig(File metadataFile)
        throws SAMLException
    {
        FileInputStream inputStream;
        try {
            inputStream = new FileInputStream(metadataFile);        
        } 
        catch (java.io.IOException e) {
            throw new SAMLException(e);
        }
        
        try {
            init(inputStream);
        } finally {
            try {
                inputStream.close();
            }
            catch (java.io.IOException e) {
                //Ignore
            }
        }
    }

    /**
     * Construct a new IdpConfig from a metadata XML input stream.
     *
     * @param inputStream An input stream containing a metadata XML document
     *
     * @throws SAMLException if an error condition occurs while trying to parse and process
     *              the metadata
     */
    public IdPConfig(InputStream inputStream)
        throws SAMLException
    {
        init(inputStream);
    }

    private void init(InputStream inputStream)
            throws SAMLException
    {
        BasicParserPool parsers = new BasicParserPool();
        parsers.setNamespaceAware(true);
        try {
            parsers.initialize();
        } catch (ComponentInitializationException e) {
            throw new SAMLException("Failed to initialize BasicParserPool", e);
        }

        EntityDescriptor edesc;

        try {
            edesc = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(parsers, inputStream);
        }
        catch (XMLParserException e) {
            throw new SAMLException(e);
        }
        catch (UnmarshallingException e) {
            throw new SAMLException(e);
        }        

        // fetch idp information
        IDPSSODescriptor idpDesc = edesc.getIDPSSODescriptor(
                SAMLConstants.SAML20P_NS);

        if (idpDesc == null)
            throw new SAMLException("No IDP SSO descriptor found");

        // get the http-redirect binding
        String loginUrl = null;
        for (SingleSignOnService svc: idpDesc.getSingleSignOnServices()) {
            if (svc.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
                loginUrl = svc.getLocation();
                break;
            }
        }

        if (loginUrl == null)
            throw new SAMLException("No acceptable Single Sign-on Service found");

        // extract the first signing cert from the file
        Certificate cert = null;

        find_cert_loop:
        for (KeyDescriptor kdesc: idpDesc.getKeyDescriptors()) {
            if (kdesc.getUse() != UsageType.SIGNING)
                continue;

            KeyInfo ki = kdesc.getKeyInfo();
            if (ki == null)
                continue;

            for (X509Data x509data: ki.getX509Datas()) {
                for (X509Certificate xcert: x509data.getX509Certificates()) {
                    try {
                        cert = certFromString(xcert.getValue());
                        break find_cert_loop;
                    } catch (CertificateException e) {
                        // keep trying certs; if we don't have one we'll
                        // throw a SAMLException at the end.
                    }
                }
            }
        }
        if (cert == null)
            throw new SAMLException("No valid signing cert found");


        this.setEntityId(edesc.getEntityID());
        this.setLoginUrl(loginUrl);
        this.setCert(cert);
    }

    private Certificate certFromString(String b64data)
        throws CertificateException
    {
        byte[] decoded = DatatypeConverter.parseBase64Binary(b64data);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(new ByteArrayInputStream(decoded));
    }

    /** To whom requests are addressed */
    private String entityId;

    /** Where the AuthnRequest is sent (SSOLoginService endpoint) */
    private String loginUrl;

    /** Certificate used to validate assertions */
    private Certificate cert;

    /**
     * Set the Idp Entity Id.
     */
    public void setEntityId(String entityId)
    {
        this.entityId = entityId;
    }

    /**
     * Get the Idp Entity Id.
     */
    public String getEntityId()
    {
        return this.entityId;
    }

    /**
     * Set the IdP login URL.  The login URL is where the
     * user is redirected from the SP to initiate the
     * authentication process.
     */
    public void setLoginUrl(String loginUrl)
    {
        this.loginUrl = loginUrl;
    }

    /**
     * Get the IdP login URL.
     */
    public String getLoginUrl()
    {
        return this.loginUrl;
    }

    /**
     * Set the IdP public key certificate.
     * The certificate is used to validate signatures
     * in the assertion.
     */
    public void setCert(Certificate cert)
    {
        this.cert = cert;
    }

    /**
     * Get the Idp public key certificate.
     */
    public Certificate getCert()
    {
        return this.cert;
    }
}
