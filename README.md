LastPass SAML SDK for Java
==========================

The LastPass SAML SDK for Java is a set of Java classes that makes
it easy to add SAML 2.0 based single-sign on to your Java applications.
The SDK is built on top of the OpenSAML library and provides a simple
client interface for service providers.

What is SAML?  What is a Service Provider?
------------------------------------------
The SAML standard is a web-based authentication protocol.  A typical
session operates like this:

 1. A user wishes to use a website, http://foo.example.com/.
    In this case, foo.example.com would be the Service Provider (SP).
 2. When the user clicks a login link at the service provider,
    they are redirected to another website for authentication,
    http://idp.example.org.  This site is the Identity Provider (IdP).
 3. The IdP authenticates the user (by prompting for a password,
    perhaps), and then causes the user's browser to return to the
    Service Provider, posting a crptographically signed token.
 4. The SP verifies that the token's signature is valid, belongs to
    the IdP, and that the token meets certain criteria.
 5. Assuming the token is valid, the user is allowed to proceed
    with the credentials from the IdP.

This library implements steps one and four of the process: creating
a SAML token request, and processing a signed token to test its validity.

Where do I get an IdP?
----------------------
There are several providers.  We suggest checking out our own IdP
service, part of LastPass Enterprise, at https://lastpass.com/.

Building the SDK
--------------------

The SDK requires Java 1.5+ and ant.  Simply run ant to build:

    $ ant

This will download dependencies with ivy and then build the class
files.  The output will be in out/lastpass-saml-sdk.jar.

Integrating SAML into your Java application
-------------------------------------------
There are two main steps to integrate SAML into your application:

 1. change your application's login page to redirect to the IdP with a
    SAMLRequest message, and
 2. add a web endpoint that processes a SAML token, and, if successful,
    returns to the web application with the authenticated subject from
    the assertion

Actual steps for integration are outside the scope of this library,
but a synopsis follows:

    // at application startup, init library and create the client
    SAMLInit.intialize();
    IdPConfig idpConfig = new IdPConfig(new File("idp-metadata.xml"));
    SPConfig spConfig = new SPConfig(new File("sp-metadata.xml"));
    client = new SAMLClient(spConfig, idpConfig);

    // ...

    // when a login link is clicked, create auth request and
    // redirect to the IdP
    String requestId = SAMLUtils.generateRequestId();
    String authrequest = client.generateAuthnRequest(requestId);
    String url = client.getIdPConfig().getLoginUrl() +
                 "?SAMLRequest=" + URLEncoder.encode(authrequest, "UTF-8");
    // redirect to url...

    // ...

    // when a saml token is posted, extract the subject
    String authresponse = request.getParameter("SAMLResponse");
    AttributeSet aset;
    try {
        aset = client.validateResponse(authresponse);
        String user = aset.getNameId();
        // do something with now-authenticated user...
    } catch (SAMLException e) {
        // response invalid, return to login page...
    }


License
-------
The LastPass SAML SDK is licensed under the Apache License, version 2.0.
