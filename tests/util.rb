require 'java'
require 'base64'

include_class com.lastpass.saml.SAMLInit
include_class com.lastpass.saml.SAMLClient
include_class com.lastpass.saml.SPConfig
include_class com.lastpass.saml.IdPConfig

include_class org.opensaml.Configuration
include_class org.opensaml.saml2.core.Response
include_class org.opensaml.saml2.core.Subject
include_class org.opensaml.saml2.core.NameID
include_class org.opensaml.saml2.core.Issuer
include_class org.opensaml.saml2.core.Assertion
include_class org.opensaml.saml2.core.Conditions
include_class org.opensaml.saml2.core.AudienceRestriction
include_class org.opensaml.saml2.core.Audience
include_class org.opensaml.saml2.core.AuthnStatement
include_class org.opensaml.saml2.core.Status
include_class org.opensaml.saml2.core.StatusCode
include_class org.opensaml.saml2.core.SubjectConfirmation
include_class org.opensaml.saml2.core.SubjectConfirmationData
include_class org.opensaml.saml2.core.StatusCode
include_class org.opensaml.xml.signature.Signature
include_class org.opensaml.xml.signature.SignatureConstants
include_class org.opensaml.xml.signature.Signer
include_class org.opensaml.xml.security.credential.BasicCredential

include_class org.bouncycastle.jce.provider.BouncyCastleProvider
include_class org.bouncycastle.openssl.PEMReader

include_class org.joda.time.DateTime

include_class java.io.FileReader
include_class java.io.BufferedReader
include_class java.security.Security

def init()
    SAMLInit.initialize()
end

def dom_to_string(elem)
    document = elem.getOwnerDocument()
    serializer = document.implementation.createLSSerializer()
    serializer.domConfig.setParameter("xml-declaration", false);
    return serializer.writeToString(elem)
end

def load_privkey(fn)
    br = BufferedReader.new(FileReader.new(fn))
    Security.addProvider(BouncyCastleProvider.new())
    kp = PEMReader.new(br).readObject()
    cred = BasicCredential.new()
    cred.publicKey = kp.getPublic()
    cred.privateKey = kp.getPrivate()
    return cred
end

def create_response(email, spmeta, idpmeta, privkey_fn, opts = {})

    spconf = SPConfig.new(java.io.File.new(spmeta))
    idpconf = IdPConfig.new(java.io.File.new(idpmeta))

    opts = {
        :delta_secs => 0,
        :has_audience => true,
        :has_conditions => true,
        :has_authnstatement => true,
        :conditions_delta_secs => 600,
        :authnstatement_delta_secs => 600,
        :subjconfdata_delta_secs => 600,
        :destination => spconf.acs,
        :status => StatusCode::SUCCESS_URI,
    }.merge(opts)

    bf = Configuration.builderFactory;
    response = bf.getBuilder(Response.DEFAULT_ELEMENT_NAME).buildObject()

    assertion = bf.getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject()
    subject = bf.getBuilder(Subject.DEFAULT_ELEMENT_NAME).buildObject()
    nameid = bf.getBuilder(NameID.DEFAULT_ELEMENT_NAME).buildObject()
    issuer = bf.getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject()
    resp_issuer = bf.getBuilder(Issuer.DEFAULT_ELEMENT_NAME).buildObject()
    signature = bf.getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject()
    resp_sig = bf.getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject()
    conditions = bf.getBuilder(Conditions.DEFAULT_ELEMENT_NAME).buildObject()
    restriction = bf.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME).buildObject()
    audience = bf.getBuilder(Audience.DEFAULT_ELEMENT_NAME).buildObject()
    authn_stmt = bf.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME).buildObject()
    status = bf.getBuilder(Status.DEFAULT_ELEMENT_NAME).buildObject()
    statusCode = bf.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME).buildObject()
    subj_conf = bf.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME).buildObject()
    subj_conf_data = bf.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME).buildObject()

    now = DateTime.now()
    now = now.plusSeconds(opts[:delta_secs])

    issuer.value = idpconf.entityId
    resp_issuer.value = idpconf.entityId

    nameid.value = email
    nameid.sPNameQualifier = spconf.entityId
    nameid.format = NameID::EMAIL

    subject.nameID = nameid

    subj_conf_data.notOnOrAfter =
        now.plusSeconds(opts[:subjconfdata_delta_secs])
    subj_conf_data.recipient = spconf.acs
    subj_conf.subjectConfirmationData = subj_conf_data
    subject.getSubjectConfirmations().add(subj_conf)

    assertion.subject = subject
    assertion.issuer = issuer
    assertion.issueInstant = now

    conditions.setNotBefore(now.minusSeconds(opts[:conditions_delta_secs]))
    conditions.setNotOnOrAfter(now.plusSeconds(opts[:conditions_delta_secs]))
    audience.audienceURI = spconf.entityId
    restriction.getAudiences().add(audience)
    if opts[:has_audience]
        conditions.getAudienceRestrictions().add(restriction)
    end
    if opts[:has_conditions]
        assertion.conditions = conditions
    end
    if opts[:has_authnstatement]
        authn_stmt.sessionNotOnOrAfter =
            now.plusSeconds(opts[:authnstatement_delta_secs])
        assertion.authnStatements.add(authn_stmt)
    end

    #TODO signature.keyInfo = signing_key_info
    signature.signingCredential = load_privkey(privkey_fn)
    signature.signatureAlgorithm = SignatureConstants::ALGO_ID_SIGNATURE_RSA_SHA1
    signature.canonicalizationAlgorithm = SignatureConstants::ALGO_ID_C14N_EXCL_OMIT_COMMENTS
    resp_sig.signingCredential = load_privkey(privkey_fn)
    resp_sig.signatureAlgorithm = SignatureConstants::ALGO_ID_SIGNATURE_RSA_SHA1
    resp_sig.canonicalizationAlgorithm = SignatureConstants::ALGO_ID_C14N_EXCL_OMIT_COMMENTS

    assertion.signature = signature
    assertion.setID("999999")

    Configuration.marshallerFactory.getMarshaller(assertion).marshall(assertion)
    Signer.signObject(signature)

    statusCode.value = opts[:status]
    status.statusCode = statusCode

    response.status = status
    response.getAssertions.add(assertion)
    response.issuer = resp_issuer
    response.signature = resp_sig
    response.destination = opts[:destination]
    response.setID("abcdef")
    response.issueInstant = now

    marshaller = Configuration.marshallerFactory.getMarshaller(response)
    elem = marshaller.marshall(response)
    Signer.signObject(resp_sig)
    xmlstr = dom_to_string(elem)

    return Base64.encode64(xmlstr)
end

def get_client(spmeta, idpmeta)
    spconf = SPConfig.new(java.io.File.new(spmeta))
    idpconf = IdPConfig.new(java.io.File.new(idpmeta))
    return SAMLClient.new(spconf, idpconf)
end
