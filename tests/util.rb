require 'java'
require 'base64'

java_import com.lastpass.saml.SAMLInit
java_import com.lastpass.saml.SAMLClient
java_import com.lastpass.saml.SPConfig
java_import com.lastpass.saml.IdPConfig

java_import org.opensaml.Configuration
java_import org.opensaml.saml2.core.Response
java_import org.opensaml.saml2.core.Subject
java_import org.opensaml.saml2.core.NameID
java_import org.opensaml.saml2.core.Issuer
java_import org.opensaml.saml2.core.Assertion
java_import org.opensaml.saml2.core.Conditions
java_import org.opensaml.saml2.core.AudienceRestriction
java_import org.opensaml.saml2.core.Audience
java_import org.opensaml.saml2.core.AuthnStatement
java_import org.opensaml.saml2.core.Status
java_import org.opensaml.saml2.core.StatusCode
java_import org.opensaml.saml2.core.SubjectConfirmation
java_import org.opensaml.saml2.core.SubjectConfirmationData
java_import org.opensaml.saml2.core.StatusCode
java_import org.opensaml.saml2.encryption.Encrypter
java_import org.opensaml.xml.signature.Signature
java_import org.opensaml.xml.signature.SignatureConstants
java_import org.opensaml.xml.signature.Signer
java_import org.opensaml.xml.security.credential.BasicCredential
java_import org.opensaml.xml.encryption.EncryptionParameters
java_import org.opensaml.xml.encryption.EncryptionConstants
java_import org.opensaml.xml.encryption.KeyEncryptionParameters

java_import org.bouncycastle.jce.provider.BouncyCastleProvider
java_import org.bouncycastle.openssl.PEMReader

java_import org.joda.time.DateTime

java_import java.io.FileReader
java_import java.io.BufferedReader
java_import java.security.Security

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

def create_response(email, spmeta, idpmeta, privkey_fn, sp_privkey_fn, opts = {})

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
        :sign_assertion => true,
        :sign_response => true,
        :encrypt_assertion => false,
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

    if opts[:sign_assertion]
        #TODO signature.keyInfo = signing_key_info
        signature.signingCredential = load_privkey(privkey_fn)
        signature.signatureAlgorithm = SignatureConstants::ALGO_ID_SIGNATURE_RSA_SHA1
        signature.canonicalizationAlgorithm = SignatureConstants::ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        assertion.signature = signature
    end

    assertion.setID("999999")

    Configuration.marshallerFactory.getMarshaller(assertion).marshall(assertion)
    if opts[:sign_assertion]
        Signer.signObject(signature)
    end

    encrypted_assertion = nil
    if opts[:encrypt_assertion]
        kek_params = KeyEncryptionParameters.new()
        kek_params.encryptionCredential = load_privkey(sp_privkey_fn)
        kek_params.algorithm = EncryptionConstants::ALGO_ID_KEYTRANSPORT_RSAOAEP

        params = EncryptionParameters.new()
        params.algorithm = EncryptionConstants::ALGO_ID_BLOCKCIPHER_AES256

        encrypter = Encrypter.new(params, kek_params)
        encrypter.keyPlacement = Encrypter::KeyPlacement::INLINE
        encrypted_assertion = encrypter.encrypt(assertion)
    end

    statusCode.value = opts[:status]
    status.statusCode = statusCode

    response.status = status
    if encrypted_assertion != nil
        response.getEncryptedAssertions.add(encrypted_assertion)
    else
        response.getAssertions.add(assertion)
    end
    response.issuer = resp_issuer
    response.destination = opts[:destination]
    response.setID("abcdef")
    response.issueInstant = now

    if opts[:sign_response]
        resp_sig.signingCredential = load_privkey(privkey_fn)
        resp_sig.signatureAlgorithm = SignatureConstants::ALGO_ID_SIGNATURE_RSA_SHA1
        resp_sig.canonicalizationAlgorithm = SignatureConstants::ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        response.signature = resp_sig
    end

    marshaller = Configuration.marshallerFactory.getMarshaller(response)
    elem = marshaller.marshall(response)
    if opts[:sign_response]
        Signer.signObject(resp_sig)
    end
    xmlstr = dom_to_string(elem)

    return Base64.encode64(xmlstr)
end

def get_client(spmeta, idpmeta)
    spconf = SPConfig.new(java.io.File.new(spmeta))
    idpconf = IdPConfig.new(java.io.File.new(idpmeta))
    return SAMLClient.new(spconf, idpconf)
end

def get_client_with_sp_key(spmeta, idpmeta, sp_privkey_fn)
    spconf = SPConfig.new(java.io.File.new(spmeta))
    idpconf = IdPConfig.new(java.io.File.new(idpmeta))

    cred = load_privkey(sp_privkey_fn)
    spconf.privateKey = cred.privateKey
    return SAMLClient.new(spconf, idpconf)
end
