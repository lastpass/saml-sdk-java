require 'java'
require 'util'

java_import com.lastpass.saml.SAMLClient
java_import com.lastpass.saml.SAMLException

describe "SAMLClient" do
    before(:all) do
        init()
    end

    it "should pass with correct key" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem')
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should_not raise_error
    end

    it "should fail with invalid key" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/badkey.pem')
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should pass with recent assertions" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :delta_secs => -120)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should_not raise_error
    end

    it "should fail with old assertions" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :delta_secs => -3600)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with future assertions" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :delta_secs => 3600)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with unsuccessful status" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :status => 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed')
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with no audience" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :has_audience => false)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with wrong audience" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem')
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.getSPConfig().entityId = 'some-other-id'
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with invalid destination" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :destination => 'http://example.com')
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with missing conditions" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :has_conditions => false)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with no AuthnStatement" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :has_authnstatement => false)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail AuthnStatement with SessionNotOnOrAfter in past" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :authnstatement_delta_secs => -500)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with invalid SubjectConfirmationData - recipient" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem')
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.getSPConfig().acs = 'some-other-acs'
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with invalid SubjectConfirmationData - notOnOrAfter" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :subjconfdata_delta_secs => -500)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with IssueInstant a day in the past" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :delta_secs => -87000,
                                :conditions_delta_secs => 864000,
                                :authnstatement_delta_secs => 864000,
                                :subjconfdata_delta_secs => 864000)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with IssueInstant a day in the future" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :delta_secs => 87000,
                                :conditions_delta_secs => 864000,
                                :authnstatement_delta_secs => 864000,
                                :subjconfdata_delta_secs => 864000)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should fail with unsigned assertion" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :sign_assertion => false,
                                :delta_secs => -120)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should raise_error(com.lastpass.saml.SAMLException)
    end

    it "should pass with unsigned response but signed assertion" do
        proc do
            r = create_response('user@example.org',
                                'data/spmeta.xml',
                                'data/idpmeta.xml',
                                'data/idpkey.pem',
                                :sign_response => false,
                                :delta_secs => -120)
            sc = get_client('data/spmeta.xml', 'data/idpmeta.xml')
            sc.validateResponse(r)
        end.should_not raise_error
    end
end
