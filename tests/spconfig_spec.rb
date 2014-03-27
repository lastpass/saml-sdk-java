require 'java'
require 'util'

include_class com.lastpass.saml.SPConfig

describe "SPConfig" do
    before(:all) do
        init()
    end

    it "should parse metadata" do
        spconfig = SPConfig.new(java.io.File.new('data/spmeta.xml'))
        spconfig.acs.should == 'https://sp.example.org/saml/sp/POST'
        spconfig.entityId.should == 'https://sp.example.org/test-sp'
    end
end
