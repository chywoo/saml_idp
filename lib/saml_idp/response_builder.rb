require 'builder'
module SamlIdp
  class ResponseBuilder
    attr_accessor :response_id
    attr_accessor :issuer_uri
    attr_accessor :issuer_format
    attr_accessor :saml_acs_url
    attr_accessor :saml_request_id
    attr_accessor :assertion_and_signature

    def initialize(response_id, issuer_uri, issuer_format, saml_acs_url, saml_request_id, assertion_and_signature)
      self.response_id = response_id
      self.issuer_uri = issuer_uri
      self.issuer_format = issuer_format
      self.saml_acs_url = saml_acs_url
      self.saml_request_id = saml_request_id
      self.assertion_and_signature = assertion_and_signature
    end

    def encoded
      @encoded ||= encode
    end

    def raw
      build
    end

    def encode
      Base64.encode64(raw)
    end
    private :encode

    def build
      builder = Builder::XmlMarkup.new
      builder.tag! "samlp:Response",
        ID: response_id_string,
        Version: "2.0",
        IssueInstant: now_iso,
        Destination: saml_acs_url,
        Consent: Saml::XML::Namespaces::Consents::UNSPECIFIED,
        InResponseTo: saml_request_id,
        "xmlns:samlp" => Saml::XML::Namespaces::PROTOCOL do |response|
          if issuer_format == true
            response.Issuer issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION, Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
          else
            response.Issuer issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          end
          response.tag! "samlp:Status" do |status|
            status.tag! "samlp:StatusCode", Value: Saml::XML::Namespaces::Statuses::SUCCESS
          end
          response << assertion_and_signature
        end
    end
    private :build

    def response_id_string
      "_#{response_id}"
    end
    private :response_id_string

    def now_iso
      Time.now.utc.iso8601
    end
    private :now_iso
  end
end
