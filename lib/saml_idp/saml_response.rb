require 'saml_idp/assertion_builder'
require 'saml_idp/response_builder'
module SamlIdp
  class SamlResponse
    attr_accessor :assertion_with_signature
    attr_accessor :reference_id
    attr_accessor :response_id
    attr_accessor :issuer_uri
    attr_accessor :principal
    attr_accessor :audience_uri
    attr_accessor :saml_request_id
    attr_accessor :saml_acs_url
    attr_accessor :algorithm
    attr_accessor :secret_key
    attr_accessor :x509_certificate
    attr_accessor :authn_context_classref
    attr_accessor :expiry
    attr_accessor :issuer_format

    def initialize(reference_id,
          response_id,
          issuer_uri,
          issuer_format,
          principal,
          audience_uri,
          saml_request_id,
          saml_acs_url,
          algorithm,
          authn_context_classref,
          expiry=60*60
          )
      self.reference_id = reference_id
      self.response_id = response_id
      self.issuer_uri = issuer_uri
      self.issuer_format = issuer_format
      self.principal = principal
      self.audience_uri = audience_uri
      self.saml_request_id = saml_request_id
      self.saml_acs_url = saml_acs_url
      self.algorithm = algorithm
      self.secret_key = secret_key
      self.x509_certificate = x509_certificate
      self.authn_context_classref = authn_context_classref
      self.expiry = expiry
    end

    def build
      @built ||= response_builder.encoded
    end

    def signed_assertion
      assertion_builder.signed
    end
    private :signed_assertion

    def response_builder
      ResponseBuilder.new(response_id, issuer_uri, issuer_format, saml_acs_url, saml_request_id, signed_assertion)
    end
    private :response_builder

    def assertion_builder
      @assertion_builder ||= AssertionBuilder.new reference_id,
        issuer_format,
        issuer_uri,
        principal,
        audience_uri,
        saml_request_id,
        saml_acs_url,
        algorithm,
        authn_context_classref,
        expiry
    end
    private :assertion_builder
  end
end
