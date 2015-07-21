require 'openssl'
require 'base64'

module Pubcookie
  class CustomStrategy < Devise::Strategies::Authenticatable

    # it must have a `valid?` method to check if it is appropriate to use
    # for a given request
    def valid?
      # must call this to actually get the authentication_hash set:
      # valid_for_http_auth?

      # but, we want this strategy to be valid for any request with this header set so that we can use a custom
      # response for an invalid request.
      #cookies['pubcookie_s_geoblacklight'].present?
      request.env['REMOTE_USER'].present?
    end


    # it must have an authenticate! method to perform the validation
    # a successful request calls `success!` with a user object to stop
    # other strategies and set up the session state for the user logged in
    # with that user object.
    def authenticate!

      # mapping comes from devise base class, "mapping.to" is the class of the model
      # being used for authentication, typically the class "User". This is set by using
      # the `devise` class method in that model
      klass = mapping.to

      if request.env['REMOTE_USER'].present?
        email = "#{request.env['REMOTE_USER']}@virginia.edu"
        user = klass.find_or_initialize_by(email: email)
        success! user
      end

      #if cookies['pubcookie_s_geoblacklight'].present?
        #username = extract_username(cookies)
        #email = "#{username}@virginia.edu"
        #user = klass.find_or_initialize_by(email: email)
        #success! user
      #end

      # if we wanted to stop other strategies from authenticating the user
    end


    private

    def extract_username(cookies)
      return nil unless cookies['pubcookie_s_geoblacklight'].present?

      #cookie = cookies['pubcookie_s_geoblacklight']
      #bytes  = Base64.decode64(cookie).bytes.to_a

      #index2 = bytes.pop
      #index1 = bytes.pop

      #decrypted = des_decrypt(bytes, index1, index2)
    end

    def des_decrypt(bytes, index1, index2)
      # According to http://bit.ly/pubcookie-doc, the initial IVEC is defined
      # around line 63 and for some reason only the first byte is used in the
      # xor'ing
      # no perms on the files
      #@keyfile = "/etc/pki/tls/private/STAR_LIB_key.pem"
      #@granting_cert = "/usr/local/pubcookie/keys/pubcookie_granting.cert"
      #::File.open(@keyfile, 'rb'){ |f| @key = f.read.bytes.to_a }
      #ivec = @key[index2, 8]
      #ivec = ivec.map{ |i| i ^ 0x4c }

      #Rails.logger.debug(ivec)

      #key = @key[index1, 8]
      #c = OpenSSL::Cipher.new('des-cfb')
      #@granting = OpenSSL::X509::Certificate.new(::File.read(@granting_cert))
      #Rails.logger.debug(granting)
    end

  end
end

# for warden, `:pubcookie_authentication`` is just a name to identify the strategy
Warden::Strategies.add :pubcookie_authentication, Pubcookie::CustomStrategy

# for devise, there must be a module named 'PubcookieAuthentication' (name.to_s.classify), and then it looks to warden
# for that strategy. This strategy will only be enabled for models using devise and `:pubcookie_authentication` as an
# option in the `devise` class method within the model.
Devise.add_module :pubcookie_authentication, :strategy => true
