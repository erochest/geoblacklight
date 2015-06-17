require 'net/ldap'
require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    class LdapAuthenticatable < Authenticatable
      def authenticate!
        if params[:user]
          Rails.logger.info("########### USE LDAP INFO #########")
          ldap = Net::LDAP.new
          ldap.host = ldap.virginia.edu
          ldap.port = 389
          Rails.logger.info("########### LDAP AUTH #########")
          ldap.auth email, password

          if ldap.bind
            user = User.find_or_create_by(email: email)
            success!(user)
          else
            fail(:invalid_login)
          end
        end
      end

      def email
        params[:user][:email]
      end

      def password
        params[:user][:password]
      end

    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)