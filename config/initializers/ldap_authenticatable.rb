require 'net/ldap'
require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    class LdapAuthenticatable < Authenticatable
      def authenticate!
        Rails.logger.info("########### USE LDAP INFO #########")
        if params[:user]
          ldap = Net::LDAP.new
          ldap.host = 'ldap.virginia.edu'
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
        Rails.logger.info("########### USER = #{params[:user].inspect} #########")
        Rails.logger.info("########### EMAIL = #{params[:user][:mail].inspect} #########")
        params[:user][:mail]
      end

      def password
        Rails.logger.info("########### PASS = #{params[:user][:password].inspect} #########")
        params[:user][:password]
      end

    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)
