module Pubcookie
  class CustomStrategy < Devise::Strategies::Authenticatable

    # it must have a `valid?` method to check if it is appropriate to use
    # for a given request
    def valid?
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

      # if we wanted to stop other strategies from authenticating the user
    end

  end
end

# for warden, `:pubcookie_authentication`` is just a name to identify the strategy
Warden::Strategies.add :pubcookie_authentication, Pubcookie::CustomStrategy

# for devise, there must be a module named 'PubcookieAuthentication' (name.to_s.classify), and then it looks to warden
# for that strategy. This strategy will only be enabled for models using devise and `:pubcookie_authentication` as an
# option in the `devise` class method within the model.
Devise.add_module :pubcookie_authentication, :strategy => true
