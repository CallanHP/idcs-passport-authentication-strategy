var OAuth2Strategy = require('passport-oauth2');
var AuthorizationError = require('./error/authorizationerror')
var idcs = require('./lib/idcs-discovery');
var https = require('https');
var util = require('util');
var url = require('url')


const ERR_NO_CONFIG="An attempt was made to initialise the idcs-passport-authentication-strategy without a configuration.";
const ERR_MISSING_CONFIG_FIELDS="Unable to initialise idcs-authentication strategy, required parameters not provided.";
const ERR_UNDEFINED_ENDPOINT="The IDCS Authentication strategy has not yet completed initialisation, "
                            +"and the endpoint has not been retrieved from the server.";
const ERR_NO_LOGOUT_CONFIG="The call to logout was made without the required config fields, at least the IDCS host is required.";
const WARN_NO_POST_LOGOUT_URL="Logout was called without a post_logout_redirect url being set. Redirecting to a dummy location.";
const WARN_LOGOUT_NO_USER="No user is available to the logout call, of the user doesn't have an id_token. Assuming user is already logged out."

const DEFAULT_DISCOVERY_URL = "/.well-known/idcs-configuration";
const DEFAULT_SCOPE = "openid urn:opc:idm:__myscopes__ offline_access";
const DEFAULT_PROFILE_URL = "/admin/v1/Me";
const DEFAULT_LOGOUT_URL = "/oauth2/v1/userlogout";
const DEFAULT_POST_LOGOUT_URL = "http://localhost/dummy"

function Strategy(configuration, verify){
  if(!configuration){
    throw new Error(ERR_NO_CONFIG);
  }

  if(!configuration.client_id || !configuration.client_secret || !configuration.callback_url){
    throw new Error(ERR_MISSING_CONFIG_FIELDS);
  } 

  this.config = configuration;
  if(!this.config.discovery_url){
    this.config.discovery_url = DEFAULT_DISCOVERY_URL;
  }
  if(!this.config.profile_url){
    this.config.profile_url = DEFAULT_PROFILE_URL;
  }
  if(!this.config.scope){
    this.config.scope = DEFAULT_SCOPE;
  }
  if(!this.config.pass_req_to_callback){
    this.config.pass_req_to_callback = true;
  }
  var idcsAgentOptions = this.config.request_agent;
  if(!idcsAgentOptions){
    idcsAgentOptions = {};
  }
  this.idcsAgent = new https.Agent(idcsAgentOptions);
  this.config._authorizeUrl = "placeholder";

  this.options = {
    authorizationURL:"placeholder",
    tokenURL:"placeholder",
    scope:this.config.scope,
    clientID:this.config.client_id,
    clientSecret:this.config.client_secret,
    callbackURL:this.config.callback_url,
    passReqToCallback:this.config.pass_req_to_callback
  }
  OAuth2Strategy.call(this, this.options, verify);

  this.name = 'idcs-openid';

  var self = this;
  idcs.getOpenIdUrls(this.config, this.idcsAgent).then(function(uris){
    self.config._logout_url = uris.logoutUrl;
    self.config._accessTokenUrl = uris.tokenUrl;
    self.config._authorizeUrl = uris.authorisationUrl;
  });

}
// Inherit from passport's OAuth2Strategy.
util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken, done){
  idcs.getUserProfile(this.config, accessToken, this.idcsAgent).then(function(result){
    return done(null, result);
  });
}

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 * Code pulled from passport-oauth2, rewritten to not use the OAuth library,
 * and instead use the IDCS Authorizarion headers.
 *
 * @param {Object} req
 * @api protected
 */
OAuth2Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }
  
  var meta = {
    authorizationURL: this.config._authorizeUrl,
    tokenURL: this.config._accessTokenUrl,
    clientID: this.config.client_id
  }

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) { return self.error(err); }
      if (!ok) {
        return self.fail(state, 403);
      }
  
      var code = req.query.code;


      //Use our own access token service, because IDCS doesn't like client_id/secret in the body
      idcs.getOAuthAccessToken(self.config, code, self.idcsAgent)
        .then(function(tokens){
          var accessToken = tokens.access_token;
          var refreshToken = tokens.refresh_token;
          self.userProfile(accessToken, function(err, profile) {
            if (err) { return self.error(err); }

            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              
              info = info || {};
              if (state) { info.state = state; }
              self.success(user, info);
            }

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
        })}, 
        function(err){
          console.log(err);
          return self.error(self._createOAuthError('Failed to obtain access token', err));
        });
    }   
    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = {};
    params.client_id = this.config.client_id;
    params.response_type = 'code';
    if (callbackURL) { params.redirect_uri = callbackURL; }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }

    var state = options.state;
    if (state) {
      params.state = state;
      var location = idcs.assembleAuthoriseURL(this.config._authorizeUrl, params);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) { return self.error(err); }

        if (state) { params.state = state; }
        var location = idcs.assembleAuthoriseURL(self.config._authorizeUrl, params);
        self.redirect(location);
      }
      
      try {
        var arity = this._stateStore.store.length;
        if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else { // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};

//Export the strategy
module.exports = Strategy;

module.exports.getLogoutURI = function(options, idToken){
  if(!options.idcs_url){
    console.log(ERR_NO_LOGOUT_CONFIG);
    return "";
  }
  if(!options.logout_url){
    options.logout_url = DEFAULT_LOGOUT_URL;
  }
  if(!options.post_logout_redirect){
    console.log(WARN_NO_POST_LOGOUT_URL)
    options.logout_url = DEFAULT_POST_LOGOUT_URL;
  }
  var ret = options.idcs_url + options.logout_url + "?post_logout_redirect_uri=" +encodeURI(options.post_logout_redirect);
  //Attempt to extract the user
  if(idToken){
    ret += "&id_token_hint=" + idToken;
  }
  return ret;          
}