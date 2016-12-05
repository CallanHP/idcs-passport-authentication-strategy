/* 
 * Functions that connect to IDCS to obtain the endpoints used for the OAuth strategy
 */
var request = require('request');
var base64 = require('js-base64').Base64;

const WARN_MISSING_PARAMS = "A request was made for an authorisation URL without providing a client id or redirect uri."
                           +" This breaks OAuth spec, and is likely a configuration issue."

exports.getOpenIdUrls = function(config, idcsAgent){
  return new Promise(function(resolve, reject){
    var uris = {};
    var options = {
        url: config.idcs_url + config.discovery_url,
        agent: idcsAgent
      };
    request(options, function(err, res, body){
      if(err){
        reject(err);
        return;
      }
      try{
        var openIdConfig = JSON.parse(body)["openid-configuration"];
      } catch(err){
        reject(err);
        return;
      }
      uris.authorisationUrl = openIdConfig.authorization_endpoint;
      uris.tokenUrl = openIdConfig.token_endpoint;
      uris.userInfoUrl = openIdConfig.userinfo_endpoint;
      uris.logoutUrl = openIdConfig.end_session_endpoint;
      resolve(uris);
    });
  });
}

exports.getUserProfile = function(config, accessToken, idcsAgent){
  return new Promise(function(resolve, reject){
    var options = {
       url: config.idcs_url + config.profile_url,
        headers: {
          "Authorization":"Bearer " +accessToken,
          "Content-Type":"application/json"
        },
        agent: idcsAgent
    };
    request(options, function(err, res, body){
      if(err){
        reject(err);
        return;
      }
      resolve(body);
    });
  });
}

exports.getOAuthAccessToken = function(config, code, idcsAgent){
  return new Promise(function(resolve, reject){
    var options = {
        method: "POST",
        url: config._accessTokenUrl,
        headers: {
          "Authorization":"Basic " +base64.encode(config.client_id +":" +config.client_secret),
          "Content-Type":"application/x-www-form-urlencoded"
        },
        body: "grant_type=authorization_code&code=" +code,
        agent: idcsAgent
      };
      request(options, function(err, res, body){
      if(err){
        reject(err);
        return;
      }
      var token = JSON.parse(body);
      if(token){
        resolve(token);
      }else{
        reject(new Error("Could not obtain Bearer token from IDCS!"));
      }
    });
  });
}

exports.assembleAuthoriseURL = function(authUrl, params){
  if(!params.client_id || !params.redirect_uri){
    console.log(WARN_MISSING_PARAMS);
    return authUrl;
  }
  var ret = authUrl +"?client_id=" +params.client_id;
  ret += "&redirect_uri=" +params.redirect_uri;
  if(params.scope){
    ret += "&scope=" +params.scope;
  }
  if(params.nonce){
    ret += "&nonce=" +params.nonce;
  }
  if(params.state){
    ret += "&state=" +params.state;
  }
  if(params.response_type){
    ret += "&response_type=" +params.response_type;
  }  
  return ret;
}

exports.logout = function(logoutUrl, accessToken, idcsAgent){
  return new Promise(function(reject, resolve){
    var url = logoutUrl;// +"?id_token_hint=" +id_token;
    //Use a dummy redirect URL. Passport will handle the redirection, so we will just ignore the 302
    //that is returned by IDCS
    //url += "&post_logout_redirect_uri=http://localhost/post_logout";
    var options = {
        url: url,
        headers: {
          "Authorization": "Bearer " +accessToken
        }
      };
    if(idcsAgent){
      options.agent = idcsAgent;
    }
    request(options, function(err, res, body){
      if(err){
        reject(err);
        return;
      }
      //Body is an empty object according to the design doc.
      resolve(body);
    });
  });
}