# idcs-passport-authentication-strategy

Passport strategy for Oracle's IDCS which authenticates a user and manages that user's session.

Based on work done by [Indrajil Jha](https://www.npmjs.com/~indraniljha). This module draws heavily on his, but is designed to be a little more self-contained, and have simplified configuration.

## Installation

```bash
$ npm install idcs-passport-authentication-strategy
```

## Usage

This strategy is designed to plug into [PassportJS](http://passportjs.org/) to enable authentication against Oracle IDCS using its OAuth endpoints. It extends the default [passport-oauth](https://github.com/jaredhanson/passport-oauth) strategy, though due to some idiosyncratic behaviour in the underlying oauth package, implements its own authentication approach.

In addition to authentication, the strategy exports a logout helper method to invalidate tokens in IDCS.

Sample usage is as follows (example shown for express):

```js
var passport = require('passport');
var session = require('express-session');
var IDCSStrategy = require('idcs-passport-authentication-strategy');

var express = require('express');
var app = express();

var passportConfig = require('./passport-config.json');

passport.use(new IDCSStrategy(passportConfig, function(req, accessToken, refreshToken, profile, done) {
      req.session.idcsAccessToken = accessToken;
      return done(null, profile);
  }));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.use(session({secret: "DEMO_SECRET_VALUE"}));
app.use(passport.initialize());
app.use(passport.session());

//Login URL
app.get('/login', passport.authenticate('idcs-openid'));

//Callback URL
app.get('/oauth/callback', passport.authenticate('idcs-openid', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/home/');
  }
);

//Rest of endpoints etc... 
```

Check the passportjs documentation for more details.

## IDCS Setup

Using this module requires a Web Application to be configured in IDCS to support the Authorization Code and Refresh Token grants (to obtain access tokens, and allow passport to manage the token exchange). It requires client access to the 'Me' Identity Cloud Service Admin APIs (to obtain the user profile).

## Configuration

A typical configuration object looks like the following:

```js
{
	"idcs_url":"https://<tenant_name>.idcs.<datacentre>.oraclecloud.com",
	"client_id":"<Application_Client_ID>",
	"client_secret":"<Application_Client_Secret>",
	"callback_url":"https://<host>/oauth/callback",
	"post_logout_redirect":"https://<host>/home/"
}
```

post_logout_redirect is only used for logout (see below), and is not required for authentication.

## Handling Logout

The strategy also exposes a method which assembles the logout URL, to invalidate the tokens in IDCS. This simply assembles the URL defined [here](http://docs.oracle.com/cloud/latest/identity-cloud/IDCSA/op-oauth2-v1-userlogout-get.html). It may simply be my IDCS instance, but it seems that this endpoint differs from the documentation slightly, and this function will likely change in future. If you have issues, I would advise assembling this URL yourself based upon the linked documentation.

```js
app.get('/logout', function(req, res){
  req.session.destroy();
  req.logout();
  res.redirect(302, IDCSStrategy.getLogoutURI(passportConfig));
});

```