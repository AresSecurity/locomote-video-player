package com.axis.http {
  import com.adobe.crypto.MD5;

  import com.axis.Logger;
  import com.axis.rtspclient.GUID;

  import flash.net.Socket;

  import mx.utils.Base64Encoder;

  public class auth {

    public static function basic(user:String, pass:String):String {
      var b64:Base64Encoder = new Base64Encoder();
      b64.insertNewLines = false;
      b64.encode(user + ':' + pass);
      return 'Basic ' + b64.toString();
    }

    public static function digest(
      user:String,
      pass:String,
      httpmethod:String,
      realm:String,
      uri:String,
      qop:String,
      nonce:String,
      nc:uint
    ):String {
      /* NOTE: Unsupported: md5-sess and auth-int */

      if (qop && 'auth' !== qop) {
        Logger.log('unsupported quality of protection: ' + qop);
        return "";
      }

      Logger.log(user + ':' + realm + ':' + pass);
      Logger.log(httpmethod + ':' + uri);
      Logger.log(qop ? "qop=true" : "qop=false");

      var ha1:String = MD5.hash(user + ':' + realm + ':' + pass);
      var ha2:String = MD5.hash(httpmethod + ':' + uri);
      var cnonce:String = MD5.hash(GUID.create());

      var hashme:String = qop ?
        (ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2) :
        (ha1 + ':' + nonce + ':' + ha2)
      var resp:String = MD5.hash(hashme);

      return 'Digest ' +
        'username="' + user + '", ' +
        'realm="' + realm + '", ' +
        'nonce="' + nonce + '", ' +
        'uri="' + uri + '", ' +
        /*'nc="' + nc + '", ' +*/
        (qop ? ('qop="' + qop + '", ') : '') +
        (qop ? ('cnonce="' + cnonce + '", ') : '') +
        'response="' + resp + '"'
        ;
    }

    public static function nextMethod(current:String, authOpts:Object):String {
      /*return 'basic';*/
      switch (current) {
        case 'none':
          /* No authorization attempt yet, try with the best method supported by server */
          if (authOpts.digestRealm)
            return 'digest';
          else if (authOpts.hasOwnProperty('basicRealm'))
            return 'basic';
          break;

        case 'digest':
          /* Weird to get unauthorized here unless credentials are invalid.
             On the off-chance of server-bug, try basic as well */
          if (authOpts.basicRealm)
            return 'basic';

        case 'basic':
          /* If we failed with basic, we're done. Credentials are invalid. */
      }

      /* Getting the same method as passed as current should be considered an error */
      return current;
    }

    public static function authorizationHeader(
      method:String,
      authState:String,
      authOpts:Object,
      urlParsed:Object,
      digestNC:uint):String {

      var content:String = '';
      switch (authState) {
        case "basic":
          content = basic(urlParsed.user, urlParsed.pass);
          break;

        case "digest":
          var u:String = 'rtsp://' + urlParsed.host + ':' + urlParsed.port + urlParsed.urlpath;
          content = digest(
            urlParsed.user,
            urlParsed.pass,
            method,
            authOpts.digestRealm,
            u,
            authOpts.qop,
            authOpts.nonce,
            digestNC
          );
          break;

        default:
        case "none":
          return "";
      }

      Logger.log("Authorization: " + content + "\r\n");
      return "Authorization: " + content + "\r\n"
    }
  }
}
