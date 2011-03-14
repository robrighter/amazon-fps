(function(){
  
  var crypto = require('crypto');
  var url = require('url');
  
  var SIGNATURE_KEYNAME = "signature";
  var SIGNATURE_METHOD_KEYNAME = "signatureMethod";
  var SIGNATURE_VERSION_KEYNAME = "signatureVersion";
	var HMAC_SHA1_ALGORITHM = "HmacSHA1";
	var HMAC_SHA256_ALGORITHM = "HmacSHA256";
	var HTTP_GET_METHOD = "GET";
	
	var MANDATORY_PARAMS = {
	  all: ["pipelineName","version","returnURL","callerReference"],
  	SingleUse: ["transactionAmount"],
  	Recurring: ["transactionAmount","recurringPeriod"],
  	Recipient: ["maxFixedFee","maxVariableFee","recipientPaysFee"],
  	MultiUse: ["globalAmountLimit"], //TODO there are some other requirements here that should be delt with (usagelimit types, etc)
  	EditToken: ["tokenId"]
	};
	
  module.exports = function(pipelineName, awsAccessKey, awsSecretKey){
  	/**
     * Version parameter for consistent signature for incoming and outgoing requests
     */
    var VERSION = "2009-01-09";
    var SIGNATURE_VERSION = 2;
    var SIGNATURE_METHOD = HMAC_SHA256_ALGORITHM;
    
  	var CBUI_URL = "https://authorize.payments.amazon.com/cobranded-ui/actions/start";
  	var parameters = {};
  	
    parameters["callerKey"] = awsAccessKey;
    parameters["pipelineName"] = pipelineName;
    parameters["version"] = VERSION;
    parameters["signatureVersion"] = SIGNATURE_VERSION;
    parameters["signatureMethod"] = SIGNATURE_METHOD;	
  	
  	this.addParameter = function(key, value){ 
  	  parameters[key] = value;
    };
  	
  	this.addOptionalParameters = function(params) {
        Object.keys(params).forEach(function(key){
          parameters[key] = params[key];
        });
    }
    
    /**
     * Constructs the query string for the parameters added to this class
     *
     * This function also calculates the signature of the all the name value pairs
     * added to the class. 
     *
     * @return string  URL 
     */
    this.getURL = function() {
      validateParameters('all',parameters);
      validateParameters(parameters.pipelineName,parameters);
		  return constructUrl(parameters);
    }

    /**
     * Computes RFC 2104-compliant HMAC signature for request parameters
     * Implements AWS Signature, as per following spec:
     *
     * If Signature Version is 1, it performs the following:
     *
     * Sorts all  parameters (including SignatureVersion and excluding Signature,
     * the value of which is being created), ignoring case.
     *
     * Iterate over the sorted list and append the parameter name (in original case)
     * and then its value. It will not URL-encode the parameter values before
     * constructing this string. There are no separators.
     *
     * If Signature Version is 2, string to sign is based on following:
     *
     *    1. The HTTP Request Method followed by an ASCII newline (%0A)
     *    2. The HTTP Host header in the form of lowercase host, followed by an ASCII newline.
     *    3. The URL encoded HTTP absolute path component of the URI
     *       (up to but not including the query string parameters);
     *       if this is empty use a forward '/'. This parameter is followed by an ASCII newline.
     *    4. The concatenation of all query string components (names and values)
     *       as UTF-8 characters which are URL encoded as per RFC 3986
     *       (hex characters MUST be uppercase), sorted using lexicographic byte ordering.
     *       Parameter names are separated from their values by the '=' character
     *       (ASCII character 61), even if the value is empty.
     *       Pairs of parameter and values are separated by the '&' character (ASCII code 38).
     *
     */
    signParameters = function(parameters, httpMethod, host, requestURI){
        var signatureVersion = parameters[SIGNATURE_VERSION_KEYNAME];
        var algorithm = HMAC_SHA1_ALGORITHM;
        var stringToSign = null;
        if (2 === signatureVersion) {
            algorithm = parameters[SIGNATURE_METHOD_KEYNAME];
            stringToSign = calculateStringToSignV2(parameters, httpMethod, host, requestURI);
        } else {
            stringToSign = calculateStringToSignV1(parameters);
        }
        return sign(stringToSign, awsSecretKey, algorithm);
    }
    
    /**
     * Calculate String to Sign for SignatureVersion 1
     * @param array $parameters request parameters
     * @return String to Sign
     */
    var calculateStringToSignV1 = function(parameters) {
        var data = '';
        var parameters =  makeSortedObject(parameters,false);
        parameters.forEach(function(param){
          data += (param['key'] + param['value']);
        });
        return data;
    }
  	
  	/**
     * Calculate String to Sign for SignatureVersion 2
     * @param array $parameters request parameters
     * @return String to Sign
     */
    var calculateStringToSignV2 = function(parameters, httpMethod, hostHeader, requestURI) {
        if (!httpMethod) {
        	throw "HttpMethod cannot be null";
        }
        var data = httpMethod;
        data += "\n";
        
        if (!hostHeader) {
        	hostHeader = "";
        } 
        data += hostHeader;
        data += "\n";
        
        if (!requestURI) {
        	requestURI = "/";
        }
        
        var uriencoded = requestURI.split('/').map(escape).join('/');
        
        data += uriencoded;
        data += "\n";
        
        parameters = makeSortedObject(parameters,false); //uksort($parameters, 'strcmp');
        data += getParametersAsString(parameters);
        return data;
    }
    
    /**
     * Computes RFC 2104-compliant HMAC signature.
     */
    function sign(data, key, algorithm) {
      var hmac;
      if (algorithm === HMAC_SHA1_ALGORITHM) {
          hmac = crypto.createHmac('sha1', key);
      } else if (algorithm === HMAC_SHA256_ALGORITHM) {
          hmac = crypto.createHmac('sha256', key);
      } else {
          throw "Non-supported signing method specified";
      }
      hmac.update(data);
      return hmac.digest('base64');
      //php: l1aQhiVCfR2L0Q9t1Nt1HRa7tF0=    <== Yes this sign is identical to the php version
      //node:l1aQhiVCfR2L0Q9t1Nt1HRa7tF0=
    }
    
    /**
     * Construct the pipeline request url using given parameters. 
     * Computes signature and adds it as additional parameter.
     * @param parameters - Map of pipeline request parameters.
     * @return Returns the pipeline request url. 
     * @throws MalformedURLException
     * @throws SignatureException
     * @throws UnsupportedEncodingException
     */
    function constructUrl($parameters) {
        if(!parameters){
          throw "Parameters can not be empty.";
        }
        var hostHeader = getHostHeader(CBUI_URL);
        var requestURI = getRequestURI(CBUI_URL);
        var signature = signParameters(parameters, HTTP_GET_METHOD, hostHeader, requestURI);
        parameters["signature"] = signature;        
        return CBUI_URL + "?" + buildQueryString(parameters);
    }
    
    function  getHostHeader(endPoint) {
		  var theurl = url.parse(endPoint);
  		var host = theurl.host.toLowerCase();
  		var protocol = theurl.protocol.toUpperCase();
  		if(theurl.hasOwnProperty('port')) {
  			if (("HTTPS" == protocol && theurl.port != 443) ||  ("HTTP" == protocol && theurl.port != 80)) {
  				return host + ":" + theurl.port;
  			}
  		}
  		return host;
	  }

    function getRequestURI(endPoint) {
      var theurl = url.parse(endPoint);
  		var requestURI = '/';
  		if(theurl.hasOwnProperty('pathname')){
  		  requestURI = theurl.pathname;
  		}
  		return requestURI;
    }
    
    function validateCommonMandatoryParameters(parameters) {
        if (!parameters.hasOwnProperty("pipelineName")){ 
            throw "pipelineName is missing in parameters.";
        }
        if (!parameters.hasOwnProperty("version")){
            throw "version is missing in parameters.";
        }
        if (!parameters.hasOwnProperty("returnURL")){
            throw "returnURL is missing in parameters.";
        }
        if (!parameters.hasOwnProperty("callerReference")){
            throw "callerReference is missing in parameters.";
        }
    }

    function validateParameters(type, parameters){
      MANDATORY_PARAMS[type].forEach(function(param){
        if (!parameters.hasOwnProperty(param)){ 
            throw param + " is missing from the parameters. This parameter is required for " + type;
        }
      });
    }
    
  	
  	//////////////////////////////////////////////
  	//                UTILS                     //
  	//////////////////////////////////////////////  
    function urlEncode(toencode){
      return escape(toencode).replace(/\//g,'%2F');
    }
    
    
    function buildQueryString(params){
      return Object.keys(params).map(function(p){
        return escape(p) + "=" + urlEncode(params[p]);
      }).join('&');
    }
    
    /**
     * Convert paremeters to Url encoded query string
     */
    function getParametersAsString(parameters) {
        return parameters.map(function(param){
          return (param.key + '=' + urlEncode(param.value));
        }).join('&');
    }
    
    function makeSortedObject(obj, casesensitive){
      return Object.keys(obj).map(function(key){
        return {key: key, value: obj[key]};
      }).sort(function(a,b){
        return (casesensitive? a.key : a.key.toLowerCase()) > (casesensitive? b.key : b.key.toLowerCase());
      });
    }
  
  }//end of the class
  

})();