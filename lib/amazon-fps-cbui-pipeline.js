(function(){
  var SIGNATURE_KEYNAME = "signature";
	var SIGNATURE_METHOD_KEYNAME = "signatureMethod";
	var SIGNATURE_VERSION_KEYNAME = "signatureVersion";
	var HMAC_SHA1_ALGORITHM = "HmacSHA1";
	var HMAC_SHA256_ALGORITHM = "HmacSHA256";
	var HTTP_GET_METHOD = "GET";
	
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
  	
  	this.addParameter = function(key, value){ parameters[key] };
  	
  	this.addOptionalParameters = function(params) {
        Object.keys(params).forEach(function(key){
          parameters[key] = params[key];
        });
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
    this.signParameters = function(parameters, httpMethod, host, requestURI){
        signatureVersion = parameters[SIGNATURE_VERSION_KEYNAME];
        algorithm HMAC_SHA1_ALGORITHM;
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
        data = '';
        parameters =  makeSortedObject(parameters,false);
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
        
		    var uriencoded = implode("/", array_map(array("Amazon_FPS_CBUIPipeline", "_urlencode"), explode("/", $requestURI)));
        
        data += uriencoded;
        data += "\n";
        
        parameters = makeSortedObject(parameters,false); //uksort($parameters, 'strcmp');
        data += getParametersAsString(parameters);
        return data;
    }
    
    /**
     * Computes RFC 2104-compliant HMAC signature.
     */
    //TODO: FINSIH THIS
    function sign(data, key, algorithm) {
      if (algorithm === 'HmacSHA1') {
          $hash = 'sha1';
      } else if ($algorithm === 'HmacSHA256') {
          $hash = 'sha256';
      } else {
          throw new Exception ("Non-supported signing method specified");
      }
      return base64_encode(
          hash_hmac($hash, $data, $key, true)
      );
    }

  	
  	
  	//////////////////////////////////////////////
  	//                UTILS                     //
  	//////////////////////////////////////////////  
    /**
     * Convert paremeters to Url encoded query string
     */
    function getParametersAsString(parameters) {
        return parameters.map(function(param){
          return (param.key + '=' + escape(param.value));
        }).join('&');
    }
    
    function makeSortedObject(obj, casesensitive){
      return Object.keys(obj).map(function(key){
        return {key: key, value: obj[key]};
      }).sort(function(a,b){
        return (casesensitive? a.key : a.key.toLowerCase()) > (casesensitive? b.key : b.key.toLowerCase());
      });
    }
  	
  }
  
  
  
  
})();