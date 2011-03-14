var PipeLine = require('./lib/amazon-fps-cbui-pipeline');
var config = require('./config.js');

var singleUse = new PipeLine('SingleUse', config.AWS_ACCESS_KEY_ID, config.AWS_SECRET_ACCESS_KEY);

singleUse.addParameter("callerReference","callerReferenceSingleUse");
singleUse.addParameter("returnURL","http://www.mysite.com/call_back.jsp");
singleUse.addParameter("transactionAmount","5");
singleUse.addParameter("currencyCode", "USD");
singleUse.addParameter("paymentReason", "HarryPotter 1-5 DVD set");

console.log("Sample CBUI url for SingleUse pipeline : " + singleUse.getURL());