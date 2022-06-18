from flask import Flask, request
from security_utils.flask_security_utils import FlaskSecurityUtils
from security_utils.SQLInjection import SQLInjection

app = Flask(__name__)

fsu = FlaskSecurityUtils(app, 
                        ip_blocked_file="example_csv.csv",
                        sql_injection_check=False,
                        blocked_ip_list = [],
                        allowed_ip_list=None)

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/no-test', methods=['GET','POST'])
def no_test():
    return "Hi, I'm not tested for SQLinjections!"

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/test-injection', methods=['GET','POST'])
@fsu.sql_injection_check
def block():
    return "Hi, i'm checked for SQLInjections on demand"

# Test with an attact on var ej '+OR+1=1--
@app.route('/<var>/check', methods=['GET','POST'])
def test_var(var: str):
    sqlCheck : SQLInjection = fsu.getSQLInjection()
    ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if sqlCheck.detectSQLInjectionVar(var,ip) == True:
        return "Alert, injection detected"
    else:
        return "Hi, i'm checked on demand"

# With this decorator the ip is blocked on this endpoint
@app.route('/blocked-by-ip', methods=['GET','POST'])
@fsu.block_ip_list(ipList=['127.0.0.1'])
def blocked_by_ip():
    return "Hi, i'm blocked on localhost!"

# With this decorator, only localhost can access to this endpoint
@app.route('/localhost-only-endpoint', methods=['GET','POST'])
@fsu.localhost_only
def localhost_only_endpoint():
    return "Hi, i'm a localhost only endpoint!"

# With this decorator, all IPs can reach the endpoint, avoiding the allowed IP list.
@app.route('/ignore-allowed-ip-list')
@fsu.ignore_allowed_ip_list
def ignore_allowed_ip_list():
    return "Hi, i'm a endpoint who can be reach from anywhere!"

# With this decorator, you can grant access only to all IPs on the ipList[str]
# To test it allowed_ip_list must be None or []
@app.route('/grant-access-ip-list')
@fsu.grant_access_ip_list(ipList=['127.0.0.1'])
def grant_access_ip_list():
    return "Hi, I'm an endpoint who can only be reach from a list of IPs!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)