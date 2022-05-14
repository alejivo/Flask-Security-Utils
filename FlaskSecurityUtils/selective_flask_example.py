from flask import Flask, request
from security_utils.flask_security_utils import FlaskSecurityUtils
from security_utils.SQLInjection import SQLInjection

app = Flask(__name__)

fsu = FlaskSecurityUtils(app, 
                        ip_blocked_file="example_csv.csv",
                        sql_injection_check=False,
                        blocked_ip_list = [])

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/no-test', methods=['GET','POST'])
def no_test():
    return "Hi, I'm not tested for SQLinjections!"

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/test-injection', methods=['GET','POST'])
@fsu.sql_injection_check
def block():
    return "Hi, i'm checked on demand"

# Test with an attact on var ej '+OR+1=1--
@app.route('/<var>/check', methods=['GET','POST'])
def test_var(var: str):
    sqlCheck : SQLInjection = fsu.getSQLInjection()
    ip = request.remote_addr
    if sqlCheck.detectSQLInjectionVar(var,ip) == True:
        return "Alert, injection detected"
    else:
        return "Hi, i'm checked on demand"

# Test with an attact on var ej '+OR+1=1--
# http://127.0.0.1:5000/'+OR+1=1--/check_single
@app.route('/<var>/check_single', methods=['GET','POST'])
def test_single(var: str):
    sqlCheck : SQLInjection = SQLInjection() #Use as singleton
    ip = request.remote_addr
    if sqlCheck.detectSQLInjectionVar(var,ip) == True:
        return "Alert, injection detected"
    else:
        return "Hi, i'm checked on demand"

# With this decorator the ip is blocked on this endpoint
@app.route('/blocked-by-ip', methods=['GET','POST'])
@fsu.block_ip_list(ipList=['127.0.0.1'])
def hello2():
    return "Hi, i'm blocked on localhost!"

if __name__ == "__main__":
    app.run()