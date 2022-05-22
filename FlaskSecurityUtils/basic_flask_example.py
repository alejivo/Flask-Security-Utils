from flask import Flask
from security_utils.flask_security_utils import FlaskSecurityUtils

app = Flask(__name__)

app.config["IP_BLOCKED_CSV_FILE"]="example_csv.csv"
app.config["SQL_INJECTION_CHECK"]= True #You can avoid as it's the default value
app.config["BLOCKED_IP_LIST"]= ['127.0.0.1'] #Should be an string list, been none None or [] will disable the check for whole app.
fsu = FlaskSecurityUtils(app)

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/exclude', methods=['GET','POST'])
@fsu.ignore_sql_injection_check
def exclude():
    return "Hi, im an excluded endpoint'!"

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/no-exclude', methods=['GET','POST'])
def no_exclude():
    return "Hi, i'm a checked endpoint!"

#With this decorator the ip excluded from been block
@app.route('/ip-block-excluded')
@fsu.ignore_blocked_ip_list
def ip_block_excluded():
    return "Hi, I'm excluded from localhost block!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)