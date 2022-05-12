from flask import Flask
from security_utils.flask_security_utils import FlaskSecurityUtils

app = Flask(__name__)

app.config["IP_BLOCKED_CSV_FILE"]="example_csv.csv"
app.config["SQL_INJECTION_CHECK"]= True #You can avoid as it's the default value
fs = FlaskSecurityUtils(app)

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/exclude', methods=['GET','POST'])
@fs.exclude_from_sql_injection_check
def hello():
    return "Hi, im an excluded endpoint'!"

#Atack this endpoint with a field as topic=Gifts'+OR+1=1--
@app.route('/no-exclude', methods=['GET','POST'])
def hello2():
    return "Hi, i'm a checked endpoint!"

# @app.route('/block')
# @fp.sql_injection_check
# def block():
#     print('during view')
#     return 'Hello, World!'

if __name__ == "__main__":
    app.run()