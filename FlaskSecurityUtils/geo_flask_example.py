from flask import Flask
from security_utils.flask_security_utils import FlaskSecurityUtils

app = Flask(__name__)

app.config["IP_COUNTRY_FILE_DB"] = None #Will auto download the file from the git repository
app.config["IP_V6_COUNTRY_FILE_DB"] = None #Will auto download the file from the git repository
app.config["IN_MEMORY_IP_DATABASE"] = True #You can avoid as it's the default value
app.config["BLOCKED_COUNTRIES"]= ['BR'] #Should be an string list, been none None or [] will disable the check for whole app.
fsu = FlaskSecurityUtils(app)

#With this decorator,  ignore the default country list and apply an on demand allow one.
@app.route('/on-demand-allow-country-list', methods=['GET','POST'])
@fsu.grant_access_country_list(countryList=['ES'])
@fsu.ignore_blocked_country_list
def exclude():
    return "Hi, I'm an on demand allow by country endpoint!"

#With this decorator, ignore the default block country list and apply an on demand block one.
@app.route('/on-demand-block-country-list', methods=['GET','POST'])
@fsu.block_access_country_list(countryList=['AR'])
@fsu.ignore_blocked_country_list
def exclude2():
    return "Hi, I'm an on demand block by country endpoint!"

#With this decorator, the IP is excluded from been block by country
@app.route('/country-block-excluded')
@fsu.ignore_blocked_country_list
def ip_block_excluded():
    return "Hi, I'm excluded from country block!"

#Without decorator, the system will block the default countries.
@app.route('/system-excluded-countries-list')
def system_excluded_countries_list():
    return "Hi, I'm an endpoint blocked by all BLOCKED_COUNTRIES list."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)