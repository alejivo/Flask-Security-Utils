<h1 align="center">
  <br>
  Flask-Security-Utils
  <br>
</h1>

<h4 align="center">A simple security extension for <a href="https://flask.palletsprojects.com/" target="_blank">Flask</a>.</h4>

<p align="center">
  <a href="#about-the-project">About</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#usage">Usage</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#implementation-details">Implementation Details</a>
</p>

## About The Project

Flask-Security-Uils is an extension to enhance the security of flask applications blocking IP, countries and sqlinjections, it's aims to reimplement any deprecated security functionality from flask 1 to 2

This library needs a flask library over 1.1.4, may work with older versions but never been tested.
This library needs a Python 3.5 and above.

## Built With

* [Flask >= 1.1.4](https://flask.palletsprojects.com/)
* [IP2Location <= 8.7.4](https://pypi.org/project/IP2Location/)

<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Installation

Installation is straigthfoward

1. Create and activate your virtual enviroment
   ```sh
   virtualenv -p python3  venv
   ```
   ```sh
   source venv/bin/activate
   ```
2. Install Flask
   ```sh
   pip install Flask
   ```
3. Install Flask-Security-Utils (Not implemented yet)
   ```sh
   pip install Flask-Security-Utils 
   ```

<!-- USAGE EXAMPLES -->
### Usage

It's implemented as any flask extension:

```python
from flask import Flask
from security_utils.flask_security_utils import FlaskSecurityUtils

app = Flask(__name__)

app.config["IP_BLOCKED_CSV_FILE"]="example_csv.csv"
app.config["SQL_INJECTION_CHECK"]= True #You can avoid as it's the default value
fs = FlaskSecurityUtils(app)

if __name__ == "__main__":
    app.run()
```

_For more examples, read the  *flask_example.py files_

### Configuration

* IP_BLOCKED_CSV_FILE: must be the complete file where the block list is saved, only used for persistence in reboots.
* SQL_INJECTION_CHECK:
   - When is **True** check for injection runs for the whole site.
   - When is **False** the scan is skipped.
* BLOCKED_IP_LIST: 
   - When is **None** the check is avoided.
   - When is [] the check is avoided
   - When contains one o more IPs, the block behavior turn on.
* ALLOWED_IP_LIST:
   - When is **None** the check is avoided.
   - When is [] the check is avoided
   - When contains one o more IPs, the system only grant access to the IP list.
* IN_MEMORY_IP_DATABASE:
   - When is **True** the database is charged on memory.
   - When is **False** the database is used from file. __Is the default behavior__
* IP_COUNTRY_FILE_DB: 
   - When is **None** the folder 'ip_database' is created and 'IP-COUNTRY.BIN' downloaded from git.
   - When is [] the folder 'ip_database' is created and 'IP-COUNTRY.BIN' downloaded from git.
   - When contains one o more IPs, the block behavior turn on.
   - Download the last file version from https://lite.ip2location.com/database/ip-country
* IP_V6_COUNTRY_FILE_DB:
   - When is **None** the folder 'ip_database' is created and 'IPV6-COUNTRY.BIN' downloaded from git.
   - When is [] the folder 'ip_database' is created and 'IPV6-COUNTRY.BIN' downloaded from git.
   - When contains one o more IPs, the system only grant access to the IP list.
   - Download the last file version from https://lite.ip2location.com/database/ip-country
* ALLOWED_COUNTRIES: 
   - When is **None** the check is avoided.
   - When is [] the check is avoided
   - When contains one o more countries, the system only grant access to an IP from the country list.
   - Uses the ISO_3166-1_alpha-2 nomenclature, more info in https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
* BLOCKED_COUNTRIES:
   - When is **None** the check is avoided.
   - When is [] the check is avoided
   - When contains one o more countries, the block behavior turn on.
   - Uses the ISO_3166-1_alpha-2 nomenclature, more info in https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2

### Decorators

* SQLInjection Regex Firewall:
   - **sql_injection_check**
   - **ignore_sql_injection_check**
* IP Firewall:
   - **ignore_blocked_ip_list**
   - **ignore_allowed_ip_list**
   - **grant_access_ip_list(ipList=[])**
   - **block_ip_list(ipList=[])**
   - **localhost_only**
* Country Firewall:
   - **ignore_blocked_country_list**: I
   - **grant_access_country_list(countryList=[])**
   - **block_access_country_list(countryList=[])**

### Functions

* SQLInjection Regex Firewall:
   - **detectSQLInjectionVar**: Allow detecting an injection into a var:
   ```python
   # Test with an attact on var ex '+OR+1=1--
   # http://127.0.0.1:5000/'+OR+1=1--/check_single
   @app.route('/<var>/check-single', methods=['GET','POST'])
   def test_single(var: str):
      sqlCheck : SQLInjection = SQLInjection() #Use as singleton
      ip = request.remote_addr
      if sqlCheck.detectSQLInjectionVar(var,ip) == True:
         return "Alert, injection detected"
      else:
         return "Hi, i'm checked on demand"
   ```

<!-- ROADMAP -->
## Roadmap

- [x] SQLInjection detector and IP Blocking : it's allow to detect hackers and block the IP where the connection was made, currently use a list on memory and a CSV, it's allow to check the blocked IPs on Excel or Calc.
- [X] Block IP: It's allow to block an IP on the system or just an endpoint.
- [X] Allow IP: It's allow to only grant access to a global IP list, or just an endpoint.
- [X] Block Country: It's allow to ban an entire country on the system, or just an endpoint.
- [X] LocalHostOnly: An decorator that allow to create localhost endpoints, useful to interconnect microservices created on different programming languages.
- [ ] Scale Support
    - [ ] Redis IP storage: To share the blocked list across multiple Flask instances.


See the [open issues](https://github.com/alejivo/Flask-Security-Utils/issues) for a full list of proposed features (and known issues).


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## Implementation Details

Some implementations detail highly important to understand the library behavior. 


### Default regular expressions of SQLInjection

The class SQLInjection contains the following expressions to detect injections by default:

 * ((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(:)) to detect SQL meta-characters
 * *\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52)) to detect typical SQL Injection attack
 * ((\%27)|(\'))union")  to detect injection with the UNION keyword
 * *exec(\s|\+)+(s|x)p\w+ to detect attacks on a MS SQL Server

SQLInjection.clearExpressions() clear all regular expressions generated on the class constructor.
SQLInjection.addExpression(cls, expression : rawStr) will let you add new expressions in raw string format r"".

Based on:
https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=001f5e09-88b4-4a9a-b310-4c20578eecf9&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments


<!-- LICENSE -->
## License

Distributed under the BSD-3-Clause License. See `LICENSE.txt` for more information.

### IP2Location 

It's uses the IP2Location lite database who is free for personal or commercial use but attribution required by mentioning the use of this data as follows,

This site or product includes IP2Location LITE data available from <a href="https://lite.ip2location.com">https://lite.ip2location.com</a>.

<!-- CONTACT -->
## Contact

[@alejivo](https://twitter.com/alejivo) - email@alejivo.com

[www.linkedin.com/in/alejivo](www.linkedin.com/in/alejivo)

Project Link: [https://github.com/alejivo/Flask-Security-Utils](https://github.com/alejivo/Flask-Security-Utils)

Project Pypi Repo Link: [https://pypi.org/project/Flask-Security-Utils/](https://pypi.org/project/Flask-Security-Utils/)




