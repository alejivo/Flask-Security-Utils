<h1 align="center">
  <br>
  Flask-Security-Utils
  <br>
</h1>

<h4 align="center">A simple security extension for <a href="http://electron.atom.io" target="_blank">Flask</a>.</h4>

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

## Built With

* [Flask >= 1.1.4](https://flask.palletsprojects.com/)

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



<!-- ROADMAP -->
## Roadmap

- [x] SQLInjection detector and IP Blocking : it's allow to detect hackers and block the IP where the connection was made, currently use a list on memory and a CSV, it's allow to check the blocked IPs on Excel or Calc.
- [ ] Block IP: It's allow to block an IP on the system or just an endpoint.
- [ ] Block Country: It's allow to ban an entire country on the system, or just an endpoint.
- [ ] LocalHostOnly: An decorator that allow to create localhost endpoints, useful to interconnect microservices created on different programming languages.
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



<!-- CONTACT -->
## Contact

[@alejivo](https://twitter.com/alejivo) - contact@alejivo.com

[www.linkedin.com/in/alejivo](www.linkedin.com/in/alejivo)

Project Link: [https://github.com/alejivo/Flask-Security-Utils](https://github.com/alejivo/Flask-Security-Utils)




