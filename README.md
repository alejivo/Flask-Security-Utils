# Flask-Security-Utils

Flask-Security-Uils is an extension to enhance the security of flask applications blocking IP, countries and sqlinjections, it's aims to reimplement any deprecated security functionality from flask 1 to 2

This library needs a flask library over 1.1.4, may work with older versions but never been tested.

Current's implementations:

    * SQLInjection detector and IP Blocking : it's allow to detect hackers and block the IP where the connection was made, currently use a list on memory and a CSV, it's allow to check the blocked IPs on Excel or Calc.

Upcoming:

    * Block IP: It's allow to block an IP on the system or just an endpoint.
    * Block Country: It's allow to ban an entire country on the system, or just an endpoint.
    * LocalHostOnly: An decorator that allow to create localhost endpoints, useful to interconnect microservices created on different programming languages.


Default regular expressions of SQLInjection
-------------------------------------------

The class SQLInjection contains the following expressions to detect injections by default:

    * ((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(:)) to detect SQL meta-characters
    * *\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52)) to detect typical SQL Injection attack
    * ((\%27)|(\'))union")  to detect injection with the UNION keyword
    * *exec(\s|\+)+(s|x)p\w+ to detect attacks on a MS SQL Server

SQLInjection.clearExpressions() clear all regular expressions generated on the class constructor.
SQLInjection.addExpression(cls, expression : rawStr) will let you add new expressions in raw string format r"".

Based on:
https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=001f5e09-88b4-4a9a-b310-4c20578eecf9&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments