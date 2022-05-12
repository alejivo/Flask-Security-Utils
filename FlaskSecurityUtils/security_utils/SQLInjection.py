from datetime import datetime as dt
import logging
import base64
import re
import csv
from typing import TypeVar

rawStr = TypeVar('rawStr', bound=str)

traza = logging.getLogger(__name__)

class SQLInjection():
    
    """
    Clase de utilidad que permite realizar diferentes verificaciones de seguridad
    antes de ingresar los datos al sistema.
    """
    
    __IPBlocked = []
    __instance = None
    __expressions = []
    __ip_blocked_file = None
        
    def __new__(cls, ip_blocked_file = 'ip_blocked.csv'):
        
        """
        Constructor of the SQLInjection class.
        """
        
        if (cls.__instance == None):
            
            #Se csv file
            cls.__ip_blocked_file = ip_blocked_file
            
            #Regular expressions loaded by default
            cls.addExpression(r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(:))") #Detect SQL meta-characters
            cls.addExpression(r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))") #Regex for typical SQL Injection attack
            cls.addExpression(r"((\%27)|(\'))union") #Regex for Injection with the UNION keyword
            cls.addExpression(r"exec(\s|\+)+(s|x)p\w+") #Injection attacks on a MS SQL Server
             
            # Load or or create the file with blocked ip 
            try:
                
                with open(cls.__ip_blocked_file) as csv_file:
                    csv_reader = csv.reader(csv_file, delimiter=',')
                    firstLine=True
                    for row in csv_reader:
                        if firstLine == True:
                            firstLine = False
                        else:
                            if len(row) > 1 : cls.__IPBlocked.append(row[0])
            except:
                
                header = ['IP_BLOCKED', 'DATE']

                with open(cls.__ip_blocked_file, 'w') as f:
                    cvs_writer = csv.writer(f)
                    cvs_writer.writerow(header)
                        
            #Create the class
            cls.__instance = object.__new__(cls)
        
        return cls.__instance
    
    @classmethod
    def clearExpressions(cls) -> None:
        
        """
        Method that removes all regular expressions from the class.
        """
        cls.__expressions.clear()
    
    @classmethod
    def addExpression(cls, expression : rawStr) -> None:
        
        """
        Method that allows adding regular expressions to be verified.
        """
        cls.__expressions.append(expression)
        
    @classmethod
    def blockIP(cls, ipToBlock : str) -> None:
        
        """
        Method that allows you to register an IP ban.
        """
        
        #Avoid duplicates
        if cls.isIPBlocked(ipToBlock) == True: return None
        
        #The IP is added to the list of blocks
        cls.__IPBlocked.append(ipToBlock)
        # The IP is saved for future attacks
        with open(cls.__ip_blocked_file, 'a+') as csv_file:
            ipBlockedWriter = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            ipBlockedWriter.writerow([ipToBlock, dt.now()])
    
    @classmethod
    def detectSQLInjection(cls, dicForm : dict, ipToBlock : str) -> bool:
        
        """
        Method that allows to detect SQL injections in a post.
        """
        
        if ipToBlock in cls.__IPBlocked: 
            return True
        
        for key, value in dicForm.items():
            
            if key in ['csrf_token','g-recaptcha-response']: continue
            if cls.detectSQLInjectionItem(value) == True: 
                cls.blockIP(ipToBlock)
                traza.critical("An SQL Injection attempt was detected on {}, with the values {}.".format(key,str(value)))
                return True
        
        return False
    
    @classmethod
    def detectSQLInjectionVar(cls, var : str, ipToBlock : str) -> bool:
        
        """
        Method that allows to detect SQL injections in a variable.
        """
        
        if ipToBlock in cls.__IPBlocked: 
            return True
        
        if cls.detectSQLInjectionItem(var) == True: 
            cls.blockIP(ipToBlock)
            traza.critical("SQL Injection attempt detected from IP[{}], with values {}.".format(ipToBlock,str(var)))
            return True
        
        return False
    
    @classmethod
    def detectSQLInjectionItem(cls, item : str) -> bool:
        
        """
        Method that allows detecting through regular expressions, hexadecimal attacks,
         SQL and base64 binary types.
        """
        
        def checkItem(strToCheck):
            
            auxStr = str(strToCheck)
            
            if auxStr == "None":
                return False
            
            for expression in cls.__expressions:
                if re.search(expression, auxStr) is not None:
                    return True
                
            return False
        
        try:
            
            decodedStr = base64.b64decode(item).decode('utf8')
            if checkItem(decodedStr) == True: return True
            if checkItem(item) == True: return True
            return False
            
        except:
            
            if checkItem(item) == True: return True
            return False
    
    @classmethod
    def isIPBlocked(cls, ip: str) -> bool:
        
        if ip in cls.__IPBlocked: 
            return True
    