import unittest
from security_utils.SQLInjection import SQLInjection
from security_utils.DinamicBlockedIPList import DinamicBlockedIPList
    
class TestSQLInjection(unittest.TestCase):

    def test_detectSQLInjectionItem(self):
        singletonDinamicBlockedIPList = DinamicBlockedIPList()
        singletonInjection = SQLInjection(singletonDinamicBlockedIPList)
        simpleInjection = "Gifts'+OR+1=1--"
        res = singletonInjection.detectSQLInjectionItem(simpleInjection)
        self.assertTrue(res,"The class can't detect the injection 'Gifts'+OR+1=1--'.")
        
    def test_detectSQLInjection(self):
        singletonDinamicBlockedIPList = DinamicBlockedIPList()
        singletonInjection = SQLInjection(singletonDinamicBlockedIPList)
        dicForm = {}
        dicForm["Name"] = "Gifts'+OR+1=1--"
        dicForm["Price"] = "50"
        res = singletonInjection.detectSQLInjection(dicForm, '999.999.999.997')
        finalRes = True if res == True and singletonDinamicBlockedIPList.isIPBlocked('999.999.999.997') == True else False
        self.assertTrue(finalRes,"The class can't detect the injection on the name field of the dictionary that simulates a form.")
        
    def test_detectSQLInjectionVar(self):
        singletonDinamicBlockedIPList = DinamicBlockedIPList()
        singletonInjection = SQLInjection(singletonDinamicBlockedIPList)
        varInjection = "Gifts'+OR+1=1--"
        res = singletonInjection.detectSQLInjectionVar(varInjection, '999.999.999.999')
        finalRes = True if res == True and singletonDinamicBlockedIPList.isIPBlocked('999.999.999.999') == True else False
        self.assertTrue(finalRes,"The class can't detect or block the injection 'Gifts'+OR+1=1--' on a var")
    
        

    
    