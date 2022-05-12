import unittest
from security_utils.SQLInjection import SQLInjection
    
class TestSQLInjection(unittest.TestCase):

    def test_detectSQLInjectionItem(self):
        singletonInjection = SQLInjection()
        simpleInjection = "Gifts'+OR+1=1--"
        res = singletonInjection.detectSQLInjectionItem(simpleInjection)
        self.assertTrue(res,"The class can't detect the injection 'Gifts'+OR+1=1--'.")
        
    def test_detectSQLInjection(self):
        singletonInjection = SQLInjection()
        dicForm = {}
        dicForm["Name"] = "Gifts'+OR+1=1--"
        dicForm["Price"] = "50"
        res = singletonInjection.detectSQLInjection(dicForm, '999.999.999.997')
        finalRes = True if res == True and singletonInjection.isIPBlocked('999.999.999.997') == True else False
        self.assertTrue(finalRes,"The class can't detect the injection on the name field of the dictionary that simulates a form.")
        
    def test_detectSQLInjectionVar(self):
        singletonInjection = SQLInjection()
        varInjection = "Gifts'+OR+1=1--"
        res = singletonInjection.detectSQLInjectionVar(varInjection, '999.999.999.999')
        finalRes = True if res == True and singletonInjection.isIPBlocked('999.999.999.999') == True else False
        self.assertTrue(finalRes,"The class can't detect or block the injection 'Gifts'+OR+1=1--' on a var")
    
    def test_isIPBlocked(self):
        singletonInjection = SQLInjection()
        singletonInjection.blockIP('999.999.999.998')
        res = singletonInjection.isIPBlocked('999.999.999.998')
        self.assertTrue(res,"The block IP function is not working.")
        
    def test_SavedBlockedIP(self):
        #Create and block IP
        singletonInjection = SQLInjection()
        singletonInjection.blockIP('999.999.999.998')
        
        #Delete and create the class again
        del singletonInjection
        singletonInjection = SQLInjection()
        
        #Verify if the injector IP remains blocked
        res = singletonInjection.isIPBlocked('999.999.999.998')
        self.assertTrue(res,"The block P function is saving the IP.")
    
    