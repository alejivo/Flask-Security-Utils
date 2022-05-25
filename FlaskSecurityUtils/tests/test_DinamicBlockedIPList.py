import unittest
from security_utils.DinamicBlockedIPList import DinamicBlockedIPList
    
class TestDinamicBlockedIPList(unittest.TestCase):
    
    def test_isIPBlocked(self):
        singletonDinamicBlockedIPList = DinamicBlockedIPList()
        singletonDinamicBlockedIPList.blockIP('999.999.999.998')
        res = singletonDinamicBlockedIPList.isIPBlocked('999.999.999.998')
        self.assertTrue(res,"The block IP function is not working.")
        
    def test_SavedBlockedIP(self):
        #Create and block IP
        singletonDinamicBlockedIPList = DinamicBlockedIPList()
        singletonDinamicBlockedIPList.blockIP('999.999.999.998')
        
        #Delete and create the class again
        del singletonDinamicBlockedIPList
        singletonDinamicBlockedIPList = DinamicBlockedIPList()
        
        #Verify if the injector IP remains blocked
        res = singletonDinamicBlockedIPList.isIPBlocked('999.999.999.998')
        self.assertTrue(res,"The block P function is saving the IP.")
    
    