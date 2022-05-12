try:
    from flask import request, abort, has_request_context
    from security_utils.SQLInjection import SQLInjection
except ImportError as ex:
    print("Missing flask dependency")

class FlaskSecurityUtils(object):
    
    def __init__(self, app=None, 
                 ip_blocked_file="ip_blocked.csv", 
                 sql_injection_check = True):
        """
        Class init
        """
        self.__app = app
        self.__sql_injection_check = sql_injection_check
        self.__ip_blocked_file = ip_blocked_file
        if app is not None:
            self.__init_app(app)
            
    def __getExtensionConfiguration(self):
        """
        This internal function is used to configure the extension
        """
        self.__ip_blocked_file = self.__app.config.get("IP_BLOCKED_CSV_FILE", self.__ip_blocked_file)
        self.__sql_injection_check = self.__app.config.get("SQL_INJECTION_CHECK", self.__sql_injection_check)

    def __init_app(self, app):
        self.__getExtensionConfiguration()
        self.__clsSQLInjection = SQLInjection(ip_blocked_file = self.__ip_blocked_file)
        self.__app.before_request(self.before_request_func) #Register the before function
        self.__app.teardown_appcontext(self.after_request) #Register the after function

    def before_request_func(self,*args, **kwargs):
        """
        This function looks for injections before any request and blocks
        injections and banned ips.
        """

        # If is not a 404
        if request.endpoint in self.__app.view_functions:
            
            view_func = self.__app.view_functions[request.endpoint]
            run_check = True if not hasattr(view_func, '_exclude_sql_injection_check') else False
            run_check = False if self.__sql_injection_check == False else run_check
            
            if run_check == True:
                
                data = request.form.to_dict()
                ip = request.remote_addr
                res = self.__clsSQLInjection.detectSQLInjection(data,ip)
                if res == True: abort(404) #If the IP is blocked or an injection was detected
            
    
    def after_request(self,exception):
        pass
    
    def getSQLInjection(self) -> SQLInjection:
        """
        Allow to get the SQLInjection parser but as is a singleton
        no new instance will be created, instead the class one.
        """
        return self.__clsSQLInjection
    
    def sql_injection_check(self,fn):
        
        """
        Check the request for sql injections
        """
        
        def wrapper_injection_check(*args, **kwargs):
            
            #If the request exists
            if has_request_context() == True:
                
                # If is not a 404
                if request.endpoint in self.__app.view_functions:
                    
                    data = request.form.to_dict()
                    ip = request.remote_addr
                    
                    res = self.__clsSQLInjection.detectSQLInjection(data,ip)
                    if res == True: abort(404) #If the IP is blocked or an injection was detected
                
            return fn(*args, **kwargs)

        
        wrapper_injection_check.__name__ = fn.__name__
        return wrapper_injection_check
    
    def exclude_from_sql_injection_check(self,func):
        """
        This decorator is used to avoid the execution of sql injection test.
        """
        func._exclude_sql_injection_check = True
        return func
    
