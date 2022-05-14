try:
    from flask import request, abort, has_request_context
    from functools import wraps
    import logging
    from security_utils.SQLInjection import SQLInjection
except ImportError as ex:
    print("Missing flask dependency")
    
traza = logging.getLogger(__name__)

class FlaskSecurityUtils(object):
    
    def __init__(self, app=None, 
                 ip_blocked_file="ip_blocked.csv", 
                 sql_injection_check = True,
                 blocked_ip_list = None,
                 allowed_ip_list = None):
        """
        Class init
        """
        self.__app = app
        self.__sqlInjectionCheck = sql_injection_check
        self.__ipBlockedFile = ip_blocked_file
        self.__blockedIpList = blocked_ip_list
        self.__allowedIpList = allowed_ip_list
        if app is not None:
            self.__init_app(app)
            
    def __getExtensionConfiguration(self):
        """
        This internal function is used to configure the extension
        """
        self.__ipBlockedFile = self.__app.config.get("IP_BLOCKED_CSV_FILE", self.__ipBlockedFile)
        self.__sqlInjectionCheck = self.__app.config.get("SQL_INJECTION_CHECK", self.__sqlInjectionCheck)
        self.__blockedIpList = self.__app.config.get("BLOCKED_IP_LIST", self.__blockedIpList)
        self.__allowedIpList = self.__app.config.get("ALLOWED_IP_LIST", self.__allowedIpList)

    def __init_app(self, app):
        self.__getExtensionConfiguration()
        self.__clsSQLInjection = SQLInjection(ip_blocked_file = self.__ipBlockedFile)
        
        #Register the before functions
        if self.__sqlInjectionCheck == True:
            self.__app.before_request(self.__beforeRequestInjectionCheck) 
            
        if self.__blockedIpList not in [None,[]]:
            self.__app.before_request(self.__beforeRequestBlockIPList)
            
        if self.__allowedIpList not in [None,[]]:
            self.__app.before_request(self.__beforeAllowIPList)
        
        #Register the after function
        self.__app.teardown_appcontext(self.__afterRequest) 
        

    def __beforeRequestBlockIPList(self,*args, **kwargs):
        """
        This function check if the request IP is on the blocked list 
        and reject the connection with a 403 Forbidden error.
        """

        # If is not a 404
        if request.endpoint in self.__app.view_functions:

            ip = request.remote_addr
            view_func = self.__app.view_functions[request.endpoint]
            exclude = False if not hasattr(view_func, '_exclude_ip_block') else True
            
            if ip in self.__blockedIpList and exclude == False:
                traza.critical("The IP[{}] trying to access the {} is on the block_ip_list.".format(ip,request.endpoint))
                abort(403)
    
    def __beforeAllowIPList(self,*args, **kwargs):
        """
        This function check if the request IP IS NOT on the allowed list 
        and reject the connection with a 403 Forbidden error.
        """

        # If is not a 404
        if request.endpoint in self.__app.view_functions:

            ip = request.remote_addr
            view_func = self.__app.view_functions[request.endpoint]
            exclude = False if not hasattr(view_func, '_ignore_allowed_ip_list') else True
            
            if ip not in self.__allowedIpList and exclude == False:
                traza.critical("The IP[{}] trying to access the {} is not on the IP allowed list.".format(ip,request.endpoint))
                abort(403)
                
        
    def __beforeRequestInjectionCheck(self,*args, **kwargs):
        """
        This function looks for injections before any request and blocks
        injections and banned ips.
        All blocked IPs will launch a 403 Forbidden error.
        """

        # If is not a 404
        if request.endpoint in self.__app.view_functions:
            
            view_func = self.__app.view_functions[request.endpoint]
            run_check = True if not hasattr(view_func, '_exclude_sql_injection_check') else False
            run_check = False if self.__sqlInjectionCheck == False else run_check
            
            if run_check == True:
                
                data = request.form.to_dict()
                ip = request.remote_addr
                res = self.__clsSQLInjection.detectSQLInjection(data,ip)
                if res == True: abort(403) #If the IP is blocked or an injection was detected
            
    
    def __afterRequest(self,exception):
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
                    if res == True: abort(403) #If the IP is blocked or an injection was detected
                
            return fn(*args, **kwargs)

        
        wrapper_injection_check.__name__ = fn.__name__
        return wrapper_injection_check
    
    def exclude_from_sql_injection_check(self,func):
        """
        This decorator is used to avoid the execution of sql injection test.
        """
        func._exclude_sql_injection_check = True
        return func
    
    def exclude_from_ip_block(self,func):
        """
        This decorator is used to avoid the execution of the global block IP list check.
        """
        func._exclude_ip_block = True
        return func
    
    def ignore_allowed_ip_list(self,func):
        """
        This decorator is used to allow all IPs to reach the endpoint, avoiding the allowed IP list.
        """
        func._ignore_allowed_ip_list = True
        return func
    
    def block_ip_list(self,ipList):
        
        """
        Restrict access to all IPs on the ipList[str]
        
        """

        def wrapper_block_ip_list(function):
            
            @wraps(function)
            def wrapper(*args, **kwargs):
                
                #If the request exists
                if has_request_context() == True:
                    
                    # If is not a 404
                    if request.endpoint in self.__app.view_functions:
                        
                        ip = request.remote_addr
                        if ip in ipList:
                            traza.critical("The IP[{}] is trying to access the {} is on the block_ip_list.".format(ip,request.endpoint))
                            abort(403)
                
                return function(*args, **kwargs)
            return wrapper
        
        return wrapper_block_ip_list
    
    def grant_access_ip_list(self,ipList):
        
        """
        Grant access only to all IPs on the ipList[str]
        
        """

        def wrapper_grant_access_ip_list(function):
            
            @wraps(function)
            def wrapper(*args, **kwargs):
                
                #If the request exists
                if has_request_context() == True:
                    
                    # If is not a 404
                    if request.endpoint in self.__app.view_functions:
                        
                        ip = request.remote_addr
                        if ip not in ipList:
                            traza.critical("The IP[{}] is trying to access the {} is not into the grant_access_ip_list{}.".format(ip,request.endpoint, ipList))
                            abort(403)
                
                return function(*args, **kwargs)
            return wrapper
        
        return wrapper_grant_access_ip_list
    
    def localhost_only(self, fn):
        
        """
        Rejects access to any non localhost IP 
        
        """
        def wrapper_localhost_only(*args, **kwargs):
            
            #If the request exists
            if has_request_context() == True:
                
                # If is not a 404
                if request.endpoint in self.__app.view_functions:
                    
                    ip = request.remote_addr
                    if ip not in ['localhost','127.0.0.1']:
                        traza.critical("The IP[{}] is trying to access the localhost_only {} function.".format(ip,request.endpoint))
                        abort(403)
                
            return fn(*args, **kwargs)

        
        wrapper_localhost_only.__name__ = fn.__name__
        return wrapper_localhost_only

    
    
