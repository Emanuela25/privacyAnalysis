import os
import sys
import signal

from mitmproxy import flowfilter, http, ctx

class MyAddon:
    def __init__(self,file):
        #construct HTTP response code
        self.http_code_ok = flowfilter.parse('~c 200')
        #create a directory for current app's log files "current_directory/logs/file/"
        current_directory = os.getcwd()
        self.folder_name = os.path.join(current_directory, 'logs', file)
        if not os.path.exists(self.folder_name):
                os.makedirs(self.folder_name, 0o777)
        #define all log file names
        self.host_file_name = self.folder_name + '/' + file + '_domains.txt'
        self.privacy_leak_file_name = self.folder_name + '/' + file + '_info.txt'
        #helper data strucutre
        self.host_set = set() #domain set
        self.whiltlist = ['127.0.0.1']#domains known well, no need to record
        self.keywords = {'sdkVersion', 'sdkVersionName', 'osversion', 
        'gms', 'deviceModel', 'deviceMake', 'language'}
        
    # @concurrent 
    def request(self, flow):
        #log all domain names in requests
        host = flow.request.host
        if not host in self.host_set and not host in self.whiltlist:
            self.host_set.add(host)
            with open(self.host_file_name,'a+') as f1:
                f1.write(host + '\n')
        
        #process get request url 
        if flow.request.method == "GET":
            url = flow.request.url
            #check if query field has any sensitive keyword inside
            if flow.request.query:
                leaks = dict()
                for q in flow.request.query:
                    key = q
                    value = flow.request.query[q]
                    if key in self.keywords:
                        if not key in leaks:
                            leaks[key] = {value}
                        elif not value in leaks[key]:
                            leaks[key].add(value)
                #write to log file if any leaks
                if leaks:
                    with open(self.privacy_leak_file_name,'a+') as f2:
                        f2.write(flow.request.method + ' ' + url  + ": \n")
                        for key in leaks:
                            f2.write("\t" + key + ": ")
                            for value in leaks[key]:
                                f2.write(value + " ")
                            f2.write("\n")

        #process post request content
        if flow.request.method == "POST":
            if flow.request.content:
                req_content = str(flow.request.content)
                #ctx.log('request content: %s' % req_content)

addons = [MyAddon(sys.argv[3])]
