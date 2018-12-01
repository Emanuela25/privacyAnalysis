import os
import sys
import signal
from urllib.parse import unquote
import json

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
        self.encode = {'identity', 'gzip', 'deflate', 'br'}
        self.host_set = set() #domain set
        self.whiltlist = ['127.0.0.1']#domains known well, no need to record
        self.keywords = {'sdkVersion', 'sdkVersionName', 'osversion', 
        'gms', 'deviceModel', 'deviceMake', 'language'}
    
    ###helper functions
    #determine if a string is a json object or not
    def isJson(self, str):
        try:
            json_object = json.loads(str)
        except ValueError as e:
            return False
        return True
    #parse json object (json arrary/ json object)
    def parseJson(self, obj):
        new_obj = dict()
        result = dict()
        if type(obj) is list:
            new_obj = obj[0]
        else:
            new_obj = obj
        result = self.traverseJson(new_obj)
        return result
    #dfs traverse a json object, store all key-value pair
    def traverseJson(self, obj):
        result = dict()
        for key in obj.keys():
            if type(obj[key]) is dict:
                result.update(self.traverseJson(obj[key]))
            else:
                value_str = ""
                if type(obj[key]) is list:
                    value_str = " ".join(str(x) for x in obj[key])
                else:
                    value_str = str(obj[key])
                result[key] = value_str
        return result
        
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
            if flow.request.raw_content:
                print(flow.request.url)
                req_content = ""
                if flow.request.headers.get("Content-Encoding", ""):
                    encode_type = flow.request.headers.get("Content-Encoding", "")
                    if not encode_type in self.encode:
                        req_content = ""
                    else:
                        req_content = str(flow.request.content)
                else:
                    req_content = str(flow.request.content)

                if req_content:
                    req_content_str = unquote(req_content[2:-1])
                    if self.isJson(req_content_str):
                        cotent_obj = json.loads(req_content_str)
                        pairs = self.parseJson(cotent_obj)
                        for k in pairs.keys():
                            print(k + ' ' + pairs[k])
                    else:
                        #print('request content: %s' % req_content_str)
                        print("request content is string")
        
                    #print('request content: %s' % req_content)

addons = [MyAddon(sys.argv[3])]
