import os
import sys
import signal
from urllib.parse import unquote
import json

from mitmproxy import flowfilter, http, ctx

class MyAddon:
    def __init__(self,file):
        #create a directory for current app's log files "current_directory/logs/file/"
        current_directory = os.getcwd()
        self.folder_name = os.path.join(current_directory, 'logs', file)
        if not os.path.exists(self.folder_name):
                os.makedirs(self.folder_name, 0o777)

        #define all log file names
        self.host_file_name = self.folder_name + '/' + file + '_domains.txt'
        self.get_leak_file_name = self.folder_name + '/' + file + '_get_info.txt'
        self.post_leak_file_name = self.folder_name + '/' + file + '_post_info.txt'

        #helper data strucutre
        #encode method supported by mitmproxy
        self.encode = {'identity', 'gzip', 'deflate', 'br'}
        #record domains already logged
        self.host_set = set() #domain set
        #domains known well, no need to record
        self.whiltlist = ['127.0.0.1', 'android.clients.google.com','play.googleapis.com']
        #keywords list for detection
        self.keywords = {'sdkVersion', 'sdkVersionName', 'osversion', 'deviceModel', 'deviceMake', 
        'device', 'mobileDeviceId', 'cpu_abi', 'deviceData','deviceOSVersion', 'advertisingTrackingId',
        'language', 'geoip_country', '$model', 'ssid', 'mac_address', 'adgroup', 'ip_address', 'gps_adid',
        'ip', 'csdk','cbrand', 'cmodel', 'cosver', 'cos', 'google_advertising_id', 'sdk_ver', 'AdvertisementHelper',
        'is_referrable', 'TaskCollectAdvertisingId_count', 'limit_ad_tracking', 'carrier', 'androidADID',
        'version_name', 'os_name', 'device_id', 'session_id', 'is_portrait'}
    
    ###helper functions
    #determine if post request content is a json object or not
    def isJson(self, str):
        try:
            json_object = json.loads(str)
        except ValueError as e:
            return False
        return True

    #parse json object in post request(json arrary/ json object)
    def parseJson(self, obj):
        new_obj = dict()
        result = dict()
        #json array: only process the first json object
        if type(obj) is list:
            new_obj = obj[0]
            if type(new_obj) is not dict:
                result['should_be_list'] = " ".join(str(x) for x in obj)
            else:
                result = self.traverseJson(new_obj)
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

    #process all http/https request sent from mobile app   
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
                        with open(self.get_leak_file_name,'a+') as f2:
                            f2.write(flow.request.method + ' ' + url  + ": \n")
                            for key in leaks:
                                f2.write("\t" + key + ": ")
                                for value in leaks[key]:
                                    f2.write(value + " ")
                                f2.write("\n")

            #process post request content
            if flow.request.method == "POST":
                if flow.request.raw_content:
                    req_content = ""
                    #check request content's encoding type before decode
                    if flow.request.headers.get("Content-Encoding", ""):
                        encode_type = flow.request.headers.get("Content-Encoding", "")
                        #if encoding method is not supported, return empty string
                        if not encode_type in self.encode:
                            req_content = ""
                        else:
                            req_content = str(flow.request.content)
                    else: #post content not encoded at all
                        req_content = str(flow.request.content)

                    #if has post content and decode successfully, further process the decoded content
                    if req_content:
                        url = flow.request.url
                        req_content_str = str(unquote(req_content[2:-1]))

                        #if request body is a json string 
                        if self.isJson(req_content_str):
                            cotent_obj = json.loads(req_content_str)
                            pairs = self.parseJson(cotent_obj)
                            #since python determine list as json, if parseJson results shows
                            #it is just a list but not real json, check the lists instead of key-value pairs
                            if 'should_be_list' in pairs.keys():
                                for word in self.keywords:
                                    if pairs['should_be_list'].find(word) != -1:
                                        with open(self.post_leak_file_name,'a+') as f3:
                                            f3.write('List ' + url  + ": \n")
                                            f3.write(req_content_str +'\n')
                                        break
                            else: #check key-value pairs for keywords if request is a real json
                                leaks = dict()
                                for k in pairs.keys():
                                    #print(k + ' ' + pairs[k])
                                    if k in self.keywords:
                                        if not k in leaks:
                                            leaks[k] = {pairs[k]}
                                        elif not value in leaks[key]:
                                            leaks[key].add(value)
                                if leaks:
                                    with open(self.post_leak_file_name,'a+') as f3:
                                        f3.write('Json ' + url  + ": \n")
                                        for key in leaks:
                                            f3.write("\t" + key + ": ")
                                            for value in leaks[key]:
                                                f3.write(value + " ")
                                            f3.write("\n")
                        else: #check request body for keywords if it is a string object
                            for word in self.keywords:
                                if req_content_str.find(word) != -1:
                                    with open(self.post_leak_file_name,'a+') as f3:
                                        f3.write('String ' + url  + ": \n")
                                        f3.write(req_content_str +'\n')
                                    break
                                    
addons = [MyAddon(sys.argv[3])]
