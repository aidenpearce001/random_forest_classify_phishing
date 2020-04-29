import pandas as pd 
import numpy as np
import re
import whois
import requests
import json
import sys
import urllib.request
from bs4 import BeautifulSoup
import datetime 
import tldextract
import time
from socket import timeout

#Phishing : 1
#Legit : 0
#Suspicious : 2

def alive(url):
    try:
        check = urllib.request.urlopen(url,timeout=10).getcode()
        if check == 200:
            return 1
        else:
            return 0
    except timeout:      
        return 2
    except:
        return 2

def url_length(url):
    if len(url) >= 54 :
        return 2
    else:
        return 0

def redirect(url):
    if "//" in str(url[7:]):
        return 1
    else: 
        return 0 

def symbol(url):
    if "@" in url:
        return 1
    else:
        return 0 

def ip_in_url(url):
    match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)
    if match:   
        return 1
    else:
        return 0


def sub_domain(url):
    if url.count(".") >=3:
        return 2
    else:
        return 0

def puny(url):
    import idna
    try:
        url = ' '.join(repr(x).lstrip('u')[1:-1] for x in url)
        domain = url.split("/")
        if "xn--" in str(idna.encode(name[2])):
            return 1
    except:
        return 0

def protocol_in_domain(url):
    if "https" in url or "http" in url:
        return 1
    else:
        return 0

def http_notsafe(url):
    protocol = url.split("/")
    if protocol[0] == 'http:':
        return 2
    else:
        return 0
def shorten(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return 2 
    else:
        return 0
def digitcount(url):
    digit_num = sum([1 for c in url if c.isdigit()])
    if(digit_num <= 7):
        return 0
    else: 
        return 1

def Prefix_Suffix(url):
        try:
            _, domain, _ = tldextract.extract(url)
            if(domain.count('-')):
                return 1
                
            else:
                return -1
                
        except Exception as e:
            print("err_Prefix_Suffix",e)
            return 0
def age_of_domain(url):
    try:
        w = whois.whois(url)
        start_date = w.creation_date
        print(type(start_date))
        if type(start_date) == datetime.datetime:
            start = start_date
        elif type(start_date) == list:
            start = start_date[0]
        current_date = datetime.datetime.now()
        age =(current_date-start).days
        if(age>=180):
            # print('Legit '+url+":"+str(age))
            return 1
        else:
            # print('phishing '+url+":"+str(age))
            return -1
    except Exception as e:
        # print('phishing '+url)
        return 2
            
# def google_index(url):
#         try:
#             r = requests.head("https://webcache.googleusercontent.com/search?q=cache:" + url, timeout=7)
#             if r.status_code == 404:
#                 return -1
#             else:
#                 return 1
#         except Exception as e:
#             print("Error!")
#             return -1
#  def URL_of_Anchor(url):
#         try:
#             t1 = time.time()
#             regex_str = "<a href=\".*?\""
#             html = requests.get(url,timeout=7).text
#             links_list = regex.findall(regex_str,html)
#             count_internal = 0
#             for link in links_list:
#                 if url_is_internal(link,url):
#                     count_internal += 1
#             if len(links_list) == 0:
#                 return 1
#             else: 
#                 count_anchor = len(links_list) - count_internal
#                 rate = count_anchor / len(links_list)
#                 anchor_link_count = count_anchor
#                 if (rate < 0.31):
#                     return -1
#                 else:
#                     status = 1
def Have_Slash_Symbol_IP(url):
    match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)
    if match:   
        return 1
    elif "@" in str(url):
        return 1
    elif "//" in str(url[7:]):
        return 1
    else: 
        return 0 
def label(num):
    ls = [[num]]
    return ls

def vector(url):
    vec = [[url_length(url),sub_domain(url), protocol_in_domain(url), http_notsafe(url),shorten(url), Have_Slash_Symbol_IP(url), suffixcount(url), digitcount(url), Prefix_Suffix(url),age_of_domain(url),puny(url)]]

    return vec

df = pd.read_csv("dataset/data.csv")

dataset = pd.DataFrame([])

for i in range(4):
    data = df.iloc[i,1:]
    data = [x for x in data if str(x) != 'nan']
    for k in data:
        if alive(k) == 1:
            print(k)
            if i == 0:
                labels = 2
            elif i == 1 or i == 2 :
                labels = 1
            elif i == 3:
                labels = 0
            # age_of_domain(k)
            combine = np.append(label(labels),vector(k)).reshape(1 ,11) 
            dataset = dataset.append(pd.DataFrame(combine))
        else:
            continue

dataset.to_csv('dataset/file.csv',index = False)
