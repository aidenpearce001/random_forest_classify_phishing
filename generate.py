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

#Phishing : 1
#Legit : 0
#Suspicious : 2

def alive(url):
    try:
        check = urllib.request.urlopen(url).getcode()
        if check == 200:
            return 1
        else:
            return 0
    except:
        return 0

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

def age_of_domain(url):
    try:
        w = whois.whois(url)
        start_date = w.creation_date
        if type(start_date) == list:
            start = start_date[0]
        elif type(start_date) == datetime.datetime:
            start = start_date
        current_date = datetime.datetime.now()
        age =(current_date-start).days
        # print(age)
        if(age>=62):
            return 0
        else:
            return 2
    except Exception as e:
        return 2

def combo1(url):
    if '-' in url and '//' in str(url[7:]) :
        return 1
    else:
        return 0

def combo2(url):
    if '-' in url and '@' in url:
        return 1
    else:
        return 0

def combo3(url):   
    if '@' in url and '//' in str(url[7:]) :
        return 1
    else:
        return 0

def favion(url):
    pass
        # page = urllib.request.urlopen(l)
        # soup = BeautifulSoup(page,"html.parser")
        # icon_link = soup.find("link", rel="shortcut icon")
        # icon = urllib.urlopen(icon_link['href'])
        # prin(l+":"+icon_link)
    # except KeyboardInterrupt:
    #     sys.exit(0)
    # except:
    #     continue

def label(num):
    ls = [[num]]
    return ls

def vector(url):
    vec = [[url_length(url),redirect(url),symbol(url),ip_in_url(url),sub_domain(url),puny(url),protocol_in_domain(url),
    http_notsafe(url),shorten(url),age_of_domain(url),combo1(url),combo2(url),combo3(url)]]

    return vec

df = pd.read_csv("dataset/data.csv")

dataset = pd.DataFrame([])

# data = df.iloc[1,1:]
# data = [x for x in data if str(x) != 'nan']
# for i in data:
#     print(age_of_domain(i))
# age_of_domain("https://www.google.com/")
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
            combine = np.append(label(labels),vector(k)).reshape(1 ,14) 
            dataset = dataset.append(pd.DataFrame(combine))
        else:
            continue

dataset.to_csv('dataset/file.csv',index = False)