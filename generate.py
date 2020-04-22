import pandas as pd 
import numpy as np
import re
import whois
import requests
import json
import sys
import urllib.request
from bs4 import BeautifulSoup

#Phishing : 1
#Legit : 0
#Suspicious : 2

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
        current_date = datetime.datetime.now()
        age =(current_date-start_date[0]).days
        if(age>=180):
            return 0
        else:
            return 2
    except Exception as e:
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
    http_notsafe(url),shorten(url),age_of_domain(url)]]

    return vec

df = pd.read_csv("dataset/data.csv")

# data = df.iloc[2,1:]
# data = [x for x in data if str(x) != 'nan']

dataset = pd.DataFrame([])

for i in range(4):
    data = df.iloc[i,1:]
    data = [x for x in data if str(x) != 'nan']
    print(i)
    for k in data:
        print(k)
        if i == 0:
            labels = 2
        elif i == 1 or i == 2 :
            labels = 1
        elif i == 3:
            labels = 0
        combine = np.append(label(labels),vector(k)).reshape(1 ,11) 
        dataset = dataset.append(pd.DataFrame(combine))

dataset.to_csv('dataset/file.csv',index = False)