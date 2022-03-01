import io
import ipaddress
import numpy as np
import os
import pandas as pd
import pymysql
import re

from ipaddress import IPv4Address, IPv4Network
from pandas import Series, DataFrame
from sqlalchemy import create_engine

# Dictionary of Internet top-level domains
# source: https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
domains = {'com': 'commercial', 'org': 'organization', 'net': 'network', 'int': 'international', 'edu': 'education', 'gov': 'US Government', 'mil': 'US Military'}

# Filepaths for CSV files
# source: https://en.wikipedia.org/wiki/Country_code_top-level_domain
filepath = '/Users/Chris/anaconda3/SFL_scientific/DATA.csv'
filepath2 = '/Users/Chris/anaconda3/SFL_scientific/country_codes.csv'


# Ingest DATA.csv as 'people' pandas dataframe
people = pd.read_csv(filepath)
website = people['email'].str.split("@", n=1, expand=True)
people['website'] = website[1]

# Ingest country_codes.csv as dictionary
filepath2 = '/Users/Chris/anaconda3/SFL_scientific/country_codes.csv'
country_codes = pd.read_csv(filepath2)
country_dict = dict(country_codes.values)

# Create url_df dataframe 
url = people['website'].str.split(".", n=0, expand=False)
domains_list = pd.Series(dtype=str)
url_country = pd.Series(dtype=str)
frame = { 'url': url, 'domain': domains_list, 'url_country': url_country}
url_df = pd.DataFrame(frame)

# Assign url_df values based on country and domain type
for index, row in url_df.iterrows():
    for segment in row['url']:
        if segment in domains.keys():
            url_df['domain'][index] = domains[segment]
        elif segment in country_dict.keys():
            url_df['url_country'][index] = country_dict[segment]
        else:
            continue

# Add website_domain and website_country columns to people dataframe
people['website_domain'] = url_df['domain']
people['website_country'] = url_df['url_country']

# https://stackoverflow.com/questions/42385097/check-if-ip-address-belongs-to-a-class-a-b-and-c-in-python
# https://www.meridianoutpost.com/resources/articles/IP-classes.php
# Class A - networks with large number of total hosts i.e. large ISPs
# Class B - networks with medium number of total hosts i.e. enterprises, offices
# Class C - networks with small number of total hosts i.e. small businesses and homes
# Class D - multicasting i.e. for audio/video streaming, cable TV networks, stock market network

# private IP class range
classA = IPv4Network(("10.0.0.0", "255.0.0.0"))  # or IPv4Network("10.0.0.0/8")
classB = IPv4Network(("172.16.0.0", "255.240.0.0"))  # or IPv4Network("172.16.0.0/12")
classC = IPv4Network(("192.168.0.0", "255.255.0.0"))  # or IPv4Network("192.168.0.0/16")

# Construct ip_df dataframe based on IP address types and classes
series_ip_type = pd.Series(dtype=str)
series_ip_class = pd.Series(dtype=str)
series_ip = people['ip_address']
ip_frame = {'ip_address': series_ip, 'ip_type': series_ip_type, 'ip_class': series_ip_class}
ip_df = pd.DataFrame(ip_frame)

# Check if IPv4 address is private or global and its class
for index, value in people['ip_address'].items():
    ip = IPv4Address(value)
    ip_type =''
    if ipaddress.ip_address(value).is_private:
        ip_df['ip_type'][index] = 'private'
        if ip in classA:
            ip_df['ip_class'][index] = 'A'
        elif ip in classB:
            ip_df['ip_class'][index] = 'B'
        elif ip in classC:
            ip_df['ip_class'][index] = 'C'
        else:
            # ip_class = ''
            continue
    elif ipaddress.ip_address(value).is_global:
        ip_df['ip_type'][index] = 'public'
        octets = value.split('.')
        first_octet = int(octets[0])
        if first_octet in range(1,128):
            ip_df['ip_class'][index] = 'A'
        elif first_octet in range(128,192):
            ip_df['ip_class'][index] = 'B'
        elif first_octet in range(192,224):
            ip_df['ip_class'][index] = 'C'
        elif first_octet in range(224,240):
            ip_df['ip_class'][index] = 'D'
        else:
            ip_class = ''
    else:
        continue

# Add ip_type and ip_class columns to people dataframe
people['ip_type'] = ip_df['ip_type']
people['ip_class'] = ip_df['ip_class']

# Rearrange columns in dataframe
people = people.drop(columns=['website'])
new_column_names = ['id', 'first_name', 'last_name', 'gender', 'email', 'website_domain', 'website_country', 'ip_address', 'ip_type', 'ip_class']
people = people.reindex(columns=new_column_names)

# Write people dataframe to CSV file
# people.to_csv('/Users/Chris/anaconda3/SFL_scientific/new_DATA.csv', index=False)

# Write people dataframe to MySQL database table with credentials
engine = create_engine('mysql+pymysql://root:SFLpassword!@localhost/sfl_db')
try:
    people.to_sql(name='people_table',
                  con=engine,
                  if_exists='replace',
                  index=False
                  )
except ValueError as vx:
    print(vx)
except Exception as ex:   
    print(ex)

# Query data from 'sfl_db' MySQL database's 'people_table' table
# query = pd.read_sql("select * from sfl_db.people_table", con=engine);
# print(query)