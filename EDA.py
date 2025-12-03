import numpy as np
import pandas as pd
import geoip2.database
import plotly.io
plotly.io.renderers.default = "browser"
import plotly.express as px
import requests
import django
from django.conf import settings
settings.configure(
    GEOIP_PATH = "/Users/kalooina/Documents/Paperwork/scolar/DSTI/2025:2026/Machine Learning/cybersecurity_attacks ( project1 )/geolite2_db" ,
    INSTALLED_APPS = [ "django.contrib.gis" ]
    )
django.setup()
from django.contrib.gis.geoip2 import GeoIP2

geoIP = GeoIP2()

maxmind_geoip2_db_url = "https://www.maxmind.com/en/accounts/1263991/geoip/downloads"
geoip2_doc_url = "https://geoip2.readthedocs.io/en/latest/"
geoip2_django_doc_url = "https://docs.djangoproject.com/en/5.2/ref/contrib/gis/geoip2/"

df = pd.read_csv("/Users/kalooina/Documents/Paperwork/scolar/DSTI/2025:2026/Machine Learning/cybersecurity_attacks ( project1 )/cybersecurity_attacks.csv" )

def piechart_col( col , names = None ) :
    if names is None :
        fig = px.pie( df[ col ].value_counts() ,
                     values = col ,
                     names = df[ col ].value_counts().index )
        fig.show()
    else : 
        fig = px.pie( df[ col ].value_counts() ,
                     values = col ,
                     names = names )
        fig.show()
        
#%% EDA
        
df = df.rename( columns = { "Timestamp" : "date" ,
                           "Alerts/Warnings" : "Alert Trigger" ,
                           })
print( df.describe())

# NAs

df_s0 = df.shape[ 0 ]
for col in df.columns :
    NA_n = sum( df[ col ].isna())
    if NA_n > 0 :
        print( f"number of NAs in { col } = { NA_n } / { df_s0 } = { NA_n / df_s0 } " )

# date

col_name = "date"
date_end = max( df[ col_name ])
date_start = min( df[ col_name ])
print( f"dates go from { date_start } and { date_end }" )
fig = px.histogram( df , col_name )
fig.show()

#%% IP address --> country , city with geoip2 ___ TRASH IT !!!!

def ip_to_country( ip_address ) :
    print( ip_address )
    try :
        with geoip2.database.Reader( "/Users/kalooina/Documents/Paperwork/scolar/DSTI/2025:2026/Machine Learning/cybersecurity_attacks ( project1 )/geolite2_db/GeoLite2-City.mmdb" ) as reader :
            response = reader.city( ip_address )
            country = response.country.name
        return country
    except :
        return pd.NA
def ip_to_city( ip_address ) :
    print( ip_address )
    try :
        with geoip2.database.Reader( "/Users/kalooina/Documents/Paperwork/scolar/DSTI/2025:2026/Machine Learning/cybersecurity_attacks ( project1 )/geolite2_db/GeoLite2-City.mmdb" ) as reader :
            response = reader.city( ip_address )
            city = response.subdivisions.most_specific.name
        return city 
    except :
        return pd.NA
df[ "IP country" ] = df[ "Source IP Address" ].apply( lambda x : ip_to_country( x ))
df[ "IP city" ] = df[ "Source IP Address" ].apply( lambda x : ip_to_city( x ))

#%% IP address 

def ip_to_coords( ip_address ) :
    ret = pd.Series( dtype = object )
    try :
        res = geoIP.geos( ip_address ).wkt
        lon , lat = res.replace( "(" , "" ).replace( ")" , "" ).split()[ 1 : ]
        # ret = ret.append( pd.Series([ lat , lon ]))
        ret = pd.concat([ ret , pd.Series([ lat , lon ])] , ignore_index = True )
    except :
        # ret = ret.append( pd.Series([ pd.NA , pd.NA ]))
        ret = pd.concat([ ret , pd.Series([ pd.NA , pd.NA ])] , ignore_index = True )
    try :
        res = geoIP.city( ip_address )
        # ret = ret.append( pd.Series([ res[ "country_name" ] , res[ "city" ]]))
        ret = pd.concat([ ret , pd.Series([ res[ "country_name" ] , res[ "city" ]])] , ignore_index = True )
    except :
        # ret = ret.append( pd.Series([ pd.NA , pd.NA ]))
        ret = pd.concat([ ret , pd.Series([ pd.NA , pd.NA ])] , ignore_index = True )
    return ret
df.insert( 2 , "IP latitude" , value = pd.NA )
df.insert( 3 , "IP longitude" , value = pd.NA )
df.insert( 4 , "IP country" , value = pd.NA )
df.insert( 5 , "IP city" , value = pd.NA )
df[[ "IP latitude" , "IP longitude" , "IP country" , "IP city" ]] = df[ "Source IP Address" ].apply( lambda x : ip_to_coords( x ))

#%%

import plotly.graph_objects as go

fig = go.Figure( data = go.Scattergeo(
        lon = df[ "IP longitude" ] ,
        lat = df[ "IP latitude" ] ,
        mode = "markers" ,
        # marker_color = df['cnt'],
        ))

fig.update_layout(
        title = "Source IP Address locations" ,
        geo_scope = "world" ,
    )
fig.show()

#%% protocol

col_name = "Protocol"
print( df[ col_name ].value_counts())
piechart_col( col_name )

# packet length

fig = px.histogram( df , "Packet Length" )
fig.show()

# packet type

col_name = "Packet Type"
print( df[ col_name ].value_counts())
piechart_col( col_name )

# traffic type

col_name = "Traffic Type"
print( df[ col_name ].value_counts())
piechart_col( col_name )

# Malware Indicators

print( df[ "Malware Indicators" ].value_counts())

# Anomaly Scores

fig = px.histogram( df , "Anomaly Scores" )
fig.show()

# Alert Trigger

col_name = "Alert Trigger"
print( df[ col_name ].value_counts())
df[ col_name ] = df[ col_name ].fillna( 0 )
df.loc[ df[ col_name ] == "Alert Triggered" , col_name ] = 1
piechart_col( col_name , names = [ "Alert triggered" , "Alert not triggered" ] )

# Attack Type

col_name = "Attack Type"
print( df[ col_name ].value_counts())
piechart_col( col_name )

# Attack Signature

col_name = "Attack Signature"
print( df[ "Attack Signature" ].value_counts())
"""
    Pattern A = 1
    Pattern B = 0
"""
bully = df[ col_name ] == "Known Pattern A"
df.loc[ bully , col_name ] = 1
df.loc[ ~ bully , col_name ] = 0
piechart_col( col_name , [ "Pattern A" , "Pattern B" ])

# Action taken

col_name = "Action Taken"
print( df[ col_name ].value_counts())
piechart_col( col_name )

# Severity Level

col_name = "Severity Level"
print( df[ col_name ].value_counts())
"""
    Low = - 1
    Medium = 0
    High = + 1
"""
df.loc[ df[ col_name ] == "Low" , col_name ] = - 1
df.loc[ df[ col_name ] == "Medium" , col_name ] = 0
df.loc[ df[ col_name ] == "High" , col_name ] = + 1
piechart_col( col_name , [ "Low" , "Medium" , "High" ])






