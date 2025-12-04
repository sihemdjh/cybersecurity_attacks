import numpy as np
import pandas as pd
import geoip2.database
import plotly.io
plotly.io.renderers.default = "browser"
import plotly.express as px
import plotly.graph_objects as go
import requests
import random
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
df = df.drop( "User Information" , axis = 1 )
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

# IP address 

def ip_to_coords( ip_address ) :
    ret = pd.Series( dtype = object )
    try :
        res = geoIP.geos( ip_address ).wkt
        lon , lat = res.replace( "(" , "" ).replace( ")" , "" ).split()[ 1 : ]
        ret = pd.concat([ ret , pd.Series([ lat , lon ])] , ignore_index = True )
    except :
        ret = pd.concat([ ret , pd.Series([ pd.NA , pd.NA ])] , ignore_index = True )
    try :
        res = geoIP.city( ip_address )
        ret = pd.concat([ ret , pd.Series([ res[ "country_name" ] , res[ "city" ]])] , ignore_index = True )
    except :
        ret = pd.concat([ ret , pd.Series([ pd.NA , pd.NA ])] , ignore_index = True )
    return ret
df.insert( 2 , "IP latitude" , value = pd.NA )
df.insert( 3 , "IP longitude" , value = pd.NA )
df.insert( 4 , "IP country" , value = pd.NA )
df.insert( 5 , "IP city" , value = pd.NA )
df[[ "IP latitude" , "IP longitude" , "IP country" , "IP city" ]] = df[ "Source IP Address" ].apply( lambda x : ip_to_coords( x ))

#%% graph 3

fig = go.Figure( go.Scattergeo(
    lat = df[ "IP latitude" ] ,
    lon = df[ "IP longitude" ] ,
    color = df[ "Anomaly Scores" ]
    ))
fig.update_geos( projection_type = "orthographic" )
fig.update_layout( 
    title = "Source IP Address locations" ,
    geo_scope = "world" ,
    height = 750 ,
    margin = { "r" : 0 ,"t" : 0,"l" : 0 ,"b" : 0 })
fig.show()

#%%

df_graph2 = (
    df[ "IP country" ]
    .value_counts()
    .reset_index()
)

df_graph2.columns = [ "country" , "count" ]

# Get full list of Plotly countries
all_countries = px.data.gapminder()[ "country" ].unique()

# Reindex to include all countries, fill missing ones with 0
df_graph2 = df_graph2.set_index( "country" ).reindex( all_countries , fill_value = 0 ).reset_index()
df_graph2.columns = [ "country" , "count" ]

# Create choropleth
fig = px.choropleth(
    df_graph2 ,
    locations = "country" ,
    locationmode = "country names" ,
    color = "count" ,
    color_continuous_scale = "inferno" ,
    projection = "orthographic" ,
    title = "Global Population by Country" ,
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

# Attack Type !!!! TARGET VARIABLE !!!!

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

# Device Information

col_name = "Device Information"
print( df[ col_name ].value_counts())
# --> to be split into several columns to be atomized [ browser/browser_version (device) ]
df[ "broswer" ] = df[ col_name ].split()[ 0 ].split( "" )

def atomization_DeviceInformation( info ) : # need to take process splitting for each case of device
    print( info )
    i1 , i2 = info.split(" (")
    i2 , i3 = i2.split( ")")
    i10 , i11 = i1.split( "/" )
    i2 = i2.split( "; " )
    i3 = i3.split()
    return pd.Series([ i10 , i11 , i2 , i3 ])
info = df.loc[ random.randint( 0 , df.shape[ 0 ]) , "Device Information" ]
print( atomization_DeviceInformation( info ))



