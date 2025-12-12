import pandas as pd
import geoip2.database
import plotly.io
import plotly.express as px
import plotly.graph_objects as go
import pyarrow as pq
import os
import numpy as np

plotly.io.renderers.default = "browser"

GEOIP_DB_PATH = "db/GeoLite2-City_20251202/GeoLite2-City.mmdb"

###
# maxmind_geoip2_db_url = "https://www.maxmind.com/en/accounts/1263991/geoip/downloads"
# geoip2_doc_url = "https://geoip2.readthedocs.io/en/latest/"
# geoip2_django_doc_url = "https://docs.djangoproject.com/en/5.2/ref/contrib/gis/geoip2/"
###


df = pd.read_csv("data/cybersecurity_attacks.csv" )


def ip_to_coords(ip_address : str ) -> pd.Series :
    """
    This function takes an IP address as input in the form of a text string

    Args:
        ip_address (str): a string representing an IP address

    Returns:
        pd.Series: series containing [latitude, longitude, country, city]
    """
    try :
        with geoip2.database.Reader( GEOIP_DB_PATH ) as reader :
            response = reader.city( ip_address )
            lat = response.location.latitude
            lon = response.location.longitude
            country = response.country.name
            city = response.city.name
            return pd.Series([ lat , lon , country , city ])
    except Exception as e:
        print(e)
        return pd.Series([ pd.NA , pd.NA , pd.NA , pd.NA ])

def ip_to_city( ip_address ) :
    try :
        with geoip2.database.Reader( GEOIP_DB_PATH ) as reader :
            response = reader.city( ip_address )
            city = response.city.name
        return city
    except :
        return pd.NA

def ip_to_country( ip_address ) :
    try :
        with geoip2.database.Reader( GEOIP_DB_PATH ) as reader :
            response = reader.city( ip_address )
            country = response.country.name
        return country
    except :
        return pd.NA

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
        
df = df.rename( columns = { "Timestamp" : "date" ,
        "Alerts/Warnings" : "Alert Trigger" ,
    })

def set_color(attack_type: str) -> str:
    
    if attack_type == "Malware":
        return "red"
    elif attack_type == "DDoS":
        return "green"
    elif attack_type == "Intrusion":
        return "blue"
    else:
        return "white"
    
def set_symbol(attack_type: str) -> str:
    
    if attack_type == "Malware":
        return "triangle-down"
    elif attack_type == "DDoS":
        return "diamond-dot"
    elif attack_type == "Intrusion":
        return "circle-dot"
    else:
        return None
    
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

if not os.path.exists("data/df_location_data.parquet"):
    
    column_names = ["Source IP lat","Source IP long", "Source IP country", "Source IP city",
                    "Destination IP lat","Destination IP long", "Destination IP country", "Destination IP city"]

    df_ips_data = pd.DataFrame(df["Source IP Address"])
    df_ips_data = df_ips_data.join(df["Destination IP Address"])
    df_ips_data = df_ips_data.join(df["Attack Type"])
    for i in range(len(column_names)):
        df_ips_data.insert( i , column_names[i] , value = np.nan )
        print(f"Inserting column {column_names[i]}")
    print(df_ips_data.head())
    df_ips_data[[ "Source IP lat","Source IP long", "Source IP country", "Source IP city"]] = df[ "Source IP Address" ].apply( lambda x : ip_to_coords( x ))
    df_ips_data[[ "Destination IP lat","Destination IP long", "Destination IP country", "Destination IP city" ]] = df[ "Destination IP Address" ].apply( lambda x : ip_to_coords( x ))
    print(df_ips_data.head())


    # df.insert( 2 , "IP latitude" , value = pd.NA )
    # df.insert( 3 , "IP longitude" , value = pd.NA )
    # df.insert( 4 , "IP country" , value = pd.NA )
    # df.insert( 5 , "IP city" , value = pd.NA )

    # df[ "IP country" ] = df[ "Source IP Address" ].apply( lambda x: ip_to_country( x ))
    # df[ "IP city" ] = df[ "Source IP Address" ].apply( lambda x : ip_to_city( x ))
    # df[[ "IP latitude" , "IP longitude" , "IP country" , "IP city" ]] = df[ "Source IP Address" ].apply( lambda x : ip_to_coords( x ))

    df_ips_data.to_parquet("data/df_location_data.parquet")
else:
    df_ips_data = pd.read_parquet("data/df_location_data.parquet")

fig_source = go.Figure()

for attack_type in df_ips_data["Attack Type"].unique():
    df_filtered = df_ips_data[df_ips_data["Attack Type"] == attack_type]
    fig_source.add_trace(go.Scattergeo(
        lon=df_filtered["Source IP long"],
        lat=df_filtered["Source IP lat"],
        mode="markers",
        name=attack_type,  # This creates the legend text
        marker=dict(
            color=set_color(attack_type),
            symbol=set_symbol(attack_type),
            size=8
            )
        )
    )

fig_source.update_layout(
    title="Source IP Address locations by attack type",
    geo_scope="world",
    legend=dict(
        title="Attack Type",
        yanchor="top",
        y=0.99,
        xanchor="left",
        x=0.01
    )
)

fig_source.show()

fig_dest = go.Figure()

for attack_type in df_ips_data["Attack Type"].unique():
    df_filtered = df_ips_data[df_ips_data["Attack Type"] == attack_type]
    fig_dest.add_trace(go.Scattergeo(
        lon=df_filtered["Destination IP long"],
        lat=df_filtered["Destination IP lat"],
        mode="markers",
        name=attack_type,  # This creates the legend text
        marker=dict(
            color=set_color(attack_type),
            symbol=set_symbol(attack_type),
            size=8
            )
        )
    )

fig_dest.update_layout(
        title = "Destination IP Address locations" ,
        geo_scope = "world" ,
    )
fig_dest.show()

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

###
# Pattern A = 1
# Pattern B = 0
###

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

###
# Low = - 1
# Medium = 0
# High = + 1
###

df.loc[ df[ col_name ] == "Low" , col_name ] = - 1
df.loc[ df[ col_name ] == "Medium" , col_name ] = 0
df.loc[ df[ col_name ] == "High" , col_name ] = + 1
piechart_col( col_name , [ "Low" , "Medium" , "High" ])






