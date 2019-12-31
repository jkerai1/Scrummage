#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests, os, logging, plugins.common.General as General, json, feedparser

Plugin_Name = "Craigslist"
The_File_Extension = ".html"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(General.Date() + "[+] Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)

            for Craigslist_Details in Configuration_Data[Plugin_Name.lower()]:

                if Craigslist_Details['city']:
                    return Craigslist_Details['city']

                else:
                    return None

    except:
        logging.warning(General.Date() + " - " + __name__.strip('plugins.') + " - Failed to load location details.")

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if kwargs.get('Limit'):

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

        else:
            Limit = 10

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Plugin_Name.lower())
    handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    Craigslist_Location = Load_Configuration()
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        Main_URL = "https://" + Craigslist_Location.lower() + ".craigslist.org/search/sss?format=rss&query=" + Query
        Craigslist_Response = feedparser.parse(Main_URL)
        Craigslist_Items = Craigslist_Response["items"]
        Current_Step = 0
        Output_Connections = General.Connections(Query, Plugin_Name, Local_Domain, "Data Leakage", Task_ID, Plugin_Name.lower())

        for Item in Craigslist_Items:
            Item_URL = Item["link"]

            if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                Craigslist_Response = requests.get(Item_URL).text
                Local_URL = "https://" + Craigslist_Location.lower() + ".craigslist.org/"
                Local_Domain = Craigslist_Location.lower() + ".craigslist.org/"
                Filename = Item_URL.replace(Local_URL, "")
                Filename = Filename.replace(".html/", "")
                Filename = Filename.replace(".html", "")
                Filename = Filename.replace("/", "-")
                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Craigslist_Response, Filename, The_File_Extension)

                if Output_file:
                    Output_Connections.Output(Output_file, Item_URL, General.Get_Title(Item_URL))

                Data_to_Cache.append(Item_URL)
                Current_Step += 1

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")