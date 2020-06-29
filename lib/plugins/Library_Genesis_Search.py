#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests, re, os, logging, plugins.common.General as General

Plugin_Name = "Library-Genesis"
Concat_Plugin_Name = "libgen"
The_File_Extension = ".html"

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if kwargs.get('Limit'):

        if int(kwargs["Limit"]) > 0:
            Limit = int(kwargs["Limit"])

        else:
            Limit = 10

    else:
        Limit = 10

    Directory = General.Make_Directory(Concat_Plugin_Name)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Concat_Plugin_Name)
    handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        # Query can be Title or ISBN
        Main_URL = f"http://gen.lib.rus.ec/search.php?req={Query}&lg_topic=libgen&open=0&view=simple&res=100&phrase=1&column=def"
        Lib_Gen_Response = requests.get(Main_URL).text
        Main_File = General.Main_File_Create(Directory, Plugin_Name, Lib_Gen_Response, Query, The_File_Extension)
        Lib_Gen_Regex = re.findall("book\/index\.php\?md5=[A-Fa-f0-9]{32}", Lib_Gen_Response)

        if Lib_Gen_Regex:
            Current_Step = 0

            for Regex in Lib_Gen_Regex:
                Item_URL = "http://gen.lib.rus.ec/" + Regex
                Lib_Item_Response = requests.get(Item_URL).text

                if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Lib_Item_Response, Regex, The_File_Extension)

                    if Main_File and Output_file:
                        Output_Connections = General.Connections(Query, Plugin_Name, "gen.lib.rus.ec", "Data Leakage", Task_ID, Concat_Plugin_Name)
                        Output_Connections.Output([Main_File, Output_file], Item_URL, General.Get_Title(Item_URL), Concat_Plugin_Name)

                    Data_to_Cache.append(Item_URL)
                    Current_Step += 1

        else:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")