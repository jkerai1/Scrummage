#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests, re, os, json, logging, plugins.common.General as General

Plugin_Name = "Doing-Business"
Concat_Plugin_Name = "doingbusiness"
The_File_Extensions = {"Main": ".json", "Query": ".html"}

def Search(Query_List, Task_ID, **kwargs):

    try:
        Data_to_Cache = []
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
        Query_List = General.Convert_to_List(Query_List)

        for Query in Query_List:
            headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "application/json", "Referer": f"https://www.doingbusiness.org/en/data/exploreeconomies/{Query}"}
            Main_URL = f"https://wbgindicatorsqa.azure-api.net/DoingBusiness/api/GetEconomyByURL/{Query}"
            Doing_Business_Response = requests.get(Main_URL, headers=headers).text
            JSON_Response = json.loads(Doing_Business_Response)
            JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)

            if 'message' not in JSON_Response:
                Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"}
                Item_URL = f"https://www.doingbusiness.org/en/data/exploreeconomies/{Query}"
                Title = f"Doing Business | {Query}"
                Current_Doing_Business_Response = requests.get(Item_URL, headers=headers).text

                if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache:
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Current_Doing_Business_Response, Query, The_File_Extensions["Query"])

                    if Output_file:
                        Output_Connections = General.Connections(Query, Plugin_Name, "doingbusiness.org", "Economic Details", Task_ID, Concat_Plugin_Name)
                        Output_Connections.Output([Main_File, Output_file], Item_URL, Title, Concat_Plugin_Name)
                        Data_to_Cache.append(Item_URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        if Cached_Data:
            General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

        else:
            General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")