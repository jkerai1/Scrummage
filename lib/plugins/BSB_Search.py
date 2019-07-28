#!/usr/bin/env python3
import plugins.common.General as General, requests, re, os, logging

The_File_Extension = ".html"
Plugin_Name = "BSB"

def Search(Query_List, Task_ID):
    Data_to_Cache = []
    Cached_Data = []
    Directory = General.Make_Directory(Plugin_Name.lower())

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Plugin_Name.lower())
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
        BSB_Search_URL = "https://www.bsbnumbers.com/" + Query + ".html"
        Response = requests.get(BSB_Search_URL).text
        Error_Regex = re.search(r"Correct\sthe\sfollowing\serrors", Response)

        if not Error_Regex:

            if BSB_Search_URL not in Cached_Data and BSB_Search_URL not in Data_to_Cache:
                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, Query, The_File_Extension)

                if Output_file:
                    General.Connections(Output_file, Query, Plugin_Name, BSB_Search_URL, "bsbnumbers.com", "Data Leakage", Task_ID, General.Get_Title(BSB_Search_URL), Plugin_Name.lower())

                Data_to_Cache.append(BSB_Search_URL)

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")