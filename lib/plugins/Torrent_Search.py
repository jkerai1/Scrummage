#!/usr/bin/env python3
import plugins.common.General as General, requests, json, os, logging

The_File_Extension = ".html"
Plugin_Name = "Torrent"

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if kwargs.get('Limit'):

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

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

    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0'}
        Response = requests.get('https://tpbc.herokuapp.com/search/' + Query.replace(" ", "+") + '/?sort=seeds_desc', headers=headers).text
        Response = json.loads(Response)
        JSON_Response = json.dumps(Response, indent=4, sort_keys=True)
        Output_file = General.Main_File_Create(Directory, Plugin_Name, JSON_Response, Query, ".json")

        if Output_file:
            Current_Step = 0

            for Search_Result in Response:
                Result_Title = Search_Result["title"]
                Result_URL = Search_Result["magnet"]
                # Search_Result_Response = requests.get(Result_URL).text

                if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(Limit):
                    # Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Search_Result_Response, Result_Title, The_File_Extension)

                    if Output_file:
                        General.Connections(Output_file, Query, Plugin_Name, Result_URL, "thepiratebay.org", "Data Leakage", Task_ID, Result_Title, Plugin_Name.lower())

                    Data_to_Cache.append(Result_URL)
                    Current_Step += 1

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")