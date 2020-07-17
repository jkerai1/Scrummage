#!/usr/bin/env python3
# Version 1 Outdated.
import plugins.common.General as General, requests, json, os, logging

The_File_Extension = ".json"
Plugin_Name = "Torrent"

def Search(Query_List, Task_ID, **kwargs):

    try:
        Data_to_Cache = []
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
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0'}
            Response = requests.get('https://tpbc.herokuapp.com/search/' + Query.replace(" ", "+") + '/?sort=seeds_desc', headers=headers).text
            Response = json.loads(Response)
            JSON_Response = json.dumps(Response, indent=4, sort_keys=True)
            Output_file = General.Main_File_Create(Directory, Plugin_Name, JSON_Response, Query, The_File_Extension)

            if Output_file:
                Current_Step = 0
                Output_Connections = General.Connections(Query, Plugin_Name, "thepiratebay.org", "Torrent", Task_ID, Plugin_Name.lower())

                for Search_Result in Response:
                    Result_Title = Search_Result["title"]
                    Result_URL = Search_Result["magnet"]

                    if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(Limit):
                        #Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, JSON_Response, Result_Title, The_File_Extension)

                        if Output_file:
                            Output_Connections.Output([Output_file], Result_URL, General.Get_Title(Result_URL), Plugin_Name.lower())
                            Data_to_Cache.append(Result_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        Current_Step += 1

        if Cached_Data:
            General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

        else:
            General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")