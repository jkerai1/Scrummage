#!/usr/bin/env python3

import play_scraper, requests, os, logging, re, json, plugins.common.General as General

Plugin_Name = "Play-Store"
Concat_Plugin_Name = "playstore"
The_File_Extensions = {"Main": ".json", "Query": ".html"}

def Search(Query_List, Task_ID, **kwargs):

    # try:
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
    Limit = General.Get_Limit(kwargs)

    for Query in Query_List:

        # try:
        Play_Store_Response = play_scraper.developer(Query, results=Limit)
        Play_Store_Response_JSON = json.dumps(Play_Store_Response, indent=4, sort_keys=True)
        Main_File = General.Main_File_Create(Plugin_Name, Play_Store_Response_JSON, Query, The_File_Extensions["Main"])
        Output_Connections = General.Connections(Query, Plugin_Name, "play.google.com", "Data Leakage", Task_ID, Concat_Plugin_Name)

        for Result_Details in Play_Store_Response:
            Result_URL = Result_Details['url']

            if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache:
                Win_Store_Regex = re.search(r"https\:\/\/play\.google\.com\/store\/apps\/details\?id\=([\w\d\_\-\.]+)", Result_URL)

                if Win_Store_Regex:
                    headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
                    Play_Store_Response = requests.get(Result_URL, headers=headers).text
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Play_Store_Response, Win_Store_Regex.group(1), The_File_Extensions["Query"])

                    if Output_file:
                        Output_Connections.Output([Main_File, Output_file], Result_URL, General.Get_Title(Result_URL), Concat_Plugin_Name)
                        Data_to_Cache.append(Result_URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        # except:
        #     logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to get results, this may be due to the query provided.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")

    # except Exception as e:
    #     logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")