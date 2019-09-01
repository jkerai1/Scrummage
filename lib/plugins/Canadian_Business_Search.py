#!/usr/bin/env python3

import os, logging, requests, json, urllib.parse, plugins.common.General as General

Plugin_Name = "Canadian-Business"
Concat_Plugin_Name = "canadianbusiness"
The_File_Extension = ".html"

def Search(Query_List, Task_ID, Type, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

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

        try:

            if Type == "CBN":
                Main_API_URL = 'https://searchapi.mrasservice.com/Search/api/v1/search?fq=keyword:%7B' + Query + '%7D+Status_State:Active&lang=en&queryaction=fieldquery&sortfield=Company_Name&sortorder=asc'
                Response = requests.get(Main_API_URL).text
                JSON_Response = json.loads(Response)

                try:

                    if JSON_Response['count'] != 0:
                        Query = str(int(Query))
                        Main_URL = 'https://beta.canadasbusinessregistries.ca/search/results?search=%7B' + Query + '%7D&status=Active'
                        Response = requests.get(Main_URL).text

                        if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, General.Get_Title(Main_URL), The_File_Extension)

                            if Output_file:
                                General.Connections(Output_file, Query, Plugin_Name, Main_URL, "canadasbusinessregistries.ca", "Data Leakage", Task_ID, General.Get_Title(Main_URL), Plugin_Name)
                                Data_to_Cache.append(Main_URL)

                except:
                    logging.warning(General.Date() + " Invalid query provided for ABN Search.")

            elif Type == "CCN":
                Main_URL = 'https://searchapi.mrasservice.com/Search/api/v1/search?fq=keyword:%7B' + urllib.parse.quote(Query) + '%7D+Status_State:Active&lang=en&queryaction=fieldquery&sortfield=Company_Name&sortorder=asc'
                Response = requests.get(Main_URL).text
                JSON_Response = json.loads(Response)
                Indented_JSON_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)

                if kwargs.get('Limit'):

                    if int(kwargs["Limit"]) > 0:
                        Limit = kwargs["Limit"]

                else:
                    Limit = 10

                try:
                    General.Main_File_Create(Directory, Plugin_Name, Indented_JSON_Response, Query, ".json")
                    Current_Step = 0

                    for JSON_Item in JSON_Response['docs']:

                        if JSON_Item.get('BN'):
                            CCN = JSON_Item['Company_Name']
                            CBN = JSON_Item['BN']

                            Full_ABN_URL = 'https://beta.canadasbusinessregistries.ca/search/results?search=%7B' + CBN + '%7D&status=Active'

                            if Full_ABN_URL not in Cached_Data and Full_ABN_URL not in Data_to_Cache and Current_Step < int(Limit):
                                Current_Response = requests.get(Full_ABN_URL).text
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), CCN.replace(' ', '-'), The_File_Extension)

                                if Output_file:
                                    General.Connections(Output_file, Query, Plugin_Name, Full_ABN_URL, "canadasbusinessregistries.ca", "Data Leakage", Task_ID, General.Get_Title(Full_ABN_URL), Plugin_Name)
                                    Data_to_Cache.append(Full_ABN_URL)
                                    Current_Step += 1

                except:
                    logging.warning(General.Date() + " Invalid query provided for CCN Search.")

            else:
                logging.warning(General.Date() + " Invalid request type.")

        except:
            logging.warning(General.Date() + " Failed to make request.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")