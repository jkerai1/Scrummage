#!/usr/bin/env python3
import requests, logging, json, re, os, plugins.common.General as General

Plugin_Name = "iTunes-Store"
Concat_Plugin_Name = "itunesstore"
The_File_Extension = ".html"

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if kwargs.get('Limit'):

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Concat_Plugin_Name)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Plugin_Name.lower())
    handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    Location = General.Load_Location_Configuration()
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:

        try:
            Response = requests.get("http://itunes.apple.com/search?term=" + Query + "&country=" + Location + "&entity=software&limit=" + str(Limit)).text

        except:
            logging.warning(General.Date() + " Failed to make request, are you connected to the internet?")

        JSON_Response = json.loads(Response)
        General.Main_File_Create(Directory, "iTunes", json.dumps(Response, indent=4, sort_keys=True), Query, ".json")

        if 'resultCount' in JSON_Response:

            if not JSON_Response['resultCount'] == 0:

                if JSON_Response['resultCount'] > 0:

                    for JSON_Object in JSON_Response['results']:
                        JSON_Object_Response = requests.get(JSON_Object['artistViewUrl']).text

                        if JSON_Object['artistViewUrl'] not in Cached_Data and JSON_Object['artistViewUrl'] not in Data_to_Cache:
                            iTunes_Regex = re.search("https\:\/\/itunes\.apple\.com\/" + Location + "\/developer\/[\w\d\-]+\/(id[\d]{9,10})\?mt\=\d\&uo\=\d", JSON_Object['artistViewUrl'])

                            if iTunes_Regex:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, JSON_Object_Response, iTunes_Regex.group(1), The_File_Extension)

                                if Output_file:
                                    General.Connections(Output_file, Query, Plugin_Name, JSON_Object['artistViewUrl'], "itunes.apple.com", "Data Leakage", Task_ID, General.Get_Title(JSON_Object['artistViewUrl']), Concat_Plugin_Name)

                            Data_to_Cache.append(JSON_Object['artistViewUrl'])

                else:
                    logging.warning(General.Date() + " Invalid value provided, value less than 0.")

            else:
                logging.warning(General.Date() + " Invalid value provided, value equal to 0.")

        else:
            logging.warning(General.Date() + " Invalid value.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")