#!/usr/bin/env python3
import requests, logging, os, re, plugins.common.General as General, json
from ebaysdk.finding import Connection

Plugin_Name = "Ebay"
The_File_Extensions = {"Main": ".json", "Query": ".html"}

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            Ebay_Details = Configuration_Data[Plugin_Name.lower()]

            if Ebay_Details['access_key']:
                return Ebay_Details['access_key']

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load location details.")

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
        Ebay_API_Key = Load_Configuration()
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            try:
                API_Request = Connection(appid=Ebay_API_Key, config_file=None)
                API_Response = API_Request.execute('findItemsAdvanced', {'keywords': Query})
                JSON_Output_Response = json.dumps(API_Response.dict(), indent=4, sort_keys=True)
                JSON_Response = json.dumps(API_Response.dict())
                JSON_Response = json.loads(JSON_Response)
                Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])

                if JSON_Response["ack"] == "Success":
                    Output_Connections = General.Connections(Query, Plugin_Name, "ebay.com", "Data Leakage", Task_ID, Plugin_Name.lower())
                    Current_Step = 0

                    for JSON_Line in JSON_Response['searchResult']['item']:
                        Ebay_Item_URL = JSON_Line['viewItemURL']

                        if Ebay_Item_URL not in Cached_Data and Ebay_Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                            Ebay_Item_Regex = re.search(r"http\:\/\/www\.ebay\.com\/itm\/([\w\d\-]+)\-\/\d+", Ebay_Item_URL)
                            headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
                            Ebay_Item_Response = requests.get(Ebay_Item_URL, headers=headers).text
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Ebay_Item_Response, Ebay_Item_Regex.group(1), The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Ebay_Item_URL, General.Get_Title(Ebay_Item_URL), Plugin_Name.lower())
                                Data_to_Cache.append(Ebay_Item_URL)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No results found.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make API call.")

        if Cached_Data:
            General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

        else:
            General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")