#!/usr/bin/env python3
import requests, logging, os, re, plugins.common.General as General, json, flickr_api

Plugin_Name = "Flickr"
The_File_Extension = ".html"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/configuration/config.json')
    logging.info(General.Date() + " Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)

            for Flickr_Details in Configuration_Data[Plugin_Name.lower()]:

                if Flickr_Details['api_key'] and Flickr_Details['api_secret']:
                    return [Flickr_Details['api_key'], Flickr_Details['api_secret']]

                else:
                    return None

    except:
        logging.warning(General.Date() + " Failed to load location details.")

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

    try:
        Flickr_Details = Load_Configuration()
        flickr_api.set_keys(api_key=Flickr_Details[0], api_secret=Flickr_Details[1])

    except:
        logging.info(General.Date() + " Failed to establish API identity.")

    for Query in Query_List:
        Email_Regex = re.search(r"[^@]+@[^\.]+\..+", Query)

        if Email_Regex:

            try:
                User = flickr_api.Person.findByEmail(Query)
                Photos = User.getPhotos()
                General.Main_File_Create(Directory, Plugin_Name, Photos, Query, ".txt")

                for Photo in Photos:
                    Photo_URL = "https://www.flickr.com/photos/" + Query + "/" + Photo["id"]
                    Current_Step = 0

                    if Photo_URL not in Cached_Data and Photo_URL not in Data_to_Cache and Current_Step < int(Limit):
                        headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
                        Photo_Response = requests.get(Photo_URL, headers=headers).text
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Photo_Response, Photo, The_File_Extension)

                        if Output_file:
                            General.Connections(Output_file, Query, Plugin_Name, Photo_URL, "flickr.com", "Data Leakage", Task_ID, General.Get_Title(Photo_URL), Plugin_Name.lower())

                        Data_to_Cache.append(Photo_URL)
                        Current_Step += 1

            except:
                logging.info(General.Date() + " Failed to make API call.")

        else:

            try:
                print(Query)
                User = flickr_api.Person.findByUserName(Query)
                Photos = User.getPhotos()
                General.Main_File_Create(Directory, Plugin_Name, Photos, Query, ".txt")

                for Photo in Photos:
                    Photo_URL = "https://www.flickr.com/photos/" + Query + "/" + Photo["id"]
                    Current_Step = 0

                    if Photo_URL not in Cached_Data and Photo_URL not in Data_to_Cache and Current_Step < int(Limit):
                        headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
                        Photo_Response = requests.get(Photo_URL, headers=headers).text
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Photo_Response, str(Photo['id']), The_File_Extension)

                        if Output_file:
                            General.Connections(Output_file, Query, Plugin_Name, Photo_URL, "flickr.com", "Data Leakage", Task_ID, General.Get_Title(Photo_URL), Plugin_Name.lower())

                        Data_to_Cache.append(Photo_URL)
                        Current_Step += 1

            except:
                logging.info(General.Date() + " Failed to make API call.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")