#!/usr/bin/env python3
import requests, os, logging, json, re, plugins.common.General as General

Plugin_Name = "SSlMate"
The_File_Extension = ".json"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')

    with open(Configuration_File) as JSON_File:  
        Configuration_Data = json.load(JSON_File)

        for SSLMate_Details in Configuration_Data[Plugin_Name.lower()]:
            SSLMate_API = SSLMate_Details['api_key']
            SSLMate_Subdomains = SSLMate_Details['search_subdomain']

            if SSLMate_API:
                return [SSLMate_API, SSLMate_Subdomains]

            else:
                return None

def Search(Query_List, Task_ID):
    Data_to_Cache = []
    Cached_Data = []
    Configuration_Details = Load_Configuration()
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

        if Configuration_Details[1].lower() == "true":
            Request = 'https://api.certspotter.com/v1/issuances?domain=' + Query + '&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert'
            Response = requests.get(Request, auth=(Configuration_Details[0], '')).text

        else:
            Request = 'https://api.certspotter.com/v1/issuances?domain=' + Query + '&expand=dns_names&expand=issuer&expand=cert'
            Response = requests.get(Request, auth=(Configuration_Details[0], '')).text

        JSON_Response = json.loads(Response)

        if 'exists' not in JSON_Response:

            if JSON_Response:

                if Request not in Cached_Data and Request not in Data_to_Cache:

                    try:
                        SSLMate_Regex = re.search("([\w\d]+)\.[\w]{2,3}(\.[\w]{2,3})?(\.[\w]{2,3})?", Query)

                        if SSLMate_Regex:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, json.dumps(JSON_Response, indent=4, sort_keys=True), SSLMate_Regex.group(1), The_File_Extension)

                            if Output_file:
                                General.Connections(Output_file, Query, Plugin_Name, Request, "sslmate.com", "Domain Spoof", Task_ID, General.Get_Title(Request), Plugin_Name.lower())

                        else:
                            logging.warning(General.Date() + " - " + __name__ + " - Failed to match regular expression.")

                    except:
                        logging.warning(General.Date() + " - " + __name__ + " - Failed to create file.")

                    Data_to_Cache.append(Request)

            else:
                logging.warning(General.Date() + " - " + __name__ + " - No response.")

        else:
            logging.warning(General.Date() + " - " + __name__ + " - Query does not exist.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")