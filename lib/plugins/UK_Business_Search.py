#!/usr/bin/env python3

import os, json, logging, requests, base64, plugins.common.General as General

Plugin_Name = "UK-Business"
Concat_Plugin_Name = "ukbusiness"
The_File_Extension = ".html"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(General.Date() + " Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)

            for API_Details in Configuration_Data[Concat_Plugin_Name]:
                API_Key = API_Details['api_key']

                if API_Key:
                    API_Key = base64.b64encode(API_Key.encode('ascii'))
                    return API_Key

                else:
                    return None

    except:
        logging.warning(General.Date() + " Failed to load location details.")


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

            if Type == "UKBN":
                Authorization_Key = Load_Configuration()

                if Authorization_Key:
                    Authorization_Key = "Basic " + Authorization_Key.decode('ascii')
                    headers = {"Authorization": Authorization_Key}
                    Main_URL = 'https://api.companieshouse.gov.uk/company/' + Query
                    Response = requests.get(Main_URL, headers=headers).text
                    JSON_Response = json.loads(Response)
                    Indented_JSON_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)

                    try:
                        Dud_Query = str(int(Query))

                        if Response and '{"errors":[{"error":"company-profile-not-found","type":"ch:service"}]}' not in Response:

                            if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                Result_URL = 'https://beta.companieshouse.gov.uk/company/' + str(JSON_Response["company_number"])
                                Result_Response = requests.get(Result_URL).text
                                Main_Output_File = General.Main_File_Create(Directory, Plugin_Name, Indented_JSON_Response, Query, '.json')
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Result_Response, str(JSON_Response["company_name"]), The_File_Extension)

                                if Main_Output_File and Output_file:
                                    General.Connections(Output_file, Query, Plugin_Name, Result_URL, "companieshouse.gov.uk", "Data Leakage", Task_ID, str(JSON_Response["company_name"]), Plugin_Name)
                                    Data_to_Cache.append(Main_URL)

                    except:
                        logging.warning(General.Date() + " Invalid query provided for UKBN Search.")

                else:
                    logging.info(General.Date() + " Failed to retrieve API key.")

            elif Type == "UKCN":
                Authorization_Key = Load_Configuration()

                if Authorization_Key:
                    Authorization_Key = "Basic " + Authorization_Key.decode('ascii')

                    if kwargs.get('Limit'):

                        if int(kwargs["Limit"]) > 0:
                            Limit = kwargs["Limit"]

                    else:
                        Limit = 10

                    try:
                        Main_URL = 'https://api.companieshouse.gov.uk/search/companies?q=' + Query + '&items_per_page=' + Limit
                        proxies = {
                            "http": "http://127.0.0.1:8080",
                            "https": "https://127.0.0.1:8080",
                        }
                        headers = {"Authorization": "Basic SGI5M0V4STRkMDZ2d0NHSzBZTkI5QUxnQ3N3UDNhNEFNMDRHeWtVdzo="}
                        Response = requests.get(Main_URL, headers=headers, proxies=proxies, verify=False).text
                        JSON_Response = json.loads(Response)
                        Indented_JSON_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)

                        try:

                            if JSON_Response['total_results'] > 0:
                                General.Main_File_Create(Directory, Plugin_Name, Indented_JSON_Response, Query, '.json')

                                for Item in JSON_Response['items']:
                                    UKBN_URL = Item['links']['self']
                                    Full_UKBN_URL = 'https://beta.companieshouse.gov.uk' + str(UKBN_URL)

                                    if Full_UKBN_URL not in Cached_Data and Full_UKBN_URL not in Data_to_Cache:
                                        UKCN = Item['title']
                                        Current_Response = requests.get(Full_UKBN_URL).text
                                        print(Full_UKBN_URL)
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), UKCN, The_File_Extension)

                                        if Output_file:
                                            General.Connections(Output_file, Query, Plugin_Name, Full_UKBN_URL, "companieshouse.gov.uk", "Data Leakage", Task_ID, UKCN, Plugin_Name)
                                            Data_to_Cache.append(Full_UKBN_URL)

                        except:
                            logging.warning(General.Date() + " Error during UKCN Search, perhaps the rate limit has been exceeded.")

                    except:
                        logging.warning(General.Date() + " Invalid query provided for UKCN Search.")

                else:
                    logging.warning(General.Date() + " Failed to retrieve API key.")

            else:
                logging.warning(General.Date() + " Invalid request type.")

        except:
            logging.warning(General.Date() + " Failed to make request.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")