#!/usr/bin/env python3

import os, re, logging, requests, plugins.common.General as General

Plugin_Name = "American-Business"
Concat_Plugin_Name = "americanbusiness"
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

            if Type == "CIK":
                Main_URL = 'https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=' + Query + '&owner=exclude&count=40&hidefilings=0'
                Response = requests.get(Main_URL).text

                try:

                    if 'No matching CIK.' not in Response:
                        Query = str(int(Query))

                        if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, General.Get_Title(Main_URL), The_File_Extension)

                            if Output_file:
                                General.Connections(Output_file, Query, Plugin_Name, Main_URL, "sec.gov", "Data Leakage", Task_ID, General.Get_Title(Main_URL), Plugin_Name)
                                Data_to_Cache.append(Main_URL)

                except:
                    logging.warning(General.Date() + " - " + __name__ + " - Invalid query provided for CIK Search.")

            elif Type == "ACN":
                Main_URL = 'https://www.sec.gov/cgi-bin/browse-edgar?company=' + Query + '&owner=exclude&action=getcompany'
                Response = requests.get(Main_URL).text

                if kwargs.get('Limit'):

                    if int(kwargs["Limit"]) > 0:
                        Limit = kwargs["Limit"]

                else:
                    Limit = 10

                try:
                    ACN = re.search(r".*[a-zA-Z].*", Query)

                    if ACN:
                        General.Main_File_Create(Directory, Plugin_Name, Response, Query, The_File_Extension)
                        Current_Step = 0
                        CIKs_Regex = re.findall(r"(\d{10})\<\/a\>\<\/td\>\s+\<td\sscope\=\"row\"\>(.*\S.*)\<\/td\>", Response)

                        if CIKs_Regex:

                            for CIK_URL, ACN in CIKs_Regex:
                                Full_CIK_URL = 'https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=' + CIK_URL + '&owner=exclude&count=40&hidefilings=0'

                                if Full_CIK_URL not in Cached_Data and Full_CIK_URL not in Data_to_Cache and Current_Step < int(Limit):
                                    Current_Response = requests.get(Full_CIK_URL).text
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), ACN.replace(' ', '-'), The_File_Extension)

                                    if Output_file:
                                        General.Connections(Output_file, Query, Plugin_Name, Full_CIK_URL, "sec.gov", "Data Leakage", Task_ID, General.Get_Title(Full_CIK_URL), Plugin_Name)
                                        Data_to_Cache.append(Full_CIK_URL)
                                        Current_Step += 1

                        else:
                            logging.warning(General.Date() + " - " + __name__ + " - Response did not match regular expression.")

                    else:
                        logging.warning(General.Date() + " - " + __name__ + " - Query did not match regular expression.")

                except:
                    logging.warning(General.Date() + " - " + __name__ + " - Invalid query provided for ACN Search.")

            else:
                logging.warning(General.Date() + " - " + __name__ + " - Invalid request type.")

        except:
            logging.warning(General.Date() + " - " + __name__ + " - Failed to make request.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")