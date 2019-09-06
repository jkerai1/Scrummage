import pyhibp, json, os, logging, plugins.common.General as General
from pyhibp import pwnedpasswords as pw

# Version 2 of this plugin. Now requires an API key.

Plugin_Name = "Have-I-Been-Pwned"
Concat_Plugin_Name = "haveibeenpwned"
The_File_Extension = ".json"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(General.Date() + " Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:
            Configuration_Data = json.load(JSON_File)

            for HIBP_Details in Configuration_Data[Concat_Plugin_Name]:
                API_Key = HIBP_Details['api_key']

                if API_Key:
                    return API_Key

                else:
                    return None

    except:
        logging.warning(General.Date() + " Failed to load API details.")

def Search(Query_List, Task_ID, Type_of_Query, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    try:

        if kwargs.get('Limit'):

            if int(kwargs["Limit"]) > 0:
                Limit = kwargs["Limit"]

        else:
            Limit = 10

        Directory = General.Make_Directory(Concat_Plugin_Name)

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        Log_File = General.Logging(Directory, Concat_Plugin_Name)
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        try:
            pyhibp.set_api_key(key=Load_Configuration())

        except:
            logging.warning(General.Date() + " Failed to set API key, make sure it is set in the configuration file.")

        Query_List = General.Convert_to_List(Query_List)

        if Type_of_Query == "email":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            if not Cached_Data:
                Cached_Data = []

            for Query in Query_List:
                Query_Response = pyhibp.get_pastes(email_address=Query)
                logging.info(Query_Response)

                if Query_Response:
                    Domain = Query_Response[0]["Source"]
                    ID = Query_Response[0]["Id"]
                    Link = "https://www." + Domain + ".com/" + ID
                    JSON_Query_Response = json.dumps(Query_Response, indent=4, sort_keys=True)

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, JSON_Query_Response, "email", The_File_Extension)

                        if Output_file:
                            General.Connections(Output_file, Query, Local_Plugin_Name, Link, "haveibeenpwned.com", "Data Leakage", Task_ID, General.Get_Title(Link), Local_Plugin_Name.lower())

                        Data_to_Cache.append(Link)

            if Cached_Data:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

            else:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

        elif Type_of_Query == "breach":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            if not Cached_Data:
                Cached_Data = []

            for Query in Query_List:
                Query_Response = pyhibp.get_single_breach(breach_name=Query)

                if Query_Response:
                    Domain = Query_Response["Domain"]
                    Link = "https://www." + Domain + ".com/"
                    JSON_Query_Response = json.dumps(Query_Response, indent=4, sort_keys=True)

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, JSON_Query_Response, "breach", The_File_Extension)

                        if Output_file:
                            General.Connections(Output_file, Query, Local_Plugin_Name, Link, "haveibeenpwned.com", "Data Leakage", Task_ID, General.Get_Title(Link), Local_Plugin_Name.lower())

                        Data_to_Cache.append(Link)

            if Cached_Data:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

            else:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

        elif Type_of_Query == "password":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            if not Cached_Data:
                Cached_Data = []

            for Query in Query_List:
                Query_Response = pw.is_password_breached(password=Query)
                logging.info(Query_Response)

                if Query_Response:
                    Link = "https://haveibeenpwned.com/Passwords?" + Query

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Query_Response), "password", ".txt")

                        if Output_file:
                            General.Connections(Output_file, Query, Local_Plugin_Name, Link, "haveibeenpwned.com", "Data Leakage", Task_ID, General.Get_Title(Link), Local_Plugin_Name.lower())

                        Data_to_Cache.append(Link)

            if Cached_Data:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

            else:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

        elif Type_of_Query == "account":
            Local_Plugin_Name = Plugin_Name + "-" + Type_of_Query
            Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

            if not Cached_Data:
                Cached_Data = []

            for Query in Query_List:
                Query_Response = pyhibp.get_account_breaches(account=Query, truncate_response=True)

                if Query_Response:
                    Current_Step = 0

                    for Response in Query_Response:
                        Current_Response = pyhibp.get_single_breach(breach_name=Response['Name'])
                        JSON_Query_Response = json.dumps(Current_Response, indent=4, sort_keys=True)
                        Link = "https://" + Current_Response['Domain']

                        if Current_Response['Domain'] not in Cached_Data and Current_Response['Domain'] not in Data_to_Cache and Current_Step < int(Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, JSON_Query_Response, "account", The_File_Extension)

                            if Output_file:
                                General.Connections(Output_file, Query, Local_Plugin_Name, Link, Current_Response['Domain'], "Data Leakage", Task_ID, General.Get_Title(Link), Local_Plugin_Name.lower())

                            Data_to_Cache.append(Current_Response['Domain'])
                            Current_Step += 1

            if Cached_Data:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

            else:
                General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

        else:
            logging.warning(General.Date() + " Invalid type provided.")

    except:
        logging.warning(General.Date() + " Execution error.")