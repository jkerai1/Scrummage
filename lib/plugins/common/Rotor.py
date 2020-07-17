# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import itertools, datetime, logging, string
Altered_URLs = []

def Date():
    return str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def List_Formatter(English_Lower, English_Upper, Numbers, Special_Characters, Cyrillic, Greek, Phoenetic_Alternatives, Comprehensive):
    Lists = {}

    for Alphabet_Letter in list(string.ascii_lowercase):
        Lists[Alphabet_Letter] = []
    
        if English_Lower:
            Lists[Alphabet_Letter].append(Alphabet_Letter)

        if English_Upper:
            Lists[Alphabet_Letter].append(Alphabet_Letter.upper())

    if Numbers:
        Lists["a"].append("4")
        Lists["b"].append("8")
        Lists["e"].append(["3", u"з", u"З", u"Ӡ"])
        Lists["i"].append("1")
        Lists["l"].append("1")
        Lists["o"].append("0")
        Lists["s"].append("5")
        Lists["t"].append("7")
        Lists["z"].append("2")

    if Special_Characters:
        Lists["a"].append("@")
        Lists["s"].append("$")
        Lists["l"].extend(["|", "[", "]"])
        Lists["t"].append("+")

    if Cyrillic and Comprehensive:
        Lists["a"].extend([u"а", u"д"])
        Lists["b"].append(u"в")
        Lists["c"].append(u"с")
        Lists["e"].extend([u"е", u"є"])
        Lists["h"].extend([u"һ", u"Һ", u"ʜ"])
        Lists["i"].append(u"і")
        Lists["k"].append(u"к")
        Lists["m"].append(u"м")
        Lists["n"].extend([u"п", u"и", u"й", u"л"])
        Lists["o"].append(u"о")
        Lists["p"].append(u"р")
        Lists["r"].extend([u"г", u"я"])
        Lists["s"].append(u"ѕ")
        Lists["t"].append(u"т")
        Lists["w"].extend([u"ш", u"щ"])
        Lists["x"].extend([u"х", u"ж"])
        Lists["y"].extend([u"у", u"ү"])

    elif Cyrillic and not Comprehensive:
        Lists["a"].append(u"а")
        Lists["c"].append(u"с")
        Lists["e"].append(u"е")
        Lists["h"].extend([u"һ", u"Һ"])
        Lists["i"].append(u"і")
        Lists["k"].append(u"к")
        Lists["m"].append(u"м")
        Lists["n"].append(u"п")
        Lists["o"].append(u"о")
        Lists["p"].append(u"р")
        Lists["r"].append(u"г")
        Lists["s"].append(u"ѕ")
        Lists["t"].append(u"т")
        Lists["w"].append(u"ш")
        Lists["x"].append(u"х")
        Lists["y"].extend([u"у", u"ү"])

    if Greek and Comprehensive:
        Lists["i"].extend([u"ί", u"ι"])
        Lists["k"].append(u"κ")
        Lists["n"].extend([u"η", u"π"])
        Lists["o"].extend([u"ο", u"σ"])
        Lists["p"].append(u"ρ")
        Lists["t"].append(u"τ")
        Lists["u"].append(u"υ")
        Lists["v"].extend([u"ν", u"υ"])
        Lists["w"].append(u"ω")
        Lists["x"].append(u"χ")
        Lists["y"].append(u"γ")

    elif Greek and not Comprehensive:
        Lists["k"].append(u"κ")
        Lists["n"].append(u"η")
        Lists["o"].extend([u"ο", u"σ"])
        Lists["p"].append(u"ρ")
        Lists["u"].append(u"υ")
        Lists["v"].append(u"ν")
        Lists["w"].append(u"ω")
        Lists["y"].append(u"γ")

    if Phoenetic_Alternatives:
        Lists["a"].extend([u"à", u"á", u"â", u"ã", u"ä", u"å", u"ā", u"ă", u"ą"])
        Lists["c"].extend([u"ç", u"ć", u"ĉ", u"ċ", u"č"])
        Lists["d"].extend([u"ð"])
        Lists["e"].extend([u"ē", u"ĕ", u"ė", u"ę", u"ě", u"è", u"é", u"ê", u"ë"])
        Lists["g"].extend([u"ġ", u"ğ"])
        Lists["i"].extend([u"ì", u"í", u"î", u"ï"])
        Lists["n"].extend([u"ñ", u"ń"])
        Lists["o"].extend([u"ø", u"ò", u"ó", u"ô", u"õ", u"ö", u"ō", u"ŏ"])
        Lists["s"].extend([u"š", u"ś", u"ş"])
        Lists["u"].extend([u"ù", u"ú", u"û", u"ü", u"ũ", u"ū", u"ŭ", u"ů"])
        Lists["y"].extend([u"ý", u"ÿ"])

    return Lists

def Search(Query, English_Lower, English_Upper, Numbers, Special_Characters, Cyrillic, Greek, Phoenetic_Alternatives, Comprehensive):
    global Altered_URLs
    Rotor_Word = []
    Altered_URLs = []
    URL_Allowed_Characters_List = ['$', '-', '_', '.', '+', '!', '*', '\'', '(', ')', ',']
    Lists = List_Formatter(English_Lower, English_Upper, Numbers, Special_Characters, Cyrillic, Greek, Phoenetic_Alternatives, Comprehensive)

    for Letter in Query:

        for List_Key, List_Value in Lists.items():

            if Letter == List_Key:
                Rotor_Word.append(List_Value)

        for Character in URL_Allowed_Characters_List:

            if Letter == Character:
                Rotor_Word.append(Character)

    Rotor_Combinations(Rotor_Word)
    return Altered_URLs

def Rotor_Word_Appender(List_to_Append):
    URL_Body = ("".join(List_to_Append))
    Altered_URLs.append(URL_Body)

def Rotor_Combinations(Rotor_Word):

    if (len(Rotor_Word) <= 15):

        for elements in list(itertools.product(*Rotor_Word)):
            Newer_List = list(elements)
            Rotor_Word_Appender(Newer_List)

    else:
        logging.warning(f"{Date()} [-] The word entered was either over 15 characters in length or had no characters, this function only permits words with character lengths between 1 and 15.")