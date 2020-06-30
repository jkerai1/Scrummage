# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import itertools, datetime, logging
Altered_URLs = []

def Date():
    return str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def List_Formatter(English_Lower, English_Upper, Numbers, Special_Characters, Cyrillic, Greek, Phoenetic_Alternatives, Comprehensive):
    A_List = []
    B_List = []
    C_List = []
    D_List = []
    E_List = []
    F_List = []
    G_List = []
    H_List = []
    I_List = []
    J_List = []
    K_List = []
    L_List = []
    M_List = []
    N_List = []
    O_List = []
    P_List = []
    Q_List = []
    R_List = []
    S_List = []
    T_List = []
    U_List = []
    V_List = []
    W_List = []
    X_List = []
    Y_List = []
    Z_List = []

    if English_Lower:
        A_List.append("a")
        B_List.append("b")
        C_List.append("c")
        D_List.append("d")
        E_List.append("e")
        F_List.append("f")
        G_List.append("g")
        H_List.append("h")
        I_List.append("i")
        J_List.append("j")
        K_List.append("k")
        L_List.append("l")
        M_List.append("m")
        N_List.append("n")
        O_List.append("o")
        P_List.append("p")
        Q_List.append("q")
        R_List.append("r")
        S_List.append("s")
        T_List.append("t")
        U_List.append("u")
        V_List.append("v")
        W_List.append("w")
        X_List.append("x")
        Y_List.append("y")
        Z_List.append("z")

    if English_Upper:
        A_List.append("A")
        B_List.append("B")
        C_List.append("C")
        D_List.append("D")
        E_List.append("E")
        F_List.append("F")
        G_List.append("G")
        H_List.append("H")
        I_List.append("I")
        J_List.append("J")
        K_List.append("K")
        L_List.append("L")
        M_List.append("M")
        N_List.append("N")
        O_List.append("O")
        P_List.append("P")
        Q_List.append("Q")
        R_List.append("R")
        S_List.append("S")
        T_List.append("T")
        U_List.append("U")
        V_List.append("V")
        W_List.append("W")
        X_List.append("X")
        Y_List.append("Y")
        Z_List.append("Z")

    if Numbers:
        A_List.append("4")
        B_List.append("8")
        E_List.append(["3", u"з", u"З", u"Ӡ"])
        I_List.append("1")
        L_List.append("1")
        O_List.append("0")
        S_List.append("5")
        T_List.append("7")
        Z_List.append("2")

    if Special_Characters:
        A_List.append("@")
        S_List.append("$")
        L_List.extend(["|", "[", "]"])
        T_List.append("+")

    if Cyrillic and Comprehensive:
        A_List.extend([u"а", u"д"])
        B_List.append(u"в")
        C_List.append(u"с")
        E_List.extend([u"е", u"є"])
        H_List.extend([u"һ", u"Һ", u"ʜ"])
        I_List.append(u"і")
        K_List.append(u"к")
        M_List.append(u"м")
        N_List.extend([u"п", u"и", u"й", u"л"])
        O_List.append(u"о")
        P_List.append(u"р")
        R_List.extend([u"г", u"я"])
        S_List.append(u"ѕ")
        T_List.append(u"т")
        W_List.extend([u"ш", u"щ"])
        X_List.extend([u"х", u"ж"])
        Y_List.extend([u"у", u"ү"])

    elif Cyrillic and not Comprehensive:
        A_List.append(u"а")
        C_List.append(u"с")
        E_List.append(u"е")
        H_List.extend([u"һ", u"Һ"])
        I_List.append(u"і")
        K_List.append(u"к")
        M_List.append(u"м")
        N_List.append(u"п")
        O_List.append(u"о")
        P_List.append(u"р")
        R_List.append(u"г")
        S_List.append(u"ѕ")
        T_List.append(u"т")
        W_List.append(u"ш")
        X_List.append(u"х")
        Y_List.extend([u"у", u"ү"])

    if Greek and Comprehensive:
        I_List.extend([u"ί", u"ι"])
        K_List.append(u"κ")
        N_List.extend([u"η", u"π"])
        O_List.extend([u"ο", u"σ"])
        P_List.append(u"ρ")
        T_List.append(u"τ")
        U_List.append(u"υ")
        V_List.extend([u"ν", u"υ"])
        W_List.append(u"ω")
        X_List.append(u"χ")
        Y_List.append(u"γ")

    elif Greek and not Comprehensive:
        K_List.append(u"κ")
        N_List.append(u"η")
        O_List.extend([u"ο", u"σ"])
        P_List.append(u"ρ")
        U_List.append(u"υ")
        V_List.append(u"ν")
        W_List.append(u"ω")
        Y_List.append(u"γ")

    if Phoenetic_Alternatives:
        A_List.extend([u"à", u"á", u"â", u"ã", u"ä", u"å", u"ā", u"ă", u"ą"])
        C_List.extend([u"ç", u"ć", u"ĉ", u"ċ", u"č"])
        D_List.extend([u"ð"])
        E_List.extend([u"ē", u"ĕ", u"ė", u"ę", u"ě", u"è", u"é", u"ê", u"ë"])
        G_List.extend([u"ġ", u"ğ"])
        I_List.extend([u"ì", u"í", u"î", u"ï"])
        N_List.extend([u"ñ", u"ń"])
        O_List.extend([u"ø", u"ò", u"ó", u"ô", u"õ", u"ö", u"ō", u"ŏ"])
        S_List.extend([u"š", u"ś", u"ş"])
        U_List.extend([u"ù", u"ú", u"û", u"ü", u"ũ", u"ū", u"ŭ", u"ů"])
        Y_List.extend([u"ý", u"ÿ"])

    return {"a": A_List, "b": B_List, "c": C_List, "d": D_List, "e": E_List, "f": F_List, "g": G_List, "h": H_List, "i": I_List, "j": J_List, "k": K_List, "l": L_List, "m": M_List, "n": N_List, "o": O_List, "p": P_List, "q": Q_List, "r": R_List, "s": S_List, "t": T_List, "u": U_List, "v": V_List, "w": W_List, "x": X_List, "y": Y_List, "z": Z_List}

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

    if (len(Rotor_Word) == 1):
        for a in list(itertools.product(*Rotor_Word)):
            Newer_List = [a]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 2):
        for a, b in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 3):
        for a, b, c in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 4):
        for a, b, c, d in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 5):
        for a, b, c, d, e in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 6):
        for a, b, c, d, e, f in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 7):
        for a, b, c, d, e, f, g in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 8):
        for a, b, c, d, e, f, g, h in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 9):
        for a, b, c, d, e, f, g, h, i in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h, i]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 10):
        for a, b, c, d, e, f, g, h, i, j in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h, i, j]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 11):
        for a, b, c, d, e, f, g, h, i, j, k in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h, i, j, k]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 12):
        for a, b, c, d, e, f, g, h, i, j, k, l in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h, i, j, k, l]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 13):
        for a, b, c, d, e, f, g, h, i, j, k, l, m in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h, i, j, k, l, m]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 14):
        for a, b, c, d, e, f, g, h, i, j, k, l, m, n in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h, i, j, k, l, m, n]
            Rotor_Word_Appender(Newer_List)

    elif (len(Rotor_Word) == 15):
        for a, b, c, d, e, f, g, h, i, j, k, l, m, n, o in list(itertools.product(*Rotor_Word)):
            Newer_List = [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o]
            Rotor_Word_Appender(Newer_List)

    else:
        logging.warning(f"{Date()} [-] The word entered was either over 15 characters in length or had no characters, this function only permits words with character lengths between 1 and 15.")