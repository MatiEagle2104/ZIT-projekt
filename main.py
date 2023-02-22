# Zarzπdzanie infrastrukturπ teleinformatycznπ - projekt
# 13. èrÛd≥a informacji o podatnoúciach oraz ich korelacja ze zbiorem zainstalowanego oprogramowania (zawierajπcego moøliwe podatnoúci)

import subprocess
import nvdlib


# detekcja oprogramowania w systemie

Data = subprocess.check_output(['wmic', 'product', 'get', 'name'])
oprogramowanie = list()
a = str(Data)  

try:
    for i in range(len(a)):
        if a.split("\\r\\r\\n")[6:][i] != '\n':
            oprogramowanie.append(a.split("\\r\\r\\n")[6:][i])
except IndexError as e:
    None


# pÍtla, ktÛra po detekcji usuwa 'brudy' i puste elementy z listy

for i in range (len(oprogramowanie)-1, 0, -1):
    check=oprogramowanie[i]
    if len(check)==0:
        del oprogramowanie[i]
    else: 
        if check[0].isalpha()==False:
            del oprogramowanie[i]
        else: None

print("Wykonano detekcje oprogramowania!", "\n")


# wypisanie na ekran oprogramowania - tylko do testÛw

#for i in range(len(oprogramowanie)):
#   print(oprogramowanie[i],end="\n")


# API do bazy danych z podatnoúciami NVD, szukanie pod katem podatnosci

vulnerabilities = list()

plik_oprogramowanie = open('oprogramowanie.csv','w',encoding="utf-8")
plik_podatnosci = open('podatnosci.csv','w',encoding='utf-8')

do_opr = []
do_pod = ["Oprogramowanie; ID; Description; Published; Score \n"]

for i in range(len(oprogramowanie)):
    vulnerabilities.append(nvdlib.searchCVE(keywordSearch=oprogramowanie[i], key='bee0e7e3-d605-4ad3-af06-1275c3133bd9', delay=6))  
    bufor=str(vulnerabilities[i])
    if bufor[1]==']':
        do_opr.append(oprogramowanie[i] + "-" + str(vulnerabilities[i]) + "\n")
    else:
        print(oprogramowanie[i]," - wykryto podatnosc/i dla oprogramowania")
        do_opr.append(oprogramowanie[i] + "-" + str(vulnerabilities[i]) + '\n')
        r=nvdlib.searchCVE(keywordSearch=oprogramowanie[i], key='bee0e7e3-d605-4ad3-af06-1275c3133bd9', delay=6)
        for eachCVE in r:
            do_pod.append(oprogramowanie[i] + "; " + eachCVE.id + "; " + str(eachCVE.descriptions) + "; " + eachCVE.published + "; " + str(eachCVE.score) + "\n")

# zapis do plikow
plik_oprogramowanie.writelines(do_opr)
plik_podatnosci.writelines(do_pod)

plik_oprogramowanie.close()
plik_podatnosci.close()


print("\n","Wykonano test podatnosci! \n")
print("Oprogramowanie systemu wraz z podatnosciami znajduje sie w pliku 'oprogramowanie.csv'!")
print("Podatnosci oprogramowania znajduja sie w pliku 'podatnosci.csv'! \n")

