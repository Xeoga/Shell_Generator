# Shell Generator V1

## Prezentare generală

Shell Generator V1 este o aplicație cu interfață grafică (GUI) construită cu `customtkinter`, care permite utilizatorilor să genereze diverse tipuri de comenzi shell reversibile și bind, să verifice Common Vulnerabilities and Exposures (CVE) folosind API-ul NIST și să copieze ușor comenzile shell generate în clipboard. Aplicația include, de asemenea, o funcționalitate de tip "easter egg" care poate fi declanșată prin apăsarea unui buton.

## Funcționalități

- **Generare Comenzi Shell:** Generarea unei varietăți de comenzi shell reversibile și bind, inclusiv bash, netcat și payload-uri msfvenom.
- **Verificare CVE:** Verificarea informațiilor detaliate despre CVE folosind API-ul NIST.
- **Funcționalitate Clipboard:** Copierea ușoară a comenzilor shell generate în clipboard.
- **Selecție Shell:** Alegerea dintr-o listă de tipuri de shell-uri comune (de exemplu, bash, zsh, cmd, powershell).
- **Easter Egg:** Declanșarea unui server local ascuns pentru divertisment.

## Dependențe

- `customtkinter`
- `requests`
- `json`
- `textwrap`
- `PIL` (Pillow)
- `server_part` (modul personalizat)
## Installation

1. **Clonează Repositorul:**
```bash
git clone https://github.com/Xeoga/Shell_Generator.git
cd shell-generator
```
2. **Instalează Bibliotecile Necesare:**
```bash
pip install -r requirements.txt
```
3. **Rulează Aplicația:**
```bash
python GUI.py
```
## Utilizare
1. **Introducerea IP-ului și Portului:**
    
    - Introduceți adresa IP și numărul portului dorit în câmpurile furnizate.
    - Apăsați Enter pentru a salva IP-ul și portul.
2. **Selectarea Tipului de Shell:**
    
    - Alegeți tipul de shell dorit din meniul dropdown.
3. **Generarea Comenzii Shell:**
    
    - Faceți clic pe butonul corespunzător din secțiunile "Reverse", "Bind" sau "MSFVenom" pentru a genera comanda shell.
    - Comanda generată va fi afișată pe ecran.
4. **Copierea în Clipboard:**
    
    - Faceți clic pe butonul "Copy to Clipboard" pentru a copia comanda generată în clipboard.
5. **Verificarea Informațiilor CVE:**
    
    - Faceți clic pe butonul "CVE Check".
    - Introduceți ID-ul CVE în noua fereastră și faceți clic pe "Check CVE" pentru a prelua informațiile de la API-ul NIST.
6. **Easter Egg:**
    
    - Faceți clic pe butonul "🐣Easter Egg" pentru a porni un server local pentru o surpriză.

## Structura Proiectului

- **main.py:** Scriptul principal al aplicației care conține logica și funcționalitățile GUI.
- **server_part.py:** Modul personalizat pentru gestionarea funcționalității serverului local de tip "easter egg".
- **emoji/:** Directorul care conține resursele de imagine utilizate în aplicație.