# Shell Generator V1
## Descriere

Shell Generator V1 este o aplicație GUI construită cu ajutorul bibliotecii CustomTkinter, destinată să faciliteze generarea și gestionarea diferitelor tipuri de shell-uri reversibile pentru testarea securității și pen-testing. Aplicația permite utilizatorilor să configureze rapid un listener și să genereze comenzi de shell personalizate bazate pe IP-ul și portul specificate.
Caracteristici
    -Setare ușoară a IP-ului și portului pentru sesiuni de ascultare.
    -Generarea diferitelor tipuri de shell-uri reversibile, inclusiv bash, nc, și busybox.
    -Suport pentru diferite opțiuni de shell (ex. bash, sh, zsh).
    -Interfață intuitivă cu mod întunecat pentru o vizibilitate îmbunătățită.

## Pentru a rula această aplicație, ai nevoie de:
    Python 3.x
    CustomTkinter
    O conexiune de rețea activă pentru testare

## Instalare
Pentru a instala CustomTkinter, folosește pip:
```bash
pip install -i requirements.txt
```
## Rulare
Clonează repository-ul și rulează scriptul principal:
```bash
git clone https://github.com/Xeoga/Shell_Generator
cd https://github.com/Xeoga/Shell_Generator
python main.py
```
## TODO
Shellurile sunt imposibile de copiat din interfata grafica adaugarea unui buton sau posibilitatea dea putea copia din interfata =(
De scos din main functile care genereaza shell-ul si de realizat o clasa care face acest lucru =) (Bomba idei)