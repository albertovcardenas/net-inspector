
import csv

def leer_ctu13(ruta_archivo):
    with open(ruta_archivo, "r", encoding="utf-8", newline="") as archivo:
        lector = csv.DictReader(archivo)

        for registro in lector:
            yield registro
