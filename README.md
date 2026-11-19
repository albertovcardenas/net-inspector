# ACV NetLab — Analizador de Tráfico de Red

Proyecto integrador de la Maestría en Ciencias y Tecnologías Computacionales (MCTC), Universidad Autónoma de Tamaulipas.

Herramienta en Python para analizar tráfico de red: lee flujos en formato CTU-13 (`.binetflow`) y conversaciones exportadas de Wireshark (CSV), normaliza los datos, los guarda en SQLite, detecta anomalías y genera estadísticas y gráficas con Pandas y Matplotlib. Incluye una interfaz web con Streamlit.

**Estado: entregado (18 de noviembre de 2026).**

## Qué hace

- Lee y normaliza flujos de red (CTU-13) y capturas convertidas desde Wireshark.
- Detecta anomalías y registra incidentes en una base de datos SQLite.
- Genera estadísticas y gráficas: tráfico por minuto, protocolos y puertos destino.
- Interfaz web (Streamlit) para explorar los resultados.

## Estructura

- `main.py` — flujo principal de análisis.
- `app.py` — interfaz web en Streamlit.
- `log_engine/` — lectura de CTU-13, normalización y manejo de errores.
- `security_core/` — información del host, conexión de red y detector de anomalías.
- `db_manager/` — base de datos SQLite e incidentes.
- `visualizer/` — estadísticas con Pandas y gráficas.
- `convertir_wireshark_a_acv.py` — convierte conversaciones de Wireshark (CSV) al formato de análisis.
- `Proyecto_Integrador_Analizador_Trafico_Red.ipynb` — notebook de Google Colab del proyecto.
- `prueba_formato_generico.csv` y `ctu13_prueba_errores.binetflow` — archivos de prueba con datos de ejemplo y del dataset público.

## Cómo ejecutarlo

```bash
pip install -r requirements.txt
python main.py
# Interfaz web:
streamlit run app.py
```

En Windows se puede iniciar con el lanzador incluido en la entrega original.

## Datos

- Dataset público **CTU-13** (Stratosphere Laboratory): https://www.stratosphereips.org/datasets-ctu13 — el archivo completo del escenario no se incluye en este repositorio; se incluye solo una muestra pequeña de prueba.
- Las pruebas con tráfico real se hicieron sobre la computadora del autor. **Por privacidad, la evidencia de tráfico real no se publica en este repositorio**; en el código y el notebook las direcciones se sustituyeron por direcciones de ejemplo.

## Autor

Alberto Carlos Vazquez Cardenas — Ingeniero Industrial, estudiante de la Maestría en Ciencias y Tecnologías Computacionales (UAT).
