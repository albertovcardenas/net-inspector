"""ACV NetLab — interfaz local Streamlit para el motor de análisis existente.

Inicio: py -m streamlit run app.py --server.address 127.0.0.1
Mantener este archivo junto a main.py y las carpetas del proyecto.
"""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import os
import sqlite3
from uuid import uuid4

import pandas as pd
import streamlit as st


BASE = Path(__file__).resolve().parent
os.chdir(BASE)  # main.py utiliza rutas relativas para BD y gráficas.

def preparar_serie_temporal_wireshark(origen):
    """Lee un CSV de Wireshark I/O Graphs (Bytes, intervalo de 1 min).

    El tiempo se expresa en segundos DESDE EL INICIO de la captura,
    no como fecha absoluta. No es una lista de conexiones TCP/UDP.
    """
    if hasattr(origen, "seek"):
        origen.seek(0)
    datos = pd.read_csv(origen, encoding="utf-8-sig")
    datos.columns = [str(col).strip() for col in datos.columns]
    campos = {"Interval start", "Todos los paquetes"}
    if not campos.issubset(datos.columns):
        raise ValueError(
            "El CSV no contiene las columnas de Gráficas de E/S esperadas: "
            "'Interval start' y 'Todos los paquetes'. "
            "En Wireshark elige 1 min y Y Axis = Bytes antes de exportar."
        )
    if datos.empty:
        raise ValueError("El CSV temporal está vacío.")

    segundos = pd.to_numeric(datos["Interval start"], errors="coerce")
    bytes_observados = pd.to_numeric(datos["Todos los paquetes"], errors="coerce")
    if segundos.isna().any() or bytes_observados.isna().any():
        raise ValueError("Hay intervalos o valores de bytes que no son números.")
    if (segundos < 0).any() or (bytes_observados < 0).any():
        raise ValueError("Los segundos y los bytes no pueden ser negativos.")
    if not ((segundos % 60) == 0).all():
        raise ValueError("Este gráfico requiere un CSV exportado a intervalos de 1 minuto.")
    if segundos.duplicated().any():
        raise ValueError("El CSV contiene intervalos duplicados.")

    serie = pd.DataFrame({
        "minuto_transcurrido": (segundos / 60).astype(int),
        "bytes_observados": bytes_observados,
    }).sort_values("minuto_transcurrido").reset_index(drop=True)
    serie["MiB"] = serie["bytes_observados"] / (1024 ** 2)
    return serie


st.set_page_config(
    page_title="ACV NetLab | Análisis de tráfico",
    page_icon="🛡️",
    layout="wide",
)

st.title("ACV NetLab")
st.caption("Laboratorio de análisis de tráfico y seguridad de redes · Aplicación local")
st.info(
    "Los indicadores de anomalía son **experimentales**: una ráfaga de registros "
    "no confirma una intrusión. ACV NetLab no captura tráfico en vivo: analiza archivos previamente preparados."
)

# Esta fuente y su serie de E/S proceden de la MISMA captura larga.
FUENTE_LARGA = "Wireshark · Captura larga 02 (45 min)"
NOMBRE_CSV_LARGO = "trafico_real_largo_02_acv_netlab.csv"
NOMBRE_CSV_TEMPORAL = "trafico_por_minuto_wireshark_02.csv"

FUENTES = {
    "Wireshark real (conversaciones normalizadas)": BASE / "trafico_real_acv_netlab.csv",
    FUENTE_LARGA: BASE / NOMBRE_CSV_LARGO,
    "CSV de prueba": BASE / "prueba_formato_generico.csv",
    "CTU-13": BASE / "ctu13_escenario7.binetflow",
}

with st.sidebar:
    st.header("1 · Archivo de entrada")
    fuente = st.radio(
        "Selecciona una fuente",
        [*FUENTES, "Subir otro CSV / binetflow"],
        index=0,
    )
    archivo_subido = None
    if fuente == "Subir otro CSV / binetflow":
        archivo_subido = st.file_uploader(
            "Archivo compatible con el formato CTU-13 o CSV genérico",
            type=["csv", "binetflow", "log"],
            help="Un archivo .log solo es compatible si contiene encabezados CSV reconocidos.",
        )
    else:
        archivo_entrada = FUENTES[fuente]
        if not archivo_entrada.is_file():
            st.warning(f"No se encontró: {archivo_entrada.name}")

    st.header("2 · Parámetros")
    umbral = st.number_input(
        "Umbral (registros por IP)", min_value=1, max_value=1000000,
        value=100, step=1,
    )
    ventana = st.number_input(
        "Ventana temporal (segundos)", min_value=1, max_value=86400,
        value=60, step=10,
    )
    limite = st.number_input(
        "Máximo de filas leídas (0 = todas)",
        min_value=0, max_value=10000000, value=30000, step=1000,
        help="Cuenta filas leídas, incluidas las rechazadas. Para leer todo el archivo, escribe 0.",
    )
    ejecutar = st.button("Analizar archivo", type="primary", use_container_width=True)
    st.caption("Los archivos y resultados permanecen en esta computadora mientras no publiques la aplicación.")

if ejecutar:
    try:
        if archivo_subido is not None and fuente == "Subir otro CSV / binetflow":
            carpeta = BASE / "entradas_app"
            carpeta.mkdir(exist_ok=True)
            nombre = Path(archivo_subido.name).name
            ruta = carpeta / f"{uuid4().hex[:8]}_{nombre}"
            ruta.write_bytes(archivo_subido.getvalue())
        elif fuente in FUENTES:
            ruta = FUENTES[fuente]
        else:
            ruta = None

        if ruta is None or not ruta.is_file():
            st.error("Selecciona un archivo válido antes de ejecutar el análisis.")
        else:
            # Reutilizamos el motor real: no reimplementamos la detección ni SQL.
            from main import main as ejecutar_motor

            salida = StringIO()
            with st.spinner("Analizando el archivo y generando resultados..."):
                with redirect_stdout(salida):
                    resultado = ejecutar_motor(
                        archivo=str(ruta),
                        limite=None if int(limite) == 0 else int(limite),
                        umbral=int(umbral),
                        ventana=int(ventana),
                    )

            st.session_state["ultimo_log"] = salida.getvalue()
            if resultado is None:
                st.session_state.pop("ultimo_resultado", None)
                st.error("El análisis no produjo resultados válidos. Revisa el registro de ejecución.")
            else:
                st.session_state["ultimo_resultado"] = resultado
                st.session_state["ultimo_archivo"] = ruta.name
                st.session_state["ultima_fuente"] = fuente
                st.session_state["ultimo_umbral"] = int(umbral)
                st.session_state["ultima_ventana"] = int(ventana)
                st.success("Análisis completado. Abajo puedes explorar los resultados.")
    except Exception as exc:
        st.session_state.pop("ultimo_resultado", None)
        st.error(f"No fue posible completar el análisis: {type(exc).__name__}: {exc}")

if "ultimo_log" in st.session_state:
    with st.expander("Ver registro técnico de ejecución"):
        st.code(st.session_state["ultimo_log"], language="text")

resultado = st.session_state.get("ultimo_resultado")
if resultado is None:
    st.markdown("### Comienza con una prueba")
    st.write(
        "En la barra izquierda selecciona **Wireshark real** o **CSV de prueba** "
        "y presiona **Analizar archivo**. También puedes cargar un CSV propio compatible."
    )
    st.stop()

if fuente != st.session_state.get("ultima_fuente"):
    st.warning(
        "La fuente seleccionada en la barra lateral cambió. "
        "Los resultados siguen correspondiendo al ÚLTIMO archivo analizado. "
        "Presiona «Analizar archivo» para cambiar de conjunto de datos."
    )

ruta_db = Path(resultado["base_datos"])
if not ruta_db.is_absolute():
    ruta_db = BASE / ruta_db
if not ruta_db.is_file():
    st.error("No se encontró la base de datos generada por el análisis.")
    st.stop()

with sqlite3.connect(ruta_db.resolve().as_uri() + "?mode=ro", uri=True) as conexion:
    df = pd.read_sql_query(
        "SELECT fecha_hora, ip_origen, ip_destino, puerto_destino, "
        "protocolo, bytes_transmitidos FROM conexiones", conexion,
    )
    incidentes = pd.read_sql_query(
        "SELECT tipo, ip_origen, cantidad, inicio, fin, "
        "umbral, ventana_segundos FROM incidentes ORDER BY inicio", conexion,
    )

st.subheader("Resultado del análisis")
st.caption(
    f"Fuente: {st.session_state.get('ultimo_archivo', 'archivo')} · "
    f"Umbral: {st.session_state.get('ultimo_umbral', '?')} registros · "
    f"Ventana: {st.session_state.get('ultima_ventana', '?')} s"
)

k1, k2, k3, k4 = st.columns(4)
k1.metric("Registros aceptados", f"{len(df):,}")
k2.metric("Tráfico contabilizado", f"{df['bytes_transmitidos'].sum() / (1024 ** 2):,.2f} MiB")
k3.metric("Alertas experimentales", f"{len(incidentes):,}")
k4.metric("Orígenes observados", f"{df['ip_origen'].nunique():,}")

st.markdown("### Explorar registros")
f1, f2, f3 = st.columns(3)
with f1:
    protocolos = sorted(df["protocolo"].dropna().unique().tolist())
    seleccion_protocolos = st.multiselect("Protocolo", protocolos, default=protocolos)
with f2:
    origenes = sorted(df["ip_origen"].dropna().unique().tolist())
    seleccion_origen = st.selectbox("IP / identificador de origen", ["Todos", *origenes])
with f3:
    puertos = sorted(df["puerto_destino"].fillna("(vacío)").astype(str).unique().tolist())
    seleccion_puerto = st.selectbox("Puerto de destino", ["Todos", *puertos])

filtrado = df[df["protocolo"].isin(seleccion_protocolos)].copy()
if seleccion_origen != "Todos":
    filtrado = filtrado[filtrado["ip_origen"] == seleccion_origen]
if seleccion_puerto != "Todos":
    filtrado = filtrado[
        filtrado["puerto_destino"].fillna("(vacío)").astype(str) == seleccion_puerto
    ]

st.caption(
    f"Registros visibles: {len(filtrado):,} de {len(df):,}. "
    "Los filtros afectan las tablas y gráficas, pero no recalculan las alertas ya detectadas."
)

tab1, tab2, tab3, tab4 = st.tabs(
    ["Protocolos y puertos", "Tiempo", "Conexiones", "Incidentes"]
)

with tab1:
    a, b = st.columns(2)
    with a:
        st.markdown("**Cantidad de registros por protocolo**")
        if filtrado.empty:
            st.warning("No hay registros con estos filtros.")
        else:
            p = filtrado.groupby("protocolo").size().reset_index(name="registros")
            st.bar_chart(p, x="protocolo", y="registros")
    with b:
        st.markdown("**Puertos más frecuentes**")
        if not filtrado.empty:
            p = (
                filtrado["puerto_destino"].fillna("(sin puerto)").astype(str)
                .value_counts().head(12).rename_axis("puerto")
                .reset_index(name="registros")
            )
            st.bar_chart(p, x="puerto", y="registros")
    if not filtrado.empty:
        bproto = filtrado.groupby("protocolo")["bytes_transmitidos"].sum()
        st.caption("Bytes por protocolo: " + "; ".join(f"{k}: {v:,}" for k, v in bproto.items()))

with tab2:
    st.markdown("#### Serie de tráfico por minuto de paquetes Wireshark (opcional)")
    st.caption(
        "Cuando se dispone de una captura Wireshark, esta serie se exporta desde "
        "Estadísticas → Gráficas de E/S, con intervalo de 1 minuto y eje Y = Bytes. "
        "No corresponde a los registros CTU-13, a menos que se importe y verifique "
        "expresamente una fuente temporal compatible."
    )

    # Nunca asociar automáticamente una serie temporal con otra captura.
    captura_larga_activa = st.session_state.get("ultima_fuente") == FUENTE_LARGA
    ruta_temporal = BASE / NOMBRE_CSV_TEMPORAL if captura_larga_activa else None
    subido_temporal = st.file_uploader(
        "Cargar CSV de Gráficas de E/S (opcional)",
        type=["csv"],
        key=f"csv_temporal_{st.session_state.get('ultimo_archivo', 'ninguno')}",
        help="Solo relaciona las conversaciones y la gráfica E/S si proceden del mismo archivo .pcapng.",
    )
    serie_manual = subido_temporal is not None
    if serie_manual:
        origen_temporal = subido_temporal
        nombre_temporal = subido_temporal.name
    elif ruta_temporal is not None and ruta_temporal.is_file():
        origen_temporal = ruta_temporal
        nombre_temporal = ruta_temporal.name
    else:
        origen_temporal = None
        nombre_temporal = None

    if origen_temporal is None:
        st.info(
            "No hay una serie temporal asociada automáticamente a esta fuente. "
            "Puedes cargar un CSV de Gráficas de E/S, pero verifica que "
            "corresponda a la misma captura antes de compararlos."
        )
    else:
        try:
            serie_io = preparar_serie_temporal_wireshark(origen_temporal)
        except (ValueError, OSError, UnicodeError, pd.errors.ParserError) as error:
            st.error(f"No se pudo leer la serie temporal: {error}")
        else:
            st.success(f"Serie temporal cargada: {nombre_temporal}")
            c1, c2, c3 = st.columns(3)
            c1.metric("Intervalos de 1 minuto", f"{len(serie_io):,}")
            c2.metric(
                "Tráfico observado (aprox.)",
                f"{serie_io['MiB'].sum():,.2f} MiB",
            )
            indice_pico = serie_io["bytes_observados"].idxmax()
            pico = serie_io.loc[indice_pico]
            c3.metric(
                f"Pico al minuto {int(pico['minuto_transcurrido'])}",
                f"{pico['MiB']:,.2f} MiB",
            )
            st.line_chart(
                serie_io, x="minuto_transcurrido", y="MiB",
                x_label="Minutos transcurridos desde el inicio",
                y_label="MiB observados en el intervalo",
            )
            if captura_larga_activa and not serie_manual:
                st.info(
                    "**Misma captura, dos mediciones diferentes:** los registros TCP/UDP "
                    "y esta serie de bytes por minuto se exportaron de "
                    "ACV_NetLab_Captura_Larga_02.pcapng. El detector trabaja con "
                    "conversaciones agregadas; esta gráfica cuenta bytes de los paquetes "
                    "capturados por intervalo. Sus totales pueden diferir debido al "
                    "alcance de los datos y al redondeo del CSV. "
                    "Los filtros de conexiones NO se aplican a la serie de E/S."
                )
            else:
                st.warning(
                    "**Serie temporal importada manualmente o independiente.** "
                    "Verifica que procede de la misma captura que las conexiones "
                    "antes de comparar resultados. Los filtros de conversaciones "
                    "NO se aplican a esta serie."
                )
            with st.expander("Ver los intervalos y descargar tabla"):
                st.dataframe(serie_io, use_container_width=True, hide_index=True)
                st.download_button(
                    "Descargar tabla temporal (CSV)",
                    serie_io.to_csv(index=False).encode("utf-8-sig"),
                    file_name="acv_trafico_temporal_minutos.csv", mime="text/csv",
                )

    st.divider()
    st.markdown("#### Bytes asociados al inicio de los registros")
    st.caption(
        "Esta gráfica suma los bytes de cada registro en su minuto de inicio, "
        "ya sea un flujo del conjunto CTU-13 o una conversación exportada de Wireshark. "
        "No representa necesariamente los bytes transmitidos durante cada minuto. "
        "Esta sección responde a los filtros de protocolo, origen y puerto."
    )
    if filtrado.empty:
        st.warning("No hay registros con estos filtros.")
    else:
        marcas = pd.to_datetime(
            filtrado["fecha_hora"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce"
        )
        temporal = filtrado.loc[marcas.notna()].copy()
        if temporal.empty:
            st.warning("No se encontraron marcas de tiempo interpretables.")
        else:
            temporal["minuto"] = marcas[marcas.notna()].dt.floor("min")
            agrupado = (
                temporal.groupby("minuto", as_index=False)["bytes_transmitidos"].sum()
            )
            agrupado["MiB"] = agrupado["bytes_transmitidos"] / (1024 ** 2)
            agrupado["inicio"] = agrupado["minuto"].dt.strftime("%Y-%m-%d %H:%M")
            st.bar_chart(agrupado, x="inicio", y="MiB")
            if len(agrupado) == 1:
                st.caption("Solo existe un minuto de inicio en los registros seleccionados.")

with tab3:
    st.dataframe(filtrado, use_container_width=True, hide_index=True)
    st.download_button(
        "Descargar registros filtrados (CSV)",
        filtrado.to_csv(index=False).encode("utf-8-sig"),
        file_name="acv_registros_filtrados.csv", mime="text/csv",
    )

with tab4:
    st.markdown("**Alertas generadas para el conjunto completo**")
    if incidentes.empty:
        st.info("No se registraron alertas con los parámetros seleccionados.")
    else:
        st.dataframe(incidentes, use_container_width=True, hide_index=True)
    st.caption("Estas alertas son indicadores de concentración de actividad, no intrusiones confirmadas.")

st.divider()
st.download_button(
    "Descargar base de datos SQLite del análisis",
    data=ruta_db.read_bytes(),
    file_name=ruta_db.name,
    mime="application/vnd.sqlite3",
)
