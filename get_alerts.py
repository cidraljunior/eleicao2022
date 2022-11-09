import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import py7zr
import requests


N_WORKERS = 16
TSE_URL = "https://resultados.tse.jus.br/oficial/ele2022/arquivo-urna/407"

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
URNA_PATH = DIR_PATH + "/urna"


states = [
    "ac",
    "al",
    "am",
    "ap",
    "ba",
    "ce",
    "df",
    "es",
    "go",
    "ma",
    "mg",
    "ms",
    "mt",
    "pa",
    "pb",
    "pe",
    "pi",
    "pr",
    "rj",
    "rn",
    "ro",
    "rr",
    "rs",
    "sc",
    "se",
    "sp",
    "to",
]


def safe_open_w(path):
    """Open "path" for writing, creating any parent directories as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, "w")


def get_file_if_not_exists(url, path):
    if not os.path.isfile(path):
        r = requests.get(url)
        with open(path, "wb") as f:
            f.write(r.content)


def get_json_if_not_exists(url, path):
    if not os.path.isfile(path):
        raw = requests.get(url).json()
        with safe_open_w(path) as f:
            json.dump(raw, f)
    else:
        with open(path, "r") as f:
            raw = json.load(f)
    return raw


def get_state_dict(state):

    if not os.path.exists(f"{URNA_PATH}/{state}"):
        os.makedirs(f"{URNA_PATH}/{state}")

    state_file = f"{state}/{state}-p000407-cs.json"
    state_path = URNA_PATH + "/" + state_file
    url_state = f"{TSE_URL}/config/{state_file}"

    state_dict = get_json_if_not_exists(url_state, state_path)

    return state_dict


def get_alerts(path_log, municipio_path, urna_file):
    z = py7zr.SevenZipFile(path_log, mode="r")
    z.extractall(path=f"{municipio_path}/{urna_file}/")
    log_text = open(
        f"{municipio_path}/{urna_file}/logd.dat",
        encoding="latin-1",
    ).readlines()

    alerts = [line.replace("\t", ",") for line in log_text if "ALERTA" in line]

    return alerts


def get_files_from_secao(state, municipio, zona, secao):

    cod_municipio = municipio["cd"]
    cod_zona = zona["cd"]
    cod_secao = secao["ns"]

    alerts_file = f"{DIR_PATH}/report-alerts/{state}/"
    alerts_file += f"report-o00407-{cod_municipio}{cod_zona}{cod_secao}.csv"

    if os.path.isfile(alerts_file):
        if os.stat(alerts_file).st_size != 0:
            return

    municipio_path = f"{URNA_PATH}/{state}/{municipio['nm']}"

    urna_index_file = (
        f"p000407-{state}-m{cod_municipio}-z{cod_zona}-s{cod_secao}-aux.json"
    )
    urna_index_url = f"{TSE_URL}/dados/{state}"
    urna_index_url += f"/{cod_municipio}/{cod_zona}/{cod_secao}/{urna_index_file}"
    urna_index_path = f"{municipio_path}/{urna_index_file}"

    urna_dict = get_json_if_not_exists(urna_index_url, urna_index_path)

    urna_hash = urna_dict["hashes"][0]["hash"]
    urna_file = urna_dict["hashes"][0]["nmarq"][0].split(".")[0]

    urna_files_url = TSE_URL + f"/dados/{state}"
    urna_files_url += f"/{cod_municipio}/{cod_zona}/{cod_secao}/{urna_hash}/{urna_file}"

    # Log de Urna
    urna_log_url = urna_files_url + ".logjez"
    urna_log_path = f"{municipio_path}/{urna_file}.logjez"

    get_file_if_not_exists(urna_log_url, urna_log_path)

    alerts = get_alerts(urna_log_path, municipio_path, urna_file)

    alerts_with_secao = [
        f"{state},{cod_municipio},{cod_zona},{cod_secao}," + line for line in alerts
    ]

    # Report

    print(
        f"Estado: {state}, Cidade: {cod_municipio}, Zona: {cod_zona}, Secao: {cod_secao} downloaded."
    )

    with safe_open_w(alerts_file) as f:
        for line in alerts_with_secao:
            f.write(line)

    os.remove(urna_log_path)
    os.remove(f"{municipio_path}/{urna_file}/logd.dat")
    os.remove(urna_index_path)


def main():

    all_tasks = []

    with ThreadPoolExecutor(max_workers=N_WORKERS) as executor:

        for state in states:
            state_dict = get_state_dict(state)

            for municipio in state_dict["abr"][0]["mu"]:

                for zona in municipio["zon"]:

                    for secao in zona["sec"]:

                        all_tasks.append(
                            executor.submit(
                                get_files_from_secao, state, municipio, zona, secao
                            )
                        )

    for future in as_completed(all_tasks):
        print(future.result())


if __name__ == "__main__":
    main()
