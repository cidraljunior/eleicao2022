import os
import re
import json
import asn1tools

import py7zr

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from slugify import slugify


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
    ''' Open "path" for writing, creating any parent directories as needed.
    '''
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, 'w')

def get_file_if_not_exists(url, path):
    if not os.path.isfile(path):
        r = requests.get(url)
        with open(path, 'wb') as f:
            f.write(r.content)

def get_json_if_not_exists(url, path):
    if not os.path.isfile(path):
        raw = requests.get(url).json()
        with safe_open_w(path) as f:
            json.dump(raw, f)
    else:
        with open(path, 'r') as f:
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


def processa_votos(votos):
    processed_votos = dict()
    for voto in votos:
        if voto['tipoVoto'] == 'nominal':
            processed_votos["votos_" + str(voto['identificacaoVotavel']['partido'])] = voto['quantidadeVotos']
        else:            
            processed_votos["votos_" + str(voto['tipoVoto'])] = voto['quantidadeVotos']
    return processed_votos

def processa_bu(asn1_paths: list, bu_path: str):
    conv = asn1tools.compile_files(asn1_paths, codec="ber")
    with open(bu_path, "rb") as file:
        envelope_encoded = bytearray(file.read())
    envelope_decoded = conv.decode("EntidadeEnvelopeGenerico", envelope_encoded)
    bu_encoded = envelope_decoded["conteudo"]
    bu_decoded = conv.decode("EntidadeBoletimUrna", bu_encoded)


    votos = bu_decoded['resultadosVotacaoPorEleicao'][0]['resultadosVotacao'][0]['totaisVotosCargo'][0]['votosVotaveis']

    bu = processa_votos(votos)
    bu['versaoVotacao'] = bu_decoded["urna"]["versaoVotacao"]
    bu['numeroInternoUrna'] = bu_decoded["urna"]['correspondenciaResultado']['carga']['numeroInternoUrna']

    return bu

def get_modelo_urna(path_log, municipio_path, urna_file):
    z = py7zr.SevenZipFile(path_log, mode='r')
    z.extractall(path=f"{municipio_path}/{urna_file}/")
    log_text = open(f"{municipio_path}/{urna_file}/logd.dat", encoding='latin-1')
    regex = re.search("(?<=Modelo de Urna: )(.*?)(?=\\t)", log_text.read())
    modelo_urna = regex.group()
    return modelo_urna
    

def get_files_from_secao(state, municipio, zona, secao):

    cod_municipio = municipio["cd"]
    cod_zona = zona["cd"]
    cod_secao = secao['ns']

    final_report = f"{URNA_PATH}/reports/report-o00407-{cod_municipio}{cod_zona}{cod_secao}.json"

    if os.path.isfile(final_report):
        if os.stat(final_report).st_size != 0:
            return

    municipio_path = f"{URNA_PATH}/{state}/{slugify(municipio['nm'])}"

    urna_index_file = f"p000407-{state}-m{cod_municipio}-z{cod_zona}-s{cod_secao}-aux.json"
    urna_index_url = f"{TSE_URL}/dados/{state}"
    urna_index_url += f"/{cod_municipio}/{cod_zona}/{cod_secao}/{urna_index_file}"
    urna_index_path = f"{municipio_path}/{urna_index_file}"


    urna_dict = get_json_if_not_exists(urna_index_url, urna_index_path)
    # Pegar o boletim de urna e o log de urna

    urna_hash = urna_dict['hashes'][0]['hash']
    urna_file = urna_dict['hashes'][0]['nmarq'][0].split(".")[0]

    urna_files_url =  TSE_URL + f"/dados/{state}"
    urna_files_url += f"/{cod_municipio}/{cod_zona}/{cod_secao}/{urna_hash}/{urna_file}"

    # Boletim de Urna
    urna_bu_url = urna_files_url + ".bu"
    urna_bu_path = f"{municipio_path}/{urna_file}.bu"

    get_file_if_not_exists(urna_bu_url, urna_bu_path)

    # Log de Urna
    urna_log_url = urna_files_url + ".logjez"
    urna_log_path = f"{municipio_path}/{urna_file}.logjez"

    get_file_if_not_exists(urna_log_url, urna_log_path)
    modelo_urna = get_modelo_urna(urna_log_path, municipio_path, urna_file)

    # Report

    print(f"Estado: {state}, Cidade: {cod_municipio}, Zona: {cod_zona}, Secao: {cod_secao} downloaded.")

    report = processa_bu("bu.asn1", urna_bu_path)

    report['estado'] = state
    report['cod_municipio'] = cod_municipio
    report['cod_zona'] = cod_zona
    report['cod_secao'] = cod_secao
    report['modelo_urna'] = modelo_urna

    final_report = f"{URNA_PATH}/reports/report-{urna_file}.json"

    
    with safe_open_w(final_report) as f:
        json.dump(report, f)

    os.remove(urna_bu_path)
    os.remove(urna_log_path)
    os.remove(f"{municipio_path}/{urna_file}/logd.dat")
    os.remove(urna_index_path)


def main():   

    all_tasks = []

    with ThreadPoolExecutor(max_workers=15) as executor:

        for state in states:
            state_dict = get_state_dict(state)
            
            for municipio in state_dict["abr"][0]['mu']:
                        
                for zona in municipio["zon"]:
                    
                    for secao in zona['sec']:

                        all_tasks.append(
                            executor.submit(
                                get_files_from_secao, 
                                state, 
                                municipio,
                                zona,
                                secao)
                            )
    
    for future in as_completed(all_tasks):
        print(future.result())


if __name__ == "__main__":
    main()