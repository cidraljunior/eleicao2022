import os
import glob
import pandas as pd
os.chdir("report-alerts/ba")

extension = 'csv'
all_filenames = [i for i in glob.glob('*.{}'.format(extension))]

combined_csv = pd.concat([pd.read_csv(f, header=None) for f in all_filenames ])
combined_csv.columns = ['estado', 'cod_municipio', 'cod_zona', 'cod_secao', 'data hora', 'log_level', 'id_ue', 'aplicativo', 'mensagem', 'mac']
combined_csv.to_csv("alerts-ba.csv", index=False)