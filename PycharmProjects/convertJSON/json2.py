import json
import pandas as pd
from sqlalchemy import create_engine
from mysql import connector

engine = create_engine('mysql+mysqlconnector://root:1111@localhost:3306/nvd', echo=False)
filename = "/home/hakem/Desktop/netscan.json"
data = pd.read_json(filename)
# df =pd.DataFrame(pd.read_json(filename)['tenant_id']['hosts']['ip'] )
li = []


for item in data["systems"]:
    for host in item["services"]:
        for CVE in host["vulnerability"]:

            if (CVE['cve_ids']!='NOCVE'):
                li.append([item['ip'],CVE['cve_ids'], CVE['cvss_score'],host['port'],host['protocol'],host['name']])



df = pd.read_sql("select * from nvd", engine)
b = [i[1] for i in li]
df = df[df.id.isin(b)]
# df.to_csv("/home/hekmat/Desktop/df.csv")
print 'test'

#
file=open("/home/hakem/Desktop/json2.p","w")
#

scan_res= pd.DataFrame(li, columns =['ip','id','score','port','protocol','service_name'])
final =pd.merge(df,scan_res)
final.to_csv("/home/hakem/Desktop/res.csv")
p = []
for index, row in final.iterrows():
    #if(row['id']==' ' or row['soft']==' ' or row['rng']==' ' or row['severity']==' ' ):
     #   print('hi')
    #else:
        if(len(row['lose_types'].split(','))>1):
           p.append('vulProperty(' +"'" + row['id'] +"'" + ',' + row['rng'][1:len(row['rng'])-1] + ',' + (row['lose_types'].split(',')[0][1:len(row['lose_types'])-2]).strip('\'') + ').')
        else:
            p.append('vulProperty(' + "'" + row['id'] + "'" + ',' + row['rng'][1:len(row['rng']) - 1] + ',' +
                     row['lose_types'][1:len(row['lose_types']) - 1] + ').')

        p.append('vulExists(' +"'" + row['ip']+"'"  + ',' +"'" + row['id']+"'"  + ',' + row['soft'].strip('.') + ').')
        p.append('cvss('  +"'" + row['id'] +"'" + ',' + row['access'] + ').')
        p.append('networkServiceInfo(' +"'" +row['ip'] +"'"+ ',' + row['service_name']+ ',' +row['protocol']+ ',' + "'"+str(row['port']) +"'" +',' + 'someuser'+ ').')
p.append('hacl(_,_,_,_).')

for i in range(len(p)):
    file.writelines(p[i]+ '\n')

file.close()